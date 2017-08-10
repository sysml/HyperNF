/*
 *
 * Copyright (c) 2016-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Authors: Kenichi Yasukata
 *
 */

#include "common.h"

#include <xen/gntdev.h>

static int limit = 1024*1024;
module_param(limit, int, 0644);
MODULE_PARM_DESC(limit, "Maximum number of grants that may be mapped by "
		"the netmap gntdev device");

static atomic_t pages_mapped = ATOMIC_INIT(0);

static int use_ptemod;
#define populate_freeable_maps use_ptemod

struct gntdev_priv {
	/* maps with visible offsets in the file descriptor */
	struct list_head maps;
	/* maps that are not visible; will be freed on munmap.
	 * Only populated if populate_freeable_maps == 1 */
	struct list_head freeable_maps;
	/* lock protects maps and freeable_maps */
	struct mutex lock;
	struct mm_struct *mm;
	struct mmu_notifier mn;
};

struct unmap_notify {
	int flags;
	/* Address relative to the start of the grant_map */
	int addr;
	int event;
};

struct vnetmap_priv_d {
	struct netmapfront_info *np_nifp;
	struct gntdev_priv gntpriv;
};

struct grant_map {
	struct list_head next;
	struct vm_area_struct *vma;
	int index;
	int count;
	int flags;
	atomic_t users;
	struct unmap_notify notify;
	struct ioctl_gntdev_grant_ref *grants;
	struct gnttab_map_grant_ref   *map_ops;
	struct gnttab_unmap_grant_ref *unmap_ops;
	struct gnttab_map_grant_ref   *kmap_ops;
	struct gnttab_unmap_grant_ref *kunmap_ops;
	struct page **pages;
	unsigned long pages_vm_start;
};

struct nm_linux_selrecord_t {
	struct file *file;
	struct poll_table_struct *pwait;
};

long __privcmd_hypercall(struct privcmd_hypercall *hypercall)
{
	long ret;

	xen_preemptible_hcall_begin();
	ret = privcmd_call(hypercall->op,
			   hypercall->arg[0], hypercall->arg[1],
			   hypercall->arg[2], hypercall->arg[3],
			   hypercall->arg[4]);
	xen_preemptible_hcall_end();

	return ret;
}

long kick_backend(struct netmap_ring_info *ring_info, enum txrx tx)
{
	long ret = 0;
	struct privcmd_hypercall hypercall;
	hypercall.op = xennet_op;
	hypercall.arg[0] = XENNETOP_sync;
	hypercall.arg[1] = 0;
	hypercall.arg[2] = ring_info->if_id;
	hypercall.arg[3] = tx;
	hypercall.arg[4] = 0;
	ret = __privcmd_hypercall(&hypercall);
	return ret;
}

static void gntdev_add_map(struct gntdev_priv *priv, struct grant_map *add)
{
	struct grant_map *map;

	list_for_each_entry(map, &priv->maps, next) {
		if (add->index + add->count < map->index) {
			list_add_tail(&add->next, &map->next);
			goto done;
		}
		add->index = map->index + map->count;
	}
	list_add_tail(&add->next, &priv->maps);

done:
	return;
	//gntdev_print_maps(priv, "[new]", add->index);
}

static struct grant_map *gntdev_find_map_index(struct gntdev_priv *priv,
		int index, int count)
{
	struct grant_map *map;

	list_for_each_entry(map, &priv->maps, next) {
		if (map->index != index)
			continue;
		if (count && map->count != count)
			continue;
		return map;
	}
	return NULL;
}

static void gntdev_free_map(struct grant_map *map)
{
	if (map == NULL)
		return;

	if (map->pages)
		gnttab_free_pages(map->count, map->pages);
	kfree(map->pages);
	kfree(map->grants);
	kfree(map->map_ops);
	kfree(map->unmap_ops);
	kfree(map->kmap_ops);
	kfree(map->kunmap_ops);
	kfree(map);
}

static struct grant_map *gntdev_alloc_map(struct gntdev_priv *priv, int count)
{
	struct grant_map *add;
	int i;

	add = kzalloc(sizeof(struct grant_map), GFP_KERNEL);
	if (NULL == add)
		return NULL;

	add->grants    = kcalloc(count, sizeof(add->grants[0]), GFP_KERNEL);
	add->map_ops   = kcalloc(count, sizeof(add->map_ops[0]), GFP_KERNEL);
	add->unmap_ops = kcalloc(count, sizeof(add->unmap_ops[0]), GFP_KERNEL);
	add->kmap_ops  = kcalloc(count, sizeof(add->kmap_ops[0]), GFP_KERNEL);
	add->kunmap_ops = kcalloc(count, sizeof(add->kunmap_ops[0]), GFP_KERNEL);
	add->pages     = kcalloc(count, sizeof(add->pages[0]), GFP_KERNEL);
	if (NULL == add->grants    ||
	    NULL == add->map_ops   ||
	    NULL == add->unmap_ops ||
	    NULL == add->kmap_ops  ||
	    NULL == add->kunmap_ops ||
	    NULL == add->pages)
		goto err;

	if (gnttab_alloc_pages(count, add->pages))
		goto err;

	for (i = 0; i < count; i++) {
		add->map_ops[i].handle = -1;
		add->unmap_ops[i].handle = -1;
		add->kmap_ops[i].handle = -1;
		add->kunmap_ops[i].handle = -1;
	}

	add->index = 0;
	add->count = count;
	atomic_set(&add->users, 1);

	return add;

err:
	gntdev_free_map(add);
	return NULL;
}

void
nm_os_selinfo_init(NM_SELINFO_T *si)
{
	init_waitqueue_head(si);
}

void
vnm_os_selwakeup(NM_SELINFO_T *si)
{
	/* We use wake_up_interruptible() since select() and poll()
	 * sleep in an interruptbile way. */
	wake_up_interruptible(si);
}

void
vnm_os_selrecord(NM_SELRECORD_T *sr, NM_SELINFO_T *si)
{
	poll_wait(sr->file, si, sr->pwait);
}

int
vnetmap_notify(struct netmap_ring_info *ring_info, int flags)
{
	if (unlikely(flags < 0 || flags > NR_TXRX)) {
		D("Weird TXRX specification %u", flags);
		return NM_IRQ_COMPLETED;
	}
	if (flags == NR_TXRX) {
		vnm_os_selwakeup(&ring_info->si[NR_TX]);
		vnm_os_selwakeup(&ring_info->si[NR_RX]);
	} else
		vnm_os_selwakeup(&ring_info->si[(enum txrx) flags]);

	return NM_IRQ_COMPLETED;
}


int
vnetmap_poll(struct vnetmap_priv_d *priv, int events, NM_SELRECORD_T *sr)
{
	struct netmapfront_info *info;
	struct netmap_ring *ring;
	u_int i, want[NR_TXRX], revents = 0;
#define want_tx want[NR_TX]
#define want_rx want[NR_RX]
	//struct mbq q;		/* packets from hw queues to host stack */
	enum txrx t;

	/*
	 * In order to avoid nested locks, we need to "double check"
	 * txsync and rxsync if we decide to do a selrecord().
	 * retry_tx (and retry_rx, later) prevent looping forever.
	 */
	int retry_tx = 1, retry_rx = 1;
	int do_kick;

	/* transparent mode: send_down is 1 if we have found some
	 * packets to forward during the rx scan and we have not
	 * sent them down to the nic yet
	 */

	//mbq_init(&q);

	if (priv->np_nifp == NULL) {
		D("No if registered");
		return POLLERR;
	}
	mb(); /* make sure following reads are not from cache */

	info = priv->np_nifp;

	want_tx = events & (POLLOUT | POLLWRNORM);
	want_rx = events & (POLLIN | POLLRDNORM);

	if (want_tx) {
		struct netmapfront_info *info = priv->np_nifp;
		for (i = 0; i < info->num_rings; i++) {
			struct netmap_ring_info *ring_info = &info->ring_info[i];
			struct netmap_ring *tx_ring = ring_info->tx_ring;
			t = NR_TX;
			if (!nm_ring_empty(tx_ring)) {
				revents |= want[t];
				want[t] = 0;	/* also breaks the loop */
			}
		}
	}
	if (want_rx) {
		struct netmapfront_info *info = priv->np_nifp;
		for (i = 0; i < info->num_rings; i++) {
			struct netmap_ring_info *ring_info = &info->ring_info[i];
			struct netmap_ring *rx_ring = ring_info->rx_ring;
			want_rx = 0; /* look for a reason to run the handlers */
			t = NR_RX;
			if (rx_ring->cur == rx_ring->tail) {
				want_rx = 1;
			}
			if (!want_rx)
				revents |= events & (POLLIN | POLLRDNORM); /* we have data */
		}
	}

	if (info->np_txpoll || want_tx) {
		do_kick = 1;
		/*
		 * The first round checks if anyone is ready, if not
		 * do a selrecord and another round to handle races.
		 * want_tx goes to 0 if any space is found, and is
		 * used to skip rings with no pending transmissions.
		 */
flush_tx:
		for (i = 0; i < info->num_rings; i++) {
			int found = 0;

			struct netmap_ring_info *ring_info = &info->ring_info[i];
			ring = ring_info->tx_ring;

			if (do_kick) {
				kick_backend(ring_info, NR_TX);
				do_kick = 0;
			}
			/*
			 * If we found new slots, notify potential
			 * listeners on the same ring.
			 * Since we just did a txsync, look at the copies
			 * of cur,tail in the kring.
			 */
			mb();
			found = !(nm_ring_empty(ring));
			//D("h %u, c %u, t %u", ring->head, ring->cur, ring->tail);
			if (found) { /* notify other listeners */
				revents |= want_tx;
				want_tx = 0;
				vnetmap_notify(ring_info, NR_TX);
			}
		}
		if (want_tx && retry_tx && sr) {
			//nm_os_selrecord(sr, check_all_tx ?
			//    &na->si[NR_TX] : &na->tx_rings[priv->np_qfirst[NR_TX]].si);
			vnm_os_selrecord(sr, &info->ring_info[0].si[NR_TX]);
			retry_tx = 0;
			goto flush_tx;
		}
	}

	/*
	 * If want_rx is still set scan receive rings.
	 * Do it on all rings because otherwise we starve.
	 */
	if (want_rx) {
		/* two rounds here for race avoidance */
		do_kick = 1;
do_retry_rx:
		for (i = 0; i < info->num_rings; i++) {
			int found = 0;

			struct netmap_ring_info *ring_info = &info->ring_info[i];
			ring = ring_info->rx_ring;

			if (do_kick) {
				kick_backend(ring_info, NR_RX);
				do_kick = 0;
			}

			//D("h %u, c %u, t %u", ring->head, ring->cur, ring->tail);
			mb();
			found = !(nm_ring_empty(ring));
			if (found) {
				revents |= want_rx;
				retry_rx = 0;
				vnetmap_notify(ring_info, NR_RX);
			}
		}

		if (retry_rx && sr) {
			//nm_os_selrecord(sr, check_all_rx ?
			//    &na->si[NR_RX] : &na->rx_rings[priv->np_qfirst[NR_RX]].si);
			vnm_os_selrecord(sr, &info->ring_info[0].si[NR_RX]);
		}
		if (retry_rx) {
			retry_rx = 0;
			goto do_retry_rx;
		}
	}

	return (revents);
#undef want_tx
#undef want_rx
}

/*
 * Remap linux arguments into the FreeBSD call.
 * - pwait is the poll table, passed as 'dev';
 *   If pwait == NULL someone else already woke up before. We can report
 *   events but they are filtered upstream.
 *   If pwait != NULL, then pwait->key contains the list of events.
 * - events is computed from pwait as above.
 * - file is passed as 'td';
 */
static u_int
linux_netmap_poll(struct file * file, struct poll_table_struct *pwait)
{
	int events = POLLIN | POLLOUT; /* XXX maybe... */
	struct nm_linux_selrecord_t sr = {
		.file = file,
		.pwait = pwait
	};
	struct vnetmap_priv_d *priv = file->private_data;
	return vnetmap_poll(priv, events, &sr);
}

static int map_grant_pages(struct grant_map *map)
{
	int i, err = 0;

	if (!use_ptemod) {
		/* Note: it could already be mapped */
		if (map->map_ops[0].handle != -1)
			return 0;
		for (i = 0; i < map->count; i++) {
			unsigned long addr = (unsigned long)
				pfn_to_kaddr(page_to_pfn(map->pages[i]));
			gnttab_set_map_op(&map->map_ops[i], addr, map->flags,
				map->grants[i].ref,
				map->grants[i].domid);
			gnttab_set_unmap_op(&map->unmap_ops[i], addr,
				map->flags, -1 /* handle */);
		}
	} else {
		/*
		 * Setup the map_ops corresponding to the pte entries pointing
		 * to the kernel linear addresses of the struct pages.
		 * These ptes are completely different from the user ptes dealt
		 * with find_grant_ptes.
		 */
		for (i = 0; i < map->count; i++) {
			unsigned long address = (unsigned long)
				pfn_to_kaddr(page_to_pfn(map->pages[i]));
			BUG_ON(PageHighMem(map->pages[i]));

			gnttab_set_map_op(&map->kmap_ops[i], address,
				map->flags | GNTMAP_host_map,
				map->grants[i].ref,
				map->grants[i].domid);
			gnttab_set_unmap_op(&map->kunmap_ops[i], address,
				map->flags | GNTMAP_host_map, -1);
		}
	}

	pr_debug("map %d+%d\n", map->index, map->count);
	err = gnttab_map_refs(map->map_ops, use_ptemod ? map->kmap_ops : NULL,
			map->pages, map->count);
	if (err)
		return err;

	for (i = 0; i < map->count; i++) {
		if (map->map_ops[i].status) {
			err = -EINVAL;
			continue;
		}

		map->unmap_ops[i].handle = map->map_ops[i].handle;
		if (use_ptemod)
			map->kunmap_ops[i].handle = map->kmap_ops[i].handle;
	}
	return err;
}

static int __unmap_grant_pages(struct grant_map *map, int offset, int pages)
{
	int i, err = 0;
	struct gntab_unmap_queue_data unmap_data;

	if (map->notify.flags & UNMAP_NOTIFY_CLEAR_BYTE) {
		int pgno = (map->notify.addr >> PAGE_SHIFT);
		if (pgno >= offset && pgno < offset + pages) {
			/* No need for kmap, pages are in lowmem */
			uint8_t *tmp = pfn_to_kaddr(page_to_pfn(map->pages[pgno]));
			tmp[map->notify.addr & (PAGE_SIZE-1)] = 0;
			map->notify.flags &= ~UNMAP_NOTIFY_CLEAR_BYTE;
		}
	}

	unmap_data.unmap_ops = map->unmap_ops + offset;
	unmap_data.kunmap_ops = use_ptemod ? map->kunmap_ops + offset : NULL;
	unmap_data.pages = map->pages + offset;
	unmap_data.count = pages;

	err = gnttab_unmap_refs_sync(&unmap_data);
	if (err)
		return err;

	for (i = 0; i < pages; i++) {
		if (map->unmap_ops[offset+i].status)
			err = -EINVAL;
		pr_debug("unmap handle=%d st=%d\n",
			map->unmap_ops[offset+i].handle,
			map->unmap_ops[offset+i].status);
		map->unmap_ops[offset+i].handle = -1;
	}
	return err;
}

static int unmap_grant_pages(struct grant_map *map, int offset, int pages)
{
	int range, err = 0;

	pr_debug("unmap %d+%d [%d+%d]\n", map->index, map->count, offset, pages);

	/* It is possible the requested range will have a "hole" where we
	 * already unmapped some of the grants. Only unmap valid ranges.
	 */
	while (pages && !err) {
		while (pages && map->unmap_ops[offset].handle == -1) {
			offset++;
			pages--;
		}
		range = 0;
		while (range < pages) {
			if (map->unmap_ops[offset+range].handle == -1) {
				range--;
				break;
			}
			range++;
		}
		err = __unmap_grant_pages(map, offset, range);
		offset += range;
		pages -= range;
	}

	return err;
}

static void gntdev_put_map(struct gntdev_priv *priv, struct grant_map *map)
{
	if (!map)
		return;

	if (!atomic_dec_and_test(&map->users))
		return;

	atomic_sub(map->count, &pages_mapped);

	if (map->notify.flags & UNMAP_NOTIFY_SEND_EVENT) {
		notify_remote_via_evtchn(map->notify.event);
		evtchn_put(map->notify.event);
	}

	if (populate_freeable_maps && priv) {
		mutex_lock(&priv->lock);
		list_del(&map->next);
		mutex_unlock(&priv->lock);
	}

	if (map->pages && !use_ptemod)
		unmap_grant_pages(map, 0, map->count);
	gntdev_free_map(map);
}

static void gntdev_vma_open(struct vm_area_struct *vma)
{
	struct grant_map *map = vma->vm_private_data;

	pr_debug("gntdev_vma_open %p\n", vma);
	atomic_inc(&map->users);
}

static void gntdev_vma_close(struct vm_area_struct *vma)
{
	struct grant_map *map = vma->vm_private_data;
	struct file *file = vma->vm_file;
	struct gntdev_priv *priv = file->private_data;

	pr_debug("gntdev_vma_close %p\n", vma);
	if (use_ptemod) {
		/* It is possible that an mmu notifier could be running
		 * concurrently, so take priv->lock to ensure that the vma won't
		 * vanishing during the unmap_grant_pages call, since we will
		 * spin here until that completes. Such a concurrent call will
		 * not do any unmapping, since that has been done prior to
		 * closing the vma, but it may still iterate the unmap_ops list.
		 */
		mutex_lock(&priv->lock);
		map->vma = NULL;
		mutex_unlock(&priv->lock);
	}
	vma->vm_private_data = NULL;
	gntdev_put_map(priv, map);
}

static struct page *gntdev_vma_find_special_page(struct vm_area_struct *vma,
						 unsigned long addr)
{
	struct grant_map *map = vma->vm_private_data;

	return map->pages[(addr - map->pages_vm_start) >> PAGE_SHIFT];
}

static const struct vm_operations_struct gntdev_vmops = {
	.open = gntdev_vma_open,
	.close = gntdev_vma_close,
	.find_special_page = gntdev_vma_find_special_page,
};

static int find_grant_ptes(pte_t *pte, pgtable_t token,
		unsigned long addr, void *data)
{
	struct grant_map *map = data;
	unsigned int pgnr = (addr - map->vma->vm_start) >> PAGE_SHIFT;
	int flags = map->flags | GNTMAP_application_map | GNTMAP_contains_pte;
	u64 pte_maddr;

	BUG_ON(pgnr >= map->count);
	pte_maddr = arbitrary_virt_to_machine(pte).maddr;

	/*
	 * Set the PTE as special to force get_user_pages_fast() fall
	 * back to the slow path.  If this is not supported as part of
	 * the grant map, it will be done afterwards.
	 */
	if (xen_feature(XENFEAT_gnttab_map_avail_bits))
		flags |= (1 << _GNTMAP_guest_avail0);

	gnttab_set_map_op(&map->map_ops[pgnr], pte_maddr, flags,
			  map->grants[pgnr].ref,
			  map->grants[pgnr].domid);
	gnttab_set_unmap_op(&map->unmap_ops[pgnr], pte_maddr, flags,
			    -1 /* handle */);
	return 0;
}

#ifdef CONFIG_X86
static int set_grant_ptes_as_special(pte_t *pte, pgtable_t token,
				     unsigned long addr, void *data)
{
	set_pte_at(current->mm, addr, pte, pte_mkspecial(*pte));
	return 0;
}
#endif

static int
linux_netmap_mmap(struct file *f, struct vm_area_struct *vma)
{
	struct vnetmap_priv_d *priv = f->private_data;
	struct netmapfront_info *info;
	struct gntdev_priv *gpriv = &priv->gntpriv;
	int index = vma->vm_pgoff;
	int count = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	struct grant_map *map;
	int i, err = -EINVAL;

	if (priv->np_nifp == NULL) {
		D("There is no np_nifp");
		return -EINVAL;
	}
	info = priv->np_nifp;
	mb();

	map = gntdev_alloc_map(gpriv, count);
	if (!map)
		return err;

	if (unlikely(atomic_add_return(count, &pages_mapped) > limit)) {
		pr_debug("can't map: over limit\n");
		gntdev_put_map(NULL, map);
		return err;
	}

	for (i = 0; i < count; i++) {
		map->grants[i].ref = info->gi->grefs[i];
		map->grants[i].domid = info->otherend_id;
	}

	mutex_lock(&gpriv->lock);
	gntdev_add_map(gpriv, map);
	//op.index = map->index << PAGE_SHIFT;
	mutex_unlock(&gpriv->lock);

	if ((vma->vm_flags & VM_WRITE) && !(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	pr_debug("map %d+%d at %lx (pgoff %lx)\n",
			index, count, vma->vm_start, vma->vm_pgoff);

	mutex_lock(&gpriv->lock);
	map = gntdev_find_map_index(gpriv, index, count);
	if (!map)
		goto unlock_out;
	if (use_ptemod && map->vma)
		goto unlock_out;
	if (use_ptemod && gpriv->mm != vma->vm_mm) {
		pr_warn("Huh? Other mm?\n");
		goto unlock_out;
	}

	atomic_inc(&map->users);

	vma->vm_ops = &gntdev_vmops;

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP | VM_IO;

	if (use_ptemod)
		vma->vm_flags |= VM_DONTCOPY;

	vma->vm_private_data = map;

	if (use_ptemod)
		map->vma = vma;

	if (map->flags) {
		if ((vma->vm_flags & VM_WRITE) &&
				(map->flags & GNTMAP_readonly))
			goto out_unlock_put;
	} else {
		map->flags = GNTMAP_host_map;
		if (!(vma->vm_flags & VM_WRITE))
			map->flags |= GNTMAP_readonly;
	}

	mutex_unlock(&gpriv->lock);

	if (use_ptemod) {
		err = apply_to_page_range(vma->vm_mm, vma->vm_start,
					  vma->vm_end - vma->vm_start,
					  find_grant_ptes, map);
		if (err) {
			pr_warn("find_grant_ptes() failure.\n");
			goto out_put_map;
		}
	}

	err = map_grant_pages(map);
	if (err)
		goto out_put_map;

	if (!use_ptemod) {
		for (i = 0; i < count; i++) {
			err = vm_insert_page(vma, vma->vm_start + i*PAGE_SIZE,
				map->pages[i]);
			if (err)
				goto out_put_map;
		}
	} else {
#ifdef CONFIG_X86
		/*
		 * If the PTEs were not made special by the grant map
		 * hypercall, do so here.
		 *
		 * This is racy since the mapping is already visible
		 * to userspace but userspace should be well-behaved
		 * enough to not touch it until the mmap() call
		 * returns.
		 */
		if (!xen_feature(XENFEAT_gnttab_map_avail_bits)) {
			apply_to_page_range(vma->vm_mm, vma->vm_start,
					    vma->vm_end - vma->vm_start,
					    set_grant_ptes_as_special, NULL);
		}
#endif
		map->pages_vm_start = vma->vm_start;
	}

	return 0;

unlock_out:
	mutex_unlock(&gpriv->lock);
	return err;

out_unlock_put:
	mutex_unlock(&gpriv->lock);
out_put_map:
	if (use_ptemod)
		map->vma = NULL;
	gntdev_put_map(gpriv, map);
	return err;

	return 0;
}

static inline uint32_t
nm_ring_space(struct netmap_ring *ring)
{
        int ret = ring->tail - ring->cur;
        if (ret < 0)
                ret += ring->num_slots;
        return ret;
}

int
vnetmap_ioctl(struct vnetmap_priv_d *priv, u_long cmd, caddr_t data, struct thread *td)
{
	struct nmreq *nmr = (struct nmreq *) data;
	int error = 0;

	if (cmd == NIOCGINFO || cmd == NIOCREGIF) {
		/* truncate name */
		nmr->nr_name[sizeof(nmr->nr_name) - 1] = '\0';
		if (nmr->nr_version != NETMAP_API) {
			D("API mismatch for %s got %d need %d",
				nmr->nr_name,
				nmr->nr_version, NETMAP_API);
			nmr->nr_version = NETMAP_API;
		}
		if (nmr->nr_version < NETMAP_MIN_API ||
		    nmr->nr_version > NETMAP_MAX_API) {
			return EINVAL;
		}
	}

	switch (cmd) {
	case NIOCGINFO:		/* return capabilities etc */
	case NIOCREGIF:
		//NMG_LOCK();
		do {
			/* memsize is always valid */
			struct net_device *netdev;
			struct netmapfront_info *info = NULL;

			if (nmr->nr_name[0] != '\0') {
				if (!(netdev = __dev_get_by_name(&init_net, nmr->nr_name))) {
					D("no such device %s", nmr->nr_name);
					error = EINVAL;
					break;
				}

				info = netdev_priv(netdev);
			}
			if (!info) {
				D("No info for %s", nmr->nr_name);
				error = EINVAL;
				break;
			}
			if (priv->np_nifp != NULL && priv->np_nifp != info) {
				D("Invalid registration privinfo:%p, info:%p",
						priv->np_nifp,
						info);
				error = EINVAL;
				break;
			}
			D("netmap device %s", nmr->nr_name);
			nmr->nr_offset = info->gi->nr_offset;
			nmr->nr_rx_slots = nmr->nr_tx_slots = 0;
			nmr->nr_rx_rings = info->num_rings;
			nmr->nr_tx_rings = info->num_rings;
			if (nmr->nr_rx_rings > 0) {
				nmr->nr_rx_slots = info->ring_info[0].rx_ring->num_slots;
				nmr->nr_tx_slots = info->ring_info[0].tx_ring->num_slots;
			}
			nmr->nr_memsize = info->nr_memsize;
			nmr->nr_arg2 = 0;
			info->np_txpoll = (nmr->nr_ringid & NETMAP_NO_TX_POLL) ? 0 : 1;
			if (priv->np_nifp == NULL) {
				nm_ref_get(info);
				priv->np_nifp = info;
			}
		} while (0);
		//NMG_UNLOCK();
		break;
	case NIOCTXSYNC:
		if (!priv->np_nifp) {
			error = ENXIO;
			break;
		}
		{
			struct netmapfront_info *info = priv->np_nifp;
			struct netmap_ring_info *ring_info = &info->ring_info[0];
			kick_backend(ring_info, NR_TX);
		}
		break;
	case NIOCRXSYNC:
		if (!priv->np_nifp) {
			error = ENXIO;
			break;
		}
		{
			struct netmapfront_info *info = priv->np_nifp;
			struct netmap_ring_info *ring_info = &info->ring_info[0];
			kick_backend(ring_info, NR_RX);
		}
		break;
	default:
		error = EOPNOTSUPP;
	}

	return (error);
}

#ifndef NETMAP_LINUX_HAVE_UNLOCKED_IOCTL
#define LIN_IOCTL_NAME	.ioctl
static int
linux_netmap_ioctl(struct inode *inode, struct file *file, u_int cmd, u_long data /* arg */)
#else
#define LIN_IOCTL_NAME	.unlocked_ioctl
static long
linux_netmap_ioctl(struct file *file, u_int cmd, u_long data /* arg */)
#endif
{
	struct vnetmap_priv_d *priv = file->private_data;
	int ret = 0;
	union {
		struct nm_ifreq ifr;
		struct nmreq nmr;
	} arg;
	size_t argsize = 0;

	switch (cmd) {
	case NIOCTXSYNC:
	case NIOCRXSYNC:
		break;
	case NIOCCONFIG:
		argsize = sizeof(arg.ifr);
		break;
	default:
		argsize = sizeof(arg.nmr);
		break;
	}
	if (argsize) {
		if (!data)
			return -EINVAL;
		bzero(&arg, argsize);
		if (copy_from_user(&arg, (void *)data, argsize) != 0)
			return -EFAULT;
	}
	ret = vnetmap_ioctl(priv, cmd, (caddr_t)&arg, NULL);
	if (data && copy_to_user((void*)data, &arg, argsize) != 0)
		return -EFAULT;
	return -ret;
}

void vnetmap_dtor(struct vnetmap_priv_d *priv)
{
	struct netmapfront_info *info = priv->np_nifp;
	struct gntdev_priv *gpriv = &priv->gntpriv;
	struct grant_map *map;

	if (info)
		nm_ref_put(info);

	mutex_lock(&gpriv->lock);
	while (!list_empty(&gpriv->maps)) {
		map = list_entry(gpriv->maps.next, struct grant_map, next);
		list_del(&map->next);
		gntdev_put_map(NULL /* already removed */, map);
	}
	WARN_ON(!list_empty(&gpriv->freeable_maps));
	mutex_unlock(&gpriv->lock);

	if (use_ptemod)
		mmu_notifier_unregister(&gpriv->mn, gpriv->mm);

	kfree(priv);
}

static int
linux_netmap_release(struct inode *inode, struct file *file)
{
	(void)inode;	/* UNUSED */
	if (file->private_data)
		vnetmap_dtor(file->private_data);
	return (0);
}

static void unmap_if_in_range(struct grant_map *map,
			      unsigned long start, unsigned long end)
{
	unsigned long mstart, mend;
	int err;

	if (!map->vma)
		return;
	if (map->vma->vm_start >= end)
		return;
	if (map->vma->vm_end <= start)
		return;
	mstart = max(start, map->vma->vm_start);
	mend   = min(end,   map->vma->vm_end);
	pr_debug("map %d+%d (%lx %lx), range %lx %lx, mrange %lx %lx\n",
			map->index, map->count,
			map->vma->vm_start, map->vma->vm_end,
			start, end, mstart, mend);
	err = unmap_grant_pages(map,
				(mstart - map->vma->vm_start) >> PAGE_SHIFT,
				(mend - mstart) >> PAGE_SHIFT);
	WARN_ON(err);
}

static void mn_invl_range_start(struct mmu_notifier *mn,
				struct mm_struct *mm,
				unsigned long start, unsigned long end)
{
	struct gntdev_priv *priv = container_of(mn, struct gntdev_priv, mn);
	struct grant_map *map;

	mutex_lock(&priv->lock);
	list_for_each_entry(map, &priv->maps, next) {
		unmap_if_in_range(map, start, end);
	}
	list_for_each_entry(map, &priv->freeable_maps, next) {
		unmap_if_in_range(map, start, end);
	}
	mutex_unlock(&priv->lock);
}

static void mn_invl_page(struct mmu_notifier *mn,
			 struct mm_struct *mm,
			 unsigned long address)
{
	mn_invl_range_start(mn, mm, address, address + PAGE_SIZE);
}

static void mn_release(struct mmu_notifier *mn,
		       struct mm_struct *mm)
{
	struct gntdev_priv *priv = container_of(mn, struct gntdev_priv, mn);
	struct grant_map *map;
	int err;

	mutex_lock(&priv->lock);
	list_for_each_entry(map, &priv->maps, next) {
		if (!map->vma)
			continue;
		pr_debug("map %d+%d (%lx %lx)\n",
				map->index, map->count,
				map->vma->vm_start, map->vma->vm_end);
		err = unmap_grant_pages(map, /* offset */ 0, map->count);
		WARN_ON(err);
	}
	list_for_each_entry(map, &priv->freeable_maps, next) {
		if (!map->vma)
			continue;
		pr_debug("map %d+%d (%lx %lx)\n",
				map->index, map->count,
				map->vma->vm_start, map->vma->vm_end);
		err = unmap_grant_pages(map, /* offset */ 0, map->count);
		WARN_ON(err);
	}
	mutex_unlock(&priv->lock);
}

static const struct mmu_notifier_ops gntdev_mmu_ops = {
	.release                = mn_release,
	.invalidate_page        = mn_invl_page,
	.invalidate_range_start = mn_invl_range_start,
};

struct vnetmap_priv_d *vnetmap_priv_new(void)
{
	struct vnetmap_priv_d *priv = kzalloc(sizeof(struct vnetmap_priv_d), GFP_KERNEL);
	struct gntdev_priv *gpriv;
	int ret = 0;

	if (!priv)
		return NULL;
	gpriv = &priv->gntpriv;

	INIT_LIST_HEAD(&gpriv->maps);
	INIT_LIST_HEAD(&gpriv->freeable_maps);
	mutex_init(&gpriv->lock);

	if (use_ptemod) {
		gpriv->mm = get_task_mm(current);
		if (!gpriv->mm) {
			kfree(priv);
			//return -ENOMEM;
			return NULL;
		}
		gpriv->mn.ops = &gntdev_mmu_ops;
		ret = mmu_notifier_register(&gpriv->mn, gpriv->mm);
		mmput(gpriv->mm);
	}

	if (ret) {
		kfree(priv);
		return NULL;
	}

	return priv;
}

static int
linux_netmap_open(struct inode *inode, struct file *file)
{
	struct vnetmap_priv_d *priv;
	int error;
	(void)inode;	/* UNUSED */

	//NMG_LOCK();
	priv = vnetmap_priv_new();
	if (priv == NULL) {
		error = -ENOMEM;
		goto out;
	}
	file->private_data = priv;
out:
	//NMG_UNLOCK();

	return (0);
}

static struct file_operations netmap_fops = {
    .owner = THIS_MODULE,
    .open = linux_netmap_open,
    .mmap = linux_netmap_mmap,
    LIN_IOCTL_NAME = linux_netmap_ioctl,
    .poll = linux_netmap_poll,
    .release = linux_netmap_release,
};

struct miscdevice netmap_cdevsw = { /* same name as FreeBSD */
	MISC_DYNAMIC_MINOR,
	"netmap",
	&netmap_fops,
};

static struct cdev *netmap_dev; /* /dev/netmap character device. */

int vnetmap_init(void)
{
	int error = 0;
	netmap_dev = make_dev_credf(MAKEDEV_ETERNAL_KLD,
		&netmap_cdevsw, 0, NULL, UID_ROOT, GID_WHEEL, 0600,
				"netmap");
	if (!netmap_dev)
		return -EFAULT;
	use_ptemod = !xen_feature(XENFEAT_auto_translated_physmap);
	if (use_ptemod) {
		D("Use ptemod");
	} else {
		D("NO Use ptemod");
	}
	D("virtual netmap cdev created");
	return 0;
}

void vnetmap_exit(void)
{
	if (netmap_dev)
		destroy_dev(netmap_dev);
	D("virtual netmap cdev destroyed");
}

MODULE_LICENSE("Dual BSD/GPL");
