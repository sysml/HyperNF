/*
 *
 * Copyright (c) 2016-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Authors: Kenichi Yasukata
 *
 */

#include "common.h"

struct xenbus_ring_ops {
	int (*map)(struct xenbus_device *dev,
		   grant_ref_t *gnt_refs, unsigned int nr_grefs,
		   void **vaddr);
	int (*unmap)(struct xenbus_device *dev, void *vaddr);
};

static const struct xenbus_ring_ops *ring_ops __read_mostly;

static struct list_head nf_info_list;
static spinlock_t nf_list_lock;

void nm_ref_init(struct netmapfront_info *info)
{
	spin_lock(&info->nm_lock);
	atomic_set(&info->nm_refs, 0);
	info->nm_mode = 0;
	spin_unlock(&info->nm_lock);
}

void nm_ref_get(struct netmapfront_info *info)
{
	int ret;
	spin_lock(&info->nm_lock);
	ret = atomic_inc_return(&info->nm_refs);
	info->nm_mode = 1;
	XD("Set netmap mode : ref %d", ret);
	spin_unlock(&info->nm_lock);
}

void nm_ref_put(struct netmapfront_info *info)
{
	int ret;
	spin_lock(&info->nm_lock);
	ret = atomic_dec_return(&info->nm_refs);
	if (ret == 0) {
		info->nm_mode = 0;
		XD("Unset netmap mode");
	} else {
		XD("Decrease reference , now %d", ret);
	}
	spin_unlock(&info->nm_lock);
}

/* Copied from netmap_user.h */
static inline uint32_t
nm_ring_next(struct netmap_ring *r, uint32_t i)
{
	return ( unlikely(i + 1 == r->num_slots) ? 0 : i + 1);
}

/* Copied from netmap_user.h */
static inline uint32_t
nm_ring_space(struct netmap_ring *ring)
{
        int ret = ring->tail - ring->cur;
        if (ret < 0)
                ret += ring->num_slots;
        return ret;
}

static unsigned int xennet_max_queues;

struct netmapfront_stats {
	u64			packets;
	u64			bytes;
	struct u64_stats_sync	syncp;
};

struct xenbus_map_node {
	struct list_head next;
	union {
		struct {
			struct vm_struct *area;
		} pv;
		struct {
			struct page *pages[XENBUS_MAX_NETMAP_PAGES];
			unsigned long addrs[XENBUS_MAX_NETMAP_GRANTS];
			void *addr;
		} hvm;
	};
	grant_handle_t handles[XENBUS_MAX_NETMAP_GRANTS];
	unsigned int   nr_handles;
};

static DEFINE_SPINLOCK(xenbus_valloc_lock);
static LIST_HEAD(xenbus_valloc_pages);

#define NM_RX_RING_HAS_UNCONSUMED_RESPONSES(nm_ring) \
	(nm_ring->head != nm_ring->tail)

static void register_nf_info(struct netmapfront_info *info, bool reg)
{
	spin_lock(&nf_list_lock);
	if (reg) {
		D("Add %p", info);
		list_add(&info->head, &nf_info_list);
	} else {
		D("Del %p", info);
		list_del(&info->head);
	}
	spin_unlock(&nf_list_lock);
}

static void *get_nm_mem_by_dom0_nm_mem(void *nm_mem)
{
	struct netmapfront_info *info = NULL;
	struct list_head *pos, *next;

	spin_lock(&nf_list_lock);
	list_for_each_safe(pos, next, &nf_info_list) {
		info = list_entry(pos, struct netmapfront_info, head);
		if (!info->gi)
			continue;
		D("%p : %p", info->gi->dom0_nm_mem, nm_mem);
		if (info->gi->dom0_nm_mem == nm_mem) {
			if (info->nm_mem) {
				D("Found %p", info->nm_mem);
				spin_unlock(&nf_list_lock);
				return info->nm_mem;
			}
		}
	}
	spin_unlock(&nf_list_lock);

	return NULL;
}

static int xennetmap_open(struct net_device *dev)
{
	struct netmapfront_info *info = netdev_priv(dev);
	unsigned int num_rings = info->num_rings;
	unsigned int i = 0;
	struct netmap_ring_info *ring_info = NULL;

	for (i = 0; i < num_rings; ++i) {
		ring_info = &info->ring_info[i];
		napi_enable(&ring_info->napi);

		spin_lock_bh(&ring_info->rx_lock);
		if (netif_carrier_ok(dev)) {
			if (NM_RX_RING_HAS_UNCONSUMED_RESPONSES(&ring_info->rx_ring))
				napi_schedule(&ring_info->napi);
		}
		spin_unlock_bh(&ring_info->rx_lock);
	}

	netif_tx_start_all_queues(dev);

	return 0;
}

static int xennetmap_close(struct net_device *dev)
{
	struct netmapfront_info *info = netdev_priv(dev);
	unsigned int num_rings = info->num_rings;
	unsigned int i = 0;
	struct netmap_ring_info *ring_info = NULL;
	netif_tx_stop_all_queues(info->netdev);
	for (i = 0; i < num_rings; ++i) {
		ring_info = &info->ring_info[i];
		napi_disable(&ring_info->napi);
	}
	return 0;
}

static int xennetmap_write(struct sk_buff *skb, struct netmap_ring *tx_ring)
{
	u_int j, k;
	int cnt = 0;

	rmb();

	j = tx_ring->cur;
	k = tx_ring->tail;

	if (j != k) {
		struct netmap_slot *slot = &tx_ring->slot[j];
		char *txbuf = NETMAP_BUF(tx_ring, slot->buf_idx);
		if (skb->data_len) {
			memcpy(txbuf, skb->data, skb->len);
		} else {
			int i;
			ssize_t copy, maxlen, offset = 0;
			maxlen = ETH_FRAME_LEN;
			copy = skb->len - skb->data_len;
			memcpy(txbuf, skb->data, copy);
			offset += copy;
			maxlen -= copy;
			for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
				copy = skb->data_len;
				if (unlikely(maxlen < copy)) {
					XD("This should never happen");
					break;
				}
				memcpy(txbuf + offset,
						page_address(skb_shinfo(skb)->frags[i].page.p)
						+ skb_shinfo(skb)->frags[i].page_offset
						+ offset,
						copy);
				offset += copy;
				maxlen -= copy;
			}
		}
		slot->len = skb->len;
		j = nm_ring_next(tx_ring, j);
		cnt++;
	} else
		return -EBUSY;

	tx_ring->head = tx_ring->cur = j;

	wmb();

	return cnt;
}

static inline int xennetmap_count_skb_slots(struct sk_buff *skb)
{
	return (skb->len / ETH_DATA_LEN) + 1;
}

static int xennetmap_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct netmapfront_info *info = netdev_priv(dev);
	struct netmapfront_stats *tx_stats = this_cpu_ptr(info->tx_stats);
	struct netmap_ring *tx_ring;
	int notify;
	int slots;
	unsigned long flags;
	struct netmap_ring_info *ring_info = NULL;
	unsigned int num_queues = info->num_rings;
	u16 queue_index;

	/* Drop the packet if no queues are set up */
	if (num_queues < 1)
		goto drop;
	/* Determine which queue to transmit this SKB on */
	queue_index = skb_get_queue_mapping(skb);
	ring_info = &info->ring_info[queue_index];
	tx_ring = NETMAP_TXRING(info->nifp, queue_index);

	/* If skb->len is too big for wire format, drop skb and alert
	 * user about misconfiguration.
	 */
	if (unlikely(skb->len > XEN_NETMAPIF_MAX_TX_SIZE)) {
		net_alert_ratelimited(
			"xennet: skb->len = %u, too big for wire format\n",
			skb->len);
		goto drop;
	}

	slots = xennetmap_count_skb_slots(skb);
	if (unlikely(slots > MAX_XEN_SKB_FRAGS + 1)) {
		net_dbg_ratelimited("xennet: skb rides the rocket: %d slots, %d bytes\n",
				    slots, skb->len);
		if (skb_linearize(skb))
			goto drop;
	}

	spin_lock_irqsave(&ring_info->tx_lock, flags);

	if (unlikely(!netif_carrier_ok(dev))) {
		goto drop;
	}

	notify = xennetmap_write(skb, tx_ring);

	if (notify)
		kick_backend(ring_info, NR_TX);

	u64_stats_update_begin(&tx_stats->syncp);
	tx_stats->bytes += skb->len;
	tx_stats->packets++;
	u64_stats_update_end(&tx_stats->syncp);

	dev_kfree_skb_irq(skb);

	spin_unlock_irqrestore(&ring_info->tx_lock, flags);

	return NETDEV_TX_OK;

 drop:
	dev->stats.tx_dropped++;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static int xennetmap_change_mtu(struct net_device *dev, int mtu)
{
	if (mtu > ETH_DATA_LEN)
		return -EINVAL;
	dev->mtu = mtu;
	return 0;
}

static struct rtnl_link_stats64 *xennetmap_get_stats64(struct net_device *dev,
						    struct rtnl_link_stats64 *tot)
{
	return tot;
}

static netdev_features_t xennetmap_fix_features(struct net_device *dev,
	netdev_features_t features)
{
	return features;
}

static int xennetmap_set_features(struct net_device *dev,
	netdev_features_t features)
{
	if (!(features & NETIF_F_SG) && dev->mtu > ETH_DATA_LEN) {
		netdev_info(dev, "Reducing MTU because no SG offload");
		dev->mtu = ETH_DATA_LEN;
	}

	return 0;
}

static u16 xennetmap_select_queue(struct net_device *dev, struct sk_buff *skb,
			       void *accel_priv, select_queue_fallback_t fallback)
{
	return 0;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void xennetmap_poll_controller(struct net_device *dev)
{

}
#endif


static const struct net_device_ops xennetmap_netdev_ops = {
	.ndo_open            = xennetmap_open,
	.ndo_stop            = xennetmap_close,
	.ndo_start_xmit      = xennetmap_start_xmit,
	.ndo_change_mtu	     = xennetmap_change_mtu,
	.ndo_get_stats64     = xennetmap_get_stats64,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_validate_addr   = eth_validate_addr,
	.ndo_fix_features    = xennetmap_fix_features,
	.ndo_set_features    = xennetmap_set_features,
	.ndo_select_queue    = xennetmap_select_queue,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = xennetmap_poll_controller,
#endif
};

/* Copied from xen-netfront.c */
static int checksum_setup(struct net_device *dev, struct sk_buff *skb)
{
	bool recalculate_partial_csum = false;

	/*
	 * A GSO SKB must be CHECKSUM_PARTIAL. However some buggy
	 * peers can fail to set NETRXF_csum_blank when sending a GSO
	 * frame. In this case force the SKB to CHECKSUM_PARTIAL and
	 * recalculate the partial checksum.
	 */
	if (skb->ip_summed != CHECKSUM_PARTIAL && skb_is_gso(skb)) {
		struct netmapfront_info *info = netdev_priv(dev);
		atomic_inc(&info->rx_gso_checksum_fixup);
		skb->ip_summed = CHECKSUM_PARTIAL;
		recalculate_partial_csum = true;
	}

	/* A non-CHECKSUM_PARTIAL SKB does not require setup. */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	return skb_checksum_setup(skb, recalculate_partial_csum);
}

static int xennetmap_poll(struct napi_struct *napi, int budget)
{
	struct netmap_ring_info *ring_info = container_of(napi, struct netmap_ring_info, napi);
	struct netmapfront_stats *rx_stats = this_cpu_ptr(ring_info->info->rx_stats);
	struct netmap_ring *rx_ring = ring_info->rx_ring;
	u_int j, k, cnt = 0;
	struct sk_buff *skb;
	int work_done;

	spin_lock(&ring_info->rx_lock);

	rmb(); /* Ensure we see queued responses up to 'rp'. */

	work_done = 0;

	j = rx_ring->cur;
	k = rx_ring->tail;

	while ((j != k) && (cnt < budget)) {
		struct netmap_slot *slot = &rx_ring->slot[j];
		char *rxbuf = NETMAP_BUF(rx_ring, slot->buf_idx);
		//int i;

		skb = dev_alloc_skb(slot->len);
		if (unlikely(!skb)) {
			XD("Failed to allocate skb");
			break;
		}

		memcpy(skb->data, rxbuf, slot->len);
		skb->dev = ring_info->info->netdev;
		skb_put(skb, slot->len);

		//printk("[%p:%p][%u]: ", skb->head, skb->data, skb->len);
		//for (i = 0; i < skb->len; i++) {
		//	printk("%c", *((char *) skb->data + i));
		//}
		//printk("\n");

		skb->protocol = eth_type_trans(skb, ring_info->info->netdev);
		skb_reset_network_header(skb);

		if (checksum_setup(ring_info->info->netdev, skb)) {
			XD("checksum setup failed");
			kfree_skb(skb);
			ring_info->info->netdev->stats.rx_errors++;
			continue;
		}

		u64_stats_update_begin(&rx_stats->syncp);
		rx_stats->packets++;
		rx_stats->bytes += skb->len;
		u64_stats_update_end(&rx_stats->syncp);

		napi_gro_receive(&ring_info->napi, skb);
		cnt++;

		j = nm_ring_next(rx_ring, j);
	}

	rx_ring->head = rx_ring->cur = j;

	wmb();

	kick_backend(ring_info, NR_RX);

	if (cnt < budget) {
		napi_complete(&ring_info->napi);
		if (NM_RX_RING_HAS_UNCONSUMED_RESPONSES(rx_ring))
			napi_schedule(&ring_info->napi);
	}

	spin_unlock(&ring_info->rx_lock);

	return cnt;
}

/* Copy from linux-4.6.2 
 * We need to break the limit of default
 * XENBUS_MAX_NETMAP_GRANTS.
 */
static int __xenbus_map_ring(struct xenbus_device *dev,
			     grant_ref_t *gnt_refs,
			     unsigned int nr_grefs,
			     grant_handle_t *handles,
			     phys_addr_t *addrs,
			     unsigned int flags,
			     bool *leaked)
{
	struct gnttab_map_grant_ref *map;
	struct gnttab_unmap_grant_ref *unmap;
	int i, j;
	int err = GNTST_okay;

	map = kzalloc(sizeof(struct gnttab_map_grant_ref) * nr_grefs, GFP_KERNEL);
	if (!map) {
		XD("fail alloc map");
		err = GNTST_general_error;
		goto fail_out;
	}

	unmap = kzalloc(sizeof(struct gnttab_unmap_grant_ref) * nr_grefs, GFP_KERNEL);
	if (!map) {
		XD("fail alloc unmap");
		err = GNTST_general_error;
		goto fail_kfree_map;
	}

	for (i = 0; i < nr_grefs; i++) {
		memset(&map[i], 0, sizeof(map[i]));
		gnttab_set_map_op(&map[i], addrs[i], flags, gnt_refs[i],
				  dev->otherend_id);
		handles[i] = INVALID_GRANT_HANDLE;
	}

	gnttab_batch_map(map, i);

	for (i = 0; i < nr_grefs; i++) {
		if (map[i].status != GNTST_okay) {
			err = map[i].status;
			xenbus_dev_fatal(dev, map[i].status,
					 "[%d]: mapping in shared page %d from domain %d",
					 i,
					 gnt_refs[i], dev->otherend_id);
			goto fail;
		} else
			handles[i] = map[i].handle;
	}
	err = GNTST_okay;
	goto out;

 fail:
	for (i = j = 0; i < nr_grefs; i++) {
		if (handles[i] != INVALID_GRANT_HANDLE) {
			memset(&unmap[j], 0, sizeof(unmap[j]));
			gnttab_set_unmap_op(&unmap[j], (phys_addr_t)addrs[i],
					    GNTMAP_host_map, handles[i]);
			j++;
		}
	}

	if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, unmap, j))
		BUG();

	*leaked = false;
	for (i = 0; i < j; i++) {
		if (unmap[i].status != GNTST_okay) {
			*leaked = true;
			break;
		}
	}
out:
	kfree(unmap);
fail_kfree_map:
	kfree(map);
fail_out:
	return err;
}

static int xenbus_map_ring_valloc_pv(struct xenbus_device *dev,
				     grant_ref_t *gnt_refs,
				     unsigned int nr_grefs,
				     void **vaddr)
{
	struct xenbus_map_node *node;
	struct vm_struct *area;
	pte_t **ptes;
	phys_addr_t *phys_addrs;
	int err = GNTST_okay;
	int i;
	bool leaked = false;

	*vaddr = NULL;

	XD("nr_grefs %u", nr_grefs);

	ptes = kzalloc(sizeof(pte_t *) * nr_grefs, GFP_KERNEL);
	if (!ptes) {
		XD("ptes alloc failed");
		err = -ENOMEM;
		goto fail_out;
	}

	phys_addrs = kzalloc(sizeof(phys_addr_t) * nr_grefs, GFP_KERNEL);
	if (!phys_addrs) {
		XD("phys_addrs alloc failed");
		err = -ENOMEM;
		goto fail_kfree_ptes;
	}

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		XD("node alloc failed");
		err = -ENOMEM;
		goto fail_kfree_node;
	}

	area = alloc_vm_area(XEN_PAGE_SIZE * nr_grefs, ptes);
	if (!area) {
		XD("area alloc failed");
		err = -ENOMEM;
		goto fail_kfree_node;
	}

	for (i = 0; i < nr_grefs; i++)
		phys_addrs[i] = arbitrary_virt_to_machine(ptes[i]).maddr;

	err = __xenbus_map_ring(dev, gnt_refs, nr_grefs, node->handles,
				phys_addrs,
				GNTMAP_host_map | GNTMAP_contains_pte,
				&leaked);
	if (err)
		goto failed;
	XD("Mapped top pa:%llx", phys_addrs[0]);

	node->nr_handles = nr_grefs;
	node->pv.area = area;

	spin_lock(&xenbus_valloc_lock);
	list_add(&node->next, &xenbus_valloc_pages);
	spin_unlock(&xenbus_valloc_lock);

	*vaddr = area->addr;

	kfree(phys_addrs);
	kfree(ptes);
	return 0;

failed:
	if (!leaked)
		free_vm_area(area);
	else
		pr_alert("leaking VM area %p size %u page(s)", area, nr_grefs);
fail_kfree_node:
	kfree(node);
fail_kfree_ptes:
	kfree(ptes);
fail_out:
	return err;
}

static int xenbus_unmap_ring_vfree_pv(struct xenbus_device *dev,
				      void *vaddr)
{
	struct xenbus_map_node *node;
	struct gnttab_unmap_grant_ref *unmap;
	unsigned int level;
	int i;
	bool leaked = false;
	int err;

	spin_lock(&xenbus_valloc_lock);
	list_for_each_entry(node, &xenbus_valloc_pages, next) {
		if (node->pv.area->addr == vaddr) {
			list_del(&node->next);
			goto found;
		}
	}
	node = NULL;
 found:
	spin_unlock(&xenbus_valloc_lock);

	if (!node) {
		xenbus_dev_error(dev, -ENOENT,
				 "can't find mapped virtual address %p", vaddr);
		return GNTST_bad_virt_addr;
	}

	unmap = kzalloc(sizeof(struct gnttab_unmap_grant_ref) * node->nr_handles, GFP_KERNEL);
	if (!unmap) {
		XD("ptes alloc failed");
		return -ENOMEM;
	}

	for (i = 0; i < node->nr_handles; i++) {
		unsigned long addr;

		memset(&unmap[i], 0, sizeof(unmap[i]));
		addr = (unsigned long)vaddr + (XEN_PAGE_SIZE * i);
		unmap[i].host_addr = arbitrary_virt_to_machine(
			lookup_address(addr, &level)).maddr;
		unmap[i].dev_bus_addr = 0;
		unmap[i].handle = node->handles[i];
	}

	if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, unmap, i))
		BUG();

	err = GNTST_okay;
	leaked = false;
	for (i = 0; i < node->nr_handles; i++) {
		if (unmap[i].status != GNTST_okay) {
			leaked = true;
			xenbus_dev_error(dev, unmap[i].status,
					 "unmapping page at handle %d error %d",
					 node->handles[i], unmap[i].status);
			err = unmap[i].status;
			break;
		}
	}

	if (!leaked)
		free_vm_area(node->pv.area);
	else
		pr_alert("leaking VM area %p size %u page(s)",
			 node->pv.area, node->nr_handles);

	kfree(node);
	kfree(unmap);
	return err;
}

static void _gnttab_foreach_grant(struct page **pages,
			  unsigned int nr_grefs,
			  xen_grant_fn_t fn,
			  void *data)
{
	unsigned int goffset = 0;
	unsigned long xen_pfn = 0;
	unsigned int i;

	for (i = 0; i < nr_grefs; i++) {
		if ((i % XEN_PFN_PER_PAGE) == 0) {
			xen_pfn = page_to_xen_pfn(pages[i / XEN_PFN_PER_PAGE]);
			goffset = 0;
		}

		fn(pfn_to_gfn(xen_pfn), goffset, XEN_PAGE_SIZE, data);

		goffset += XEN_PAGE_SIZE;
		xen_pfn++;
	}
}

struct map_ring_valloc_hvm
{
	unsigned int idx;

	/* Why do we need two arrays? See comment of __xenbus_map_ring */
	phys_addr_t *phys_addrs;
	unsigned long *addrs;
};

static void xenbus_map_ring_setup_grant_hvm(unsigned long gfn,
					    unsigned int goffset,
					    unsigned int len,
					    void *data)
{
	struct map_ring_valloc_hvm *info = data;
	unsigned long vaddr = (unsigned long)gfn_to_virt(gfn);

	info->phys_addrs[info->idx] = vaddr;
	info->addrs[info->idx] = vaddr;

	info->idx++;
}

static int ex_xenbus_unmap_ring(struct xenbus_device *dev,
		      grant_handle_t *handles, unsigned int nr_handles,
		      unsigned long *vaddrs)
{
	struct gnttab_unmap_grant_ref *unmap;
	int i;
	int err;

	unmap = kzalloc(sizeof(struct gnttab_unmap_grant_ref) * nr_handles, GFP_KERNEL);
	if (unmap == NULL)
		return -ENOMEM;

	for (i = 0; i < nr_handles; i++)
		gnttab_set_unmap_op(&unmap[i], vaddrs[i],
				    GNTMAP_host_map, handles[i]);

	if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, unmap, i))
		BUG();

	err = GNTST_okay;
	for (i = 0; i < nr_handles; i++) {
		if (unmap[i].status != GNTST_okay) {
			xenbus_dev_error(dev, unmap[i].status,
					 "unmapping page at handle %d error %d",
					 handles[i], unmap[i].status);
			err = unmap[i].status;
			break;
		}
	}

	return err;
}

static int xenbus_map_ring_valloc_hvm(struct xenbus_device *dev,
				      grant_ref_t *gnt_ref,
				      unsigned int nr_grefs,
				      void **vaddr)
{
	struct xenbus_map_node *node;
	int err;
	void *addr;
	bool leaked = false;
	struct map_ring_valloc_hvm info = {
		.idx = 0,
	};
	unsigned int nr_pages = XENBUS_PAGES(nr_grefs);

	info.phys_addrs = kzalloc(sizeof(phys_addr_t) * nr_grefs, GFP_KERNEL);
	if (info.phys_addrs == NULL)
		return -ENOMEM;

	info.addrs = kzalloc(sizeof(unsigned long) * nr_grefs, GFP_KERNEL);
	if (info.addrs == NULL) {
		kfree(info.phys_addrs);
		return -ENOMEM;
	}

	*vaddr = NULL;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	err = alloc_xenballooned_pages(nr_pages, node->hvm.pages);
	if (err)
		goto out_err;

	_gnttab_foreach_grant(node->hvm.pages, nr_grefs,
			     xenbus_map_ring_setup_grant_hvm,
			     &info);

	err = __xenbus_map_ring(dev, gnt_ref, nr_grefs, node->handles,
				info.phys_addrs, GNTMAP_host_map, &leaked);
	node->nr_handles = nr_grefs;

	if (err)
		goto out_free_ballooned_pages;

	addr = vmap(node->hvm.pages, nr_pages, VM_MAP | VM_IOREMAP,
		    PAGE_KERNEL);
	if (!addr) {
		err = -ENOMEM;
		goto out_xenbus_unmap_ring;
	}

	node->hvm.addr = addr;

	spin_lock(&xenbus_valloc_lock);
	list_add(&node->next, &xenbus_valloc_pages);
	spin_unlock(&xenbus_valloc_lock);

	*vaddr = addr;
	kfree(info.phys_addrs);
	kfree(info.addrs);
	return 0;

 out_xenbus_unmap_ring:
	if (!leaked)
		ex_xenbus_unmap_ring(dev, node->handles, nr_grefs, info.addrs);
	else
		pr_alert("leaking %p size %u page(s)",
			 addr, nr_pages);
 out_free_ballooned_pages:
	if (!leaked)
		free_xenballooned_pages(nr_pages, node->hvm.pages);
 out_err:
	kfree(node);
	kfree(info.phys_addrs);
	kfree(info.addrs);
	return err;
}

struct unmap_ring_vfree_hvm
{
	unsigned int idx;
	unsigned long *addrs;
};

static void xenbus_unmap_ring_setup_grant_hvm(unsigned long gfn,
					      unsigned int goffset,
					      unsigned int len,
					      void *data)
{
	struct unmap_ring_vfree_hvm *info = data;

	info->addrs[info->idx] = (unsigned long)gfn_to_virt(gfn);

	info->idx++;
}

static int xenbus_unmap_ring_vfree_hvm(struct xenbus_device *dev, void *vaddr)
{
	int rv;
	struct xenbus_map_node *node;
	void *addr;
	struct unmap_ring_vfree_hvm info = {
		.idx = 0,
	};
	unsigned int nr_pages;

	spin_lock(&xenbus_valloc_lock);
	list_for_each_entry(node, &xenbus_valloc_pages, next) {
		addr = node->hvm.addr;
		if (addr == vaddr) {
			list_del(&node->next);
			goto found;
		}
	}
	node = addr = NULL;
 found:
	spin_unlock(&xenbus_valloc_lock);

	if (!node) {
		xenbus_dev_error(dev, -ENOENT,
				 "can't find mapped virtual address %p", vaddr);
		return GNTST_bad_virt_addr;
	}

	nr_pages = XENBUS_PAGES(node->nr_handles);

	info.addrs = kzalloc(sizeof(unsigned long) * node->nr_handles, GFP_KERNEL);
	if (info.addrs == NULL)
		return GNTST_general_error;

	_gnttab_foreach_grant(node->hvm.pages, node->nr_handles,
			     xenbus_unmap_ring_setup_grant_hvm,
			     &info);

	rv = ex_xenbus_unmap_ring(dev, node->handles, node->nr_handles,
			       info.addrs);
	if (!rv) {
		vunmap(vaddr);
		free_xenballooned_pages(nr_pages, node->hvm.pages);
	}
	else
		WARN(1, "Leaking %p, size %u page(s)\n", vaddr, nr_pages);

	kfree(node);
	kfree(info.addrs);
	return rv;
}

static const struct xenbus_ring_ops ring_ops_pv = {
	.map = xenbus_map_ring_valloc_pv,
	.unmap = xenbus_unmap_ring_vfree_pv,
};

static const struct xenbus_ring_ops ring_ops_hvm = {
	.map = xenbus_map_ring_valloc_hvm,
	.unmap = xenbus_unmap_ring_vfree_hvm,
};

static int ex_xenbus_map_ring_valloc(struct xenbus_device *dev, grant_ref_t *gnt_refs,
			   unsigned int nr_grefs, void **vaddr)
{
	return ring_ops->map(dev, gnt_refs, nr_grefs, vaddr);
}

static int ex_xenbus_unmap_ring_vfree(struct xenbus_device *dev, void *vaddr)
{
	return ring_ops->unmap(dev, vaddr);
}

static void xennet_disconnect_backend(struct netmapfront_info *info)
{
	int err, i;

	netif_carrier_off(info->netdev);

	if (info->nm_mem) {
		for (i = 0; i < info->num_rings; i++) {
			struct netmap_ring_info *ring_info = &info->ring_info[i];
			unbind_from_irqhandler(ring_info->tx_irq, ring_info);
			ring_info->tx_irq = ring_info->rx_irq = 0;
			if (netif_running(info->netdev))
				napi_synchronize(&ring_info->napi);
		}
		if (info->master) {
			XD("Unmap grant nm_mem");
			err = ex_xenbus_unmap_ring_vfree(info->xbdev, info->nm_mem);
			if (err) {
				XD("fail unmap netmap");
			}
		} else {
			XD("Skip unmapping grant nm_mem, because this is not master");
		}

		err = ex_xenbus_unmap_ring_vfree(info->xbdev, info->gi);
		if (err) {
			XD("fail xenbus_unmap_ring_vfree");
		}
	}
}

static irqreturn_t xennet_rx_interrupt(int irq, void *dev_id)
{
	struct netmap_ring_info *ring_info = dev_id;
	struct net_device *dev = ring_info->info->netdev;

	if (likely(netif_carrier_ok(dev) &&
		   NM_RX_RING_HAS_UNCONSUMED_RESPONSES(&ring_info->rx_ring)))
		napi_schedule(&ring_info->napi);

	return IRQ_HANDLED;
}

static long sync_backend(struct netmap_ring_info *ring_info)
{
	long ret = 0;
	struct privcmd_hypercall hypercall;
	hypercall.op = xennet_op;
	hypercall.arg[0] = XENNETOP_sync;
	hypercall.arg[1] = 0;
	hypercall.arg[2] = ring_info->if_id;
	hypercall.arg[3] = NR_TXRX;
	hypercall.arg[4] = 0;
	ret = __privcmd_hypercall(&hypercall);
	return ret;
}

static irqreturn_t xennet_interrupt(int irq, void *dev_id)
{
	struct netmap_ring_info *ring_info = dev_id;
	bool rxfound = false;
	if (ring_info->info->nm_mode) {
		vnetmap_notify(ring_info, NR_TXRX);
		return IRQ_HANDLED;
	}
	sync_backend(ring_info);
	//txfound = (ring_info->tx_ring->cur != ring_info->tx_ring->tail);
	rxfound = (ring_info->rx_ring->cur != ring_info->rx_ring->tail);
	if (rxfound)
		return xennet_rx_interrupt(irq, dev_id);
	else
		return IRQ_HANDLED;
}

static void xennetmap_destroy_queues(struct netmapfront_info *info)
{
	int i;

	rtnl_lock();

	for (i = 0; i < info->num_rings; i++) {
		struct netmap_ring_info *ring_info = &info->ring_info[i];
		if (netif_running(info->netdev))
			napi_disable(&ring_info->napi);
		netif_napi_del(&ring_info->napi);
	}

	rtnl_unlock();

	kfree(info->ring_info);
	info->ring_info = NULL;
}

static int __setup_local_info(struct xenbus_device *dev,
			      struct net_device *netdev,
			      struct netmapfront_info *info,
			      struct netmap_ring_info *ring_info,
			      int id)
{
	int err;

	err = xenbus_alloc_evtchn(dev, &ring_info->tx_evtchn);
	if (err < 0)
		goto fail;

	err = bind_evtchn_to_irqhandler(ring_info->tx_evtchn,
					xennet_interrupt,
					0, netdev->name, ring_info);
	if (err < 0)
		goto bind_fail;
	ring_info->rx_evtchn = ring_info->tx_evtchn;
	ring_info->rx_irq = ring_info->tx_irq = err;

	ring_info->xbdev = dev;
	ring_info->info = info;

	ring_info->id = id;
	ring_info->if_id = info->gi->if_id;
	ring_info->type = info->gi->type;

	ring_info->tx_ring = NETMAP_TXRING(info->nifp, id);
	ring_info->rx_ring = NETMAP_RXRING(info->nifp, id);

	spin_lock_init(&ring_info->tx_lock);
	spin_lock_init(&ring_info->rx_lock);

	nm_os_selinfo_init(&ring_info->si[NR_TX]);
	nm_os_selinfo_init(&ring_info->si[NR_RX]);

	netif_napi_add(netdev, &ring_info->napi, xennetmap_poll, 64);
	if (netif_running(netdev))
		napi_enable(&ring_info->napi);

	return 0;

bind_fail:
	xenbus_free_evtchn(dev, ring_info->tx_evtchn);
	ring_info->tx_evtchn = 0;
fail:
	return err;
}

static int setup_local_info(struct netmapfront_info *info)
{
	int i;

	if (info->nifp->ni_tx_rings != info->nifp->ni_rx_rings) {
		XD("TX/RX rings should be the same number");
		return -EINVAL;
	}

	info->num_rings = min(info->nifp->ni_tx_rings, xennet_max_queues);
	info->ring_info = kzalloc(sizeof(struct netmap_ring_info) * info->num_rings,
				  GFP_KERNEL);

	for (i = 0; i < info->num_rings; i++) {
		__setup_local_info(info->xbdev, info->netdev, info, info->ring_info, i);
	}

	return 0;
}

static int write_ring_xenstore_keys(struct netmap_ring_info *ring_info,
				    struct xenbus_transaction *xbt)
{
	struct xenbus_device *dev = ring_info->xbdev;
	int err;
	const char *message;
	char *path;
	size_t pathsize;

	pathsize = strlen(dev->nodename) + 10;
	path = kzalloc(pathsize, GFP_KERNEL);
	if (!path) {
		err = -ENOMEM;
		message = "out of memory while writing ring references";
		goto error_out;
	}
	snprintf(path, pathsize, "%s/ring-%u",
			dev->nodename, ring_info->id);
	err = xenbus_printf(*xbt, path,
			"event-channel", "%u", ring_info->tx_evtchn);
	if (err) {
		message = "writing event-channel";
		goto error;
	}

	kfree(path);
	return 0;

error:
	xenbus_dev_fatal(dev, err, "%s", message);
	kfree(path);
error_out:
	return err;
}

static int xen_net_read_mac(struct xenbus_device *dev, u8 mac[])
{
	char *s, *e, *macstr;
	int i;

	macstr = s = xenbus_read(XBT_NIL, dev->nodename, "mac", NULL);
	if (IS_ERR(macstr))
		return PTR_ERR(macstr);

	for (i = 0; i < ETH_ALEN; i++) {
		mac[i] = simple_strtoul(s, &e, 16);
		if ((s == e) || (*e != ((i == ETH_ALEN-1) ? '\0' : ':'))) {
			kfree(macstr);
			return -ENOENT;
		}
		s = e+1;
	}

	kfree(macstr);
	return 0;
}

static int talk_to_netback(struct xenbus_device *dev,
			   struct netmapfront_info *info)
{
	int err;
	unsigned int i;
	struct xenbus_transaction xbt;
	char path[strlen("gref-info-xx") + 1];
	grant_ref_t grefs[100]; // Assume grant info table is less than 100 pages
	void *addr;
	struct netmap_ring *txring, *rxring;
	struct netmap_ring_info *ring_info;

	info->otherend_id = dev->otherend_id;

	err = xen_net_read_mac(dev, info->netdev->dev_addr);
	if (err) {
		xenbus_dev_fatal(dev, err, "parsing %s/mac", dev->nodename);
		goto failed_out;
	}

	err = xenbus_scanf(XBT_NIL, info->xbdev->otherend,
			   "gref-info-pages", "%u", &info->gref_info_pages);
	if (err < 0) {
		XD("No netmap info");
		goto failed_out;
	}

	for (i = 0; i < info->gref_info_pages; i++) {
		snprintf(path, sizeof(path), "gref-info-%u", i);
		err = xenbus_scanf(XBT_NIL, info->xbdev->otherend,
				   path, "%u", &grefs[i]);
		if (err < 0) {
			xenbus_dev_fatal(dev, err, "reading %s", path);
			XD("xenbus scanf fail %d : %d?", i, err);
		}
	}

	err = ex_xenbus_map_ring_valloc(info->xbdev, grefs, info->gref_info_pages, &addr);
	if (err) {
		XD("failed to map info page");
		goto failed_out;
	}

	info->gi = (struct grant_info *) addr;
	info->nr_memsize = PAGE_SIZE * info->gi->num_grefs;

	D("dom0_nm_mem %p", info->gi->dom0_nm_mem);
	addr = get_nm_mem_by_dom0_nm_mem(info->gi->dom0_nm_mem);
	D("addr %p", addr);
	if (addr != NULL) {
		info->master = 0;
		info->nm_mem = addr;
		XD("Share nm_mem %p", info->nm_mem);
	} else {
		err = ex_xenbus_map_ring_valloc(info->xbdev, info->gi->grefs, info->gi->num_grefs, &addr);
		if (err) {
			XD("failed to map netmap %d", err);

			err = ex_xenbus_unmap_ring_vfree(info->xbdev, info->gi);
			if (err) {
				XD("fail xenbus_unmap_ring_vfree");
			}
			XD("success unmap ginfo");

			goto failed_out;
		}

		info->master = 1;
		XD("Map nm_mem %p", addr);
	}
	info->nm_mem = addr;

	XD("netmap is mapped at %p", info->nm_mem);

	info->nifp = NETMAP_IF(addr, info->gi->nr_offset);
	txring = NETMAP_TXRING(info->nifp, 0);
	rxring = NETMAP_RXRING(info->nifp, 0);
	XD("txring %d:%d, rxring %d:%d",
			info->nifp->ni_tx_rings,
			txring->num_slots,
			info->nifp->ni_rx_rings,
			rxring->num_slots);

	setup_local_info(info);

again:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		goto destroy_ring;
	}

	for (i = 0; i < info->num_rings; i++) {
		ring_info = &info->ring_info[i];
		err = write_ring_xenstore_keys(ring_info, &xbt);
		if (err)
			goto abort_transaction_no_dev_fatal;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err) {
		if (err == -EAGAIN)
			goto again;
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto destroy_ring;
	}

	return 0;

//abort_transaction:
	//xenbus_dev_fatal(dev, err, "%s", message);
abort_transaction_no_dev_fatal:
	xenbus_transaction_end(xbt, 1);
destroy_ring:
	xennet_disconnect_backend(info);
failed_out:
	return err;
}

static void xennet_free_netdev(struct net_device *netdev)
{
	struct netmapfront_info *info = netdev_priv(netdev);

	register_nf_info(info, false);

	free_percpu(info->rx_stats);
	free_percpu(info->tx_stats);
	free_netdev(netdev);
}

static struct net_device *xennet_create_dev(struct xenbus_device *dev)
{
	struct net_device *netdev;
	struct netmapfront_info *info;
	int err;

	netdev = alloc_etherdev_mq(sizeof(struct netmapfront_info), xennet_max_queues);
	if (!netdev)
		return ERR_PTR(-ENOMEM);
	XD("new dev is created");

	info = netdev_priv(netdev);
	info->xbdev = dev;
	info->nm_mem = NULL; // For sure
	info->netdev = netdev;

	spin_lock_init(&info->nm_lock);
	nm_ref_init(info);

	register_nf_info(info, true);

	err = -ENOMEM;
	info->rx_stats = netdev_alloc_pcpu_stats(struct netmapfront_stats);
	if (info->rx_stats == NULL) {
		XD("rx stats is NULL, exit");
		goto exit;
	}
	info->tx_stats = netdev_alloc_pcpu_stats(struct netmapfront_stats);
	if (info->tx_stats == NULL) {
		XD("tx stats is NULL, exit");
		goto exit;
	}

	netdev->netdev_ops = &xennetmap_netdev_ops;

	netdev->features = NETIF_F_GSO_ROBUST;
	netdev->hw_features = NETIF_F_SG;

	netdev->features |= netdev->hw_features;

	//netdev->ethtool_ops = &xennet_ethtool_ops;
	SET_NETDEV_DEV(netdev, &dev->dev);

	netif_carrier_off(netdev);

	dev_set_drvdata(&dev->dev, info);

	return netdev;
 exit:
	xennet_free_netdev(netdev);
	return ERR_PTR(err);
}

static int netmapfront_probe(struct xenbus_device *dev,
			  const struct xenbus_device_id *id)
{
	int err;
	struct net_device *netdev;

	netdev = xennet_create_dev(dev);
	if (IS_ERR(netdev)) {
		err = PTR_ERR(netdev);
		xenbus_dev_fatal(dev, err, "creating netdev");
		return err;
	}

	err = register_netdev(netdev);
	if (err) {
		pr_warn("%s: register_netdev err=%d\n", __func__, err);
		goto fail;
	}

	return 0;

fail:
	xennet_free_netdev(netdev);
	dev_set_drvdata(&dev->dev, NULL);
	return err;
}

static int netmapfront_resume(struct xenbus_device *dev)
{
	struct netmapfront_info *info = dev_get_drvdata(&dev->dev);

	dev_dbg(&dev->dev, "%s\n", dev->nodename);

	xennet_disconnect_backend(info);

	return 0;
}

static int xennet_connect(struct net_device *dev)
{
	struct netmapfront_info *info = netdev_priv(dev);
	int err;

	err = talk_to_netback(info->xbdev, info);
	if (err)
		return err;

	rtnl_lock();
	netdev_update_features(dev);
	rtnl_unlock();

	netif_carrier_on(info->netdev);

	return 0;
}

static void netback_changed(struct xenbus_device *dev,
			    enum xenbus_state backend_state)
{
	struct netmapfront_info *info = dev_get_drvdata(&dev->dev);
	struct net_device *netdev = info->netdev;

	dev_dbg(&dev->dev, "%s\n", xenbus_strstate(backend_state));

	switch (backend_state) {
	case XenbusStateInitialising:
	case XenbusStateInitialised:
	case XenbusStateReconfiguring:
	case XenbusStateReconfigured:
	case XenbusStateUnknown:
		break;

	case XenbusStateInitWait:
		if (dev->state != XenbusStateInitialising)
			break;
		if (xennet_connect(netdev) != 0)
			break;
		xenbus_switch_state(dev, XenbusStateConnected);
		break;

	case XenbusStateConnected:
		netdev_notify_peers(netdev);
		break;

	case XenbusStateClosed:
		if (dev->state == XenbusStateClosed)
			break;
		/* Missed the backend's CLOSING state -- fallthrough */
	case XenbusStateClosing:
		xenbus_frontend_closed(dev);
		break;
	}
}

static int xennet_remove(struct xenbus_device *dev)
{
	struct netmapfront_info *info = dev_get_drvdata(&dev->dev);

	dev_dbg(&dev->dev, "%s\n", dev->nodename);

	xennet_disconnect_backend(info);

	unregister_netdev(info->netdev);

	if (info->ring_info)
		xennetmap_destroy_queues(info);

	xennet_free_netdev(info->netdev);

	XD("remove nmif %s", dev->nodename);
	return 0;
}

static const struct xenbus_device_id netmapfront_ids[] = {
	{ "nmif" },
	{ "" }
};

static struct xenbus_driver netmapfront_driver = {
	.ids = netmapfront_ids,
	.probe = netmapfront_probe,
	.remove = xennet_remove,
	.resume = netmapfront_resume,
	.otherend_changed = netback_changed,
};

static void xenbus_ring_ops_init(void)
{
	if (!xen_feature(XENFEAT_auto_translated_physmap)) {
		XD("Run over PV mode");
		ring_ops = &ring_ops_pv;
	} else {
		XD("Run over HVM mode");
		ring_ops = &ring_ops_hvm;
	}
}

static int __init netif_init(void)
{
	XD("try init");
	if (!xen_domain())
		return -ENODEV;

	xenbus_ring_ops_init();

	pr_info("Initialising Xen virtual ethernet driver\n");
	XD("netmapfront INIT");

	INIT_LIST_HEAD(&nf_info_list);
	spin_lock_init(&nf_list_lock);

	if (xennet_max_queues == 0)
		xennet_max_queues = num_online_cpus();

	vnetmap_init();

	return xenbus_register_frontend(&netmapfront_driver);
}
module_init(netif_init);


static void __exit netif_exit(void)
{
	XD("netmapfront EXIT");
	vnetmap_exit();
	xenbus_unregister_driver(&netmapfront_driver);
}
module_exit(netif_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("xen-netmap-frontend");
MODULE_AUTHOR("Kenichi Yasukata");
