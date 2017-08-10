/*
 *
 * Copyright (c) 2016-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Authors: Kenichi Yasukata
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/types.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include <asm/desc.h>
#include <asm/uaccess.h>

#include <xen/xen.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>

#include "common.h"
#include "xennet.h"

static void nm_bdg_detach(struct netmap_vp_adapter *na_vp);

static inline struct backend_info *backend_info_hwna(struct netmap_adapter *na)
{
	struct backend_info *be;
	if (na->ifp && ((be = backend_info_get_by_name(na->ifp->if_xname)) != NULL))
		return be;
	else
		return NULL;
}

static inline int
num_pages(size_t size)
{
	return size == 0 ? 0 : ((size - 1) / PAGE_SIZE) + 1;
}

static inline int
HYPERVISOR_xennet_op(unsigned int cmd, void *uop, unsigned int count, unsigned int count2)
{
	return _hypercall4(int, xennet_op, cmd, uop, count, count2);
}

static irqreturn_t
xennet_rx_irq_handler(int irq, void *dev_id)
{
	struct netmap_kring *kring = (struct netmap_kring *) dev_id;
	kring->nm_notify(kring, 0);
	return IRQ_HANDLED;
}

// Copied from linux
/* Interrupt types. */
enum xen_irq_type {
	IRQT_UNBOUND = 0,
	IRQT_PIRQ,
	IRQT_VIRQ,
	IRQT_IPI,
	IRQT_EVTCHN
};

/*
 * Packed IRQ information:
 * type - enum xen_irq_type
 * event channel - irq->event channel mapping
 * cpu - cpu this event channel is bound to
 * index - type-specific information:
 *    PIRQ - vector, with MSB being "needs EIO", or physical IRQ of the HVM
 *           guest, or GSI (real passthrough IRQ) of the device.
 *    VIRQ - virq number
 *    IPI - IPI vector
 *    EVTCHN -
 */
struct irq_info {
	struct list_head list;
	int refcnt;
	enum xen_irq_type type;	/* type */
	unsigned irq;
	unsigned int evtchn;	/* event channel */
	unsigned short cpu;	/* cpu bound */

	union {
		unsigned short virq;
		enum ipi_vector ipi;
		struct {
			unsigned short pirq;
			unsigned short gsi;
			unsigned char vector;
			unsigned char flags;
			uint16_t domid;
		} pirq;
	} u;
};

static struct irq_info *__info_for_irq(unsigned irq)
{
	return irq_get_handler_data(irq);
}

unsigned int __evtchn_from_irq(unsigned irq)
{
	return __info_for_irq(irq)->evtchn;
}

int xennet_free_evtchn(int port)
{
	struct evtchn_close close;
	int err;

	close.port = port;

	err = HYPERVISOR_event_channel_op(EVTCHNOP_close, &close);
	if (err)
		XD("freeing event channel %d", port);

	return err;
}

int xennet_alloc_evtchn(int *port)
{
	struct evtchn_alloc_unbound alloc_unbound;
	int err;

	//alloc_unbound.dom = DOMID_SELF;
	alloc_unbound.dom = DOM0ID;
	//alloc_unbound.remote_dom = dev->otherend_id;
	//alloc_unbound.remote_dom = DOMID_SELF;
	alloc_unbound.remote_dom = DOM0ID;

	err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound,
					  &alloc_unbound);
	if (err) {
		XD("allocating event channel");
	} else {
		*port = alloc_unbound.port;
	}

	return err;
}

static void __xennet_unbind_kring_evtchn(struct netmap_kring *kring)
{
	if (kring->xen_irq1) {
		unbind_from_irqhandler(kring->xen_irq1, kring);
		kring->xen_irq1 = 0;
	}

	if (kring->xen_irq2) {
		unbind_from_irqhandler(kring->xen_irq2, kring);
		kring->xen_irq2 = 0;
	}

	kring->evtchn_port = 0;
}

static void xennet_unbind_kring_evtchn(struct backend_info *be)
{
	struct xennmif *nmif = be->nmif;
	struct netmap_adapter *na;
	struct netmap_kring *kring;
	int i;

	na = nmif->na;

	for (i = 0; i < na->num_rx_rings; i++) {
		kring = &na->rx_rings[i];
		__xennet_unbind_kring_evtchn(kring);
	}
}

static inline void __xennet_unset_kring_evtchn(struct netmap_kring *kring)
{
	kring->xen_irq1 = 0;
	kring->xen_irq2 = 0;
	kring->evtchn_port = 0;
}

void xennet_unset_kring_evtchn(struct backend_info *be)
{
	struct xennmif *nmif = be->nmif;
	struct netmap_adapter *na;
	struct netmap_kring *kring;
	int i;

	na = nmif->na;

	for (i = 0; i < na->num_rx_rings; i++) {
		kring = &na->rx_rings[i];
		__xennet_unset_kring_evtchn(kring);
	}

	for (i = 0; i < na->num_rx_rings; i++) {
		kring = &na->tx_rings[i];
		__xennet_unset_kring_evtchn(kring);
	}
}

static inline void __xennet_set_kring_evtchn(struct netmap_kring *kring,
					     unsigned int evtchn, unsigned int irq)
{
	kring->evtchn_port = __evtchn_from_irq(irq);
	kring->xen_irq2 = irq;
}

void xennet_set_kring_evtchn(struct backend_info *be)
{
	struct xennmif *nmif = be->nmif;
	struct netmap_adapter *na;
	struct netmap_kring *kring;
	struct netmap_ring_info *ring_info;
	int i;

	na = nmif->na;

	for (i = 0; i < na->num_rx_rings; i++) {
		kring = &na->rx_rings[i];
		ring_info = &nmif->ring_info[i];
		__xennet_set_kring_evtchn(kring, ring_info->tx_evtchn, ring_info->tx_irq);
	}

	for (i = 0; i < na->num_tx_rings; i++) {
		kring = &na->tx_rings[i];
		ring_info = &nmif->ring_info[i];
		__xennet_set_kring_evtchn(kring, ring_info->tx_evtchn, ring_info->tx_irq);
	}
}

static int __xennet_bind_kring_evtchn(struct netmap_kring *kring)
{
	int err = 0;
	uint32_t evtchn = 0;
	char irq_name[128];

	if (kring->tx == NR_TX) {
		XD("This ring is for tx");
		return -EINVAL;
	}

	err = xennet_alloc_evtchn(&evtchn);
	if (err < 0) {
		XD("failed to alloc evtchn");
		goto out;
	}

	XD("bind 1");
	snprintf(irq_name, sizeof(irq_name), "%s-src", kring->name);
	// FIXME: Optimal interrupt CPU assignemnt and distribution
	err = bind_evtchn_to_irqhandler(evtchn,
					xennet_rx_irq_handler,
					smp_processor_id(), irq_name, kring);
	if (err < 0) {
		XD("failed to bind evtchn");
		goto out1;
	}
	kring->xen_irq1 = err;
	kring->evtchn_port = evtchn;
	XD("bound 1 %d", err);

	XD("bind 2");
	snprintf(irq_name, sizeof(irq_name), "%s-dst", kring->name);
	err = bind_interdomain_evtchn_to_irqhandler(DOMID_SELF,
					evtchn,
					xennet_rx_irq_handler,
					smp_processor_id(), irq_name, kring);
	kring->xen_irq2 = err;
	XD("bound 2 %d", err);

	return err;
out1:
	xennet_free_evtchn(evtchn);
out:
	return err;
}

static int xennet_bind_kring_evtchn(struct backend_info *be)
{
	struct xennmif *nmif = be->nmif;
	struct netmap_adapter *na;
	struct netmap_kring *kring;
	int i, ret = 0;

	na = nmif->na;

	for (i = 0; i < na->num_rx_rings; i++) {
		kring = &na->rx_rings[i];
		if ((ret = __xennet_bind_kring_evtchn(kring)) < 0) {
			XD("Failed to bind kring evtchn %d", i);
			xennet_unbind_kring_evtchn(be);
			break;
		}
	}

	return ret;
}

static int xennet_map(void *frames, domid_t target, uint16_t if_id, uint16_t id2,
		      uint16_t operation, uint16_t operation2,
		      uint32_t page_cnt, uint64_t pgoff,
		      uint32_t objoff,
		      phys_addr_t pa, uint32_t len)
{
	int err = 0;
	struct xennet_mem_op op;

	memset(&op, 0, sizeof(struct xennet_mem_op));

	op.dom = DOM0ID;
	op.target_dom = target;
	op.op = operation;
	op.op2 = operation2;
	op.id = if_id;
	op.id2 = id2;
	op.objoff = objoff;
	op.pgoff = pgoff;
	op.pa = pa;
	op.len = len;
	op.nr_frames = page_cnt;

	set_xen_guest_handle(op.frame_list, frames);

	err = HYPERVISOR_xennet_op(XENNETOP_mem_netmap, &op, page_cnt, 0);
	if (err < 0) {
		XD("hypercall map failed %d", err);
	}

	return err;
}

static int __map_xennet_obj(void *addr, domid_t target,
			    uint16_t operation, uint16_t operation2,
			    uint16_t if_id, uint16_t id2,
			    size_t obj_size, uint64_t objoff)
{
	int i, err = 0, page_cnt;
	unsigned long pa, pfn, off = 0, pgoff = 0;
	xen_pfn_t *frames;

	pgoff = (unsigned long) addr;
	pgoff &= ~PAGE_MASK;
	page_cnt = num_pages(obj_size + pgoff);

	frames = kzalloc(sizeof(xen_pfn_t) * page_cnt, GFP_KERNEL);
	if (!frames) {
		XD("failed to alloc frames");
		return -ENOMEM;
	}

	for (i = 0; i < page_cnt; i++) {
		pa = virt_to_phys(addr + off);
		if (pa == 0) {
			XD("Bad address");
			err = -EINVAL;
			goto fail;
		}

		pfn = pa >> PAGE_SHIFT;
		if (!pfn_valid(pfn)) {
			XD("Bad pfn %p, %lx, %lx", addr, pa, pfn);
			err = -EINVAL;
			goto fail;
		}

		frames[i] = pfn_to_gfn(pfn);
		off += PAGE_SIZE;
	}

	if ((err = xennet_map(frames, target, if_id, id2,
			      operation, operation2,
			      page_cnt, pgoff, objoff, 0, 0)) < 0) {
		XD("failed to map xennet %d", err);
	}
fail:
	kfree(frames);

	return err;
}

static int __map_xennet_obj_phys(phys_addr_t addr, domid_t target,
				 uint16_t operation, uint16_t operation2,
				 uint16_t if_id, uint16_t id2,
				 size_t obj_size, uint64_t objoff)
{
	int err = 0, page_cnt;
	unsigned long pgoff = 0;

	pgoff = (unsigned long) addr;
	pgoff &= ~PAGE_MASK;
	page_cnt = num_pages(obj_size);

	if ((err = xennet_map(NULL, target, if_id, id2,
			      operation, operation2,
			      page_cnt, pgoff, objoff, addr, obj_size)) < 0) {
		XD("failed to map xennet %d", err);
	}

	return err;
}

int detach_xennet_bdg(struct backend_info *be)
{
	struct xennmif *nmif;
	int err = 0;

	nmif = be->nmif;
	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return -EINVAL;
	}

	if ((err = xennet_map(NULL, be->dev->otherend_id, nmif->if_id, -1,
			      XENNETOP_MEM_bdg_detach, 0, 0, 0, 0, 0, 0)) < 0) {
		XD("failed to unmap xennet nmifobj");
	}

	return err;
}

/* everything is unmapped by Xen */
int unmap_xennet_kringobj(struct backend_info *be)
{
	struct xennmif *nmif = be->nmif;
	int err = 0;

	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return -EINVAL;
	}

	if ((err = xennet_map(NULL, be->dev->otherend_id, nmif->if_id, -1,
			      XENNETOP_MEM_unmap_kring_objoff, 0, 0, 0, 0, 0, 0)) < 0) {
		XD("failed to unmap xennet kringobj");
	}

	return err;
}

int map_xennet_kringobj(struct backend_info *be)
{
	struct xennmif *nmif = be->nmif;
	struct netmap_adapter *na;
	struct netmap_vp_adapter *na_vp;
	struct netmap_kring *kring;
	struct netmap_ring *xen_ring;
	int i, err = 0;

	struct nm_bdg_fwd *xen_nkr_ft;
	uint32_t *xen_nkr_leases;

	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return -EINVAL;
	}

	na = nmif->na;

	na_vp = (struct netmap_vp_adapter *) na;
	na = &na_vp->up;

#define MAP_XENNET_OBJ(objname, objaddr, objsize, kring_id, op2) \
	do {									    \
		objname = objaddr;						    \
		err = __map_xennet_obj(objname, be->dev->otherend_id,		    \
				       XENNETOP_MEM_map_kring_objoff,		    \
				       op2,					    \
				       nmif->if_id,				    \
				       kring_id,				    \
				       objsize,					    \
				       offsetof(struct netmap_kring, objname));	    \
		if (err) {							    \
			XD("map failed %d", err);				    \
			goto fail;						    \
		}								    \
	} while (0)

	for (i = 0; i < na->num_tx_rings; i++) {
		kring = &na->tx_rings[i];
		if (kring->nkr_ft) {
			int l, num_dstq;
			num_dstq = NM_BDG_MAXPORTS * NM_BDG_MAXRINGS + 1;
			l = sizeof(struct nm_bdg_fwd) * NM_BDG_BATCH_MAX;
			l += sizeof(struct nm_bdg_q) * num_dstq;
			l += sizeof(uint16_t) * NM_BDG_BATCH_MAX;
			MAP_XENNET_OBJ(xen_nkr_ft, kring->nkr_ft,
				       l, kring->ring_id, NR_TX);
		}
		if (kring->nkr_leases) {
			u_int nrx = netmap_real_rings(na, NR_RX);
			u_int tailroom = sizeof(uint32_t) * na->num_rx_desc * nrx;
			MAP_XENNET_OBJ(xen_nkr_leases, kring->nkr_leases,
				       tailroom, kring->ring_id, NR_TX);
		}
		if (kring->ring) {
			MAP_XENNET_OBJ(xen_ring, kring->ring,
				       sizeof(struct netmap_ring)
					+ (sizeof(struct netmap_slot) * kring->ring->num_slots),
				       kring->ring_id, NR_TX);
		}
	}
	for (i = 0; i < na->num_rx_rings; i++) {
		kring = &na->rx_rings[i];
		if (kring->nkr_ft) {
			int l, num_dstq;
			num_dstq = NM_BDG_MAXPORTS * NM_BDG_MAXRINGS + 1;
			l = sizeof(struct nm_bdg_fwd) * NM_BDG_BATCH_MAX;
			l += sizeof(struct nm_bdg_q) * num_dstq;
			l += sizeof(uint16_t) * NM_BDG_BATCH_MAX;
			MAP_XENNET_OBJ(xen_nkr_ft, kring->nkr_ft,
				       l, kring->ring_id, NR_RX);
		}
		if (kring->nkr_leases) {
			u_int nrx = netmap_real_rings(na, NR_RX);
			u_int tailroom = sizeof(uint32_t) * na->num_rx_desc * nrx;
			MAP_XENNET_OBJ(xen_nkr_leases, kring->nkr_leases,
				       tailroom, kring->ring_id, NR_RX);
		}
		if (kring->ring) {
			MAP_XENNET_OBJ(xen_ring, kring->ring,
				       sizeof(struct netmap_ring)
					+ (sizeof(struct netmap_slot) * kring->ring->num_slots),
				       kring->ring_id, NR_RX);
		}
	}
#undef MAP_XENNET_OBJ

	return err;
fail:
	unmap_xennet_nmifobj(be);
	return err;
}

/* everything is unmapped by Xen */
int unmap_xennet_nmifobj(struct backend_info *be)
{
	struct xennmif *nmif = be->nmif;
	int err = 0;

	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return -EINVAL;
	}

	if ((err = xennet_map(NULL, be->dev->otherend_id, nmif->if_id, -1,
			      XENNETOP_MEM_unmap_nmif_objoff, 0, 0, 0, 0, 0, 0)) < 0) {
		XD("failed to unmap xennet nmifobj");
	}

	return err;
}

void prepare_lut(struct lut_entry *lut, size_t objsize)
{
	int i;
	xen_pfn_t pfn;
	for (i = 0; i < objsize; i++) {
		if (lut[i].gfn) {
			XD("lut already has gfn values %d, %ld", i, lut[i].gfn);
			break;
		}
		pfn = lut[i].paddr >> PAGE_SHIFT;
		lut[i].gfn = pfn_to_gfn(pfn);
	}
}

int map_xennet_nmifobj(struct backend_info *be)
{
	struct xennmif *nmif = be->nmif;
	struct netmap_adapter *na;
	struct netmap_vp_adapter *na_vp;
	int err = 0;
	bool is_hw = false;

	struct nm_bridge *na_bdg;
	uint32_t *up_na_flags;
	uint64_t *last_smac;
	int *bdg_port;
	u_int *mfs;
	u_int *up_virt_hdr_len;
	uint32_t *nm_buf_size;
	uint32_t *nm_objtotal;
	struct lut_entry *xen_lut;

	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return -EINVAL;
	}

	na = nmif->na;
	na_vp = (struct netmap_vp_adapter *) na;
	if (!na_vp->na_bdg)
		is_hw = true;

#define MAP_XENNET_OBJ(objname, objaddr, objsize) \
	do {									    \
		objname = objaddr;						    \
		if (!objname) {							    \
			XD("no %s %p, %p", #objname, na, na_vp);		    \
			goto out;						    \
		}								    \
		err = __map_xennet_obj(objname, be->dev->otherend_id,		    \
				       XENNETOP_MEM_map_nmif_objoff,		    \
				       0,					    \
				       nmif->if_id,				    \
				       0,					    \
				       objsize,					    \
				       offsetof(struct xen_netmapif, objname));	    \
		if (err) {							    \
			XD("map failed %d", err);				    \
			goto fail;						    \
		}								    \
	} while (0)

	MAP_XENNET_OBJ(up_na_flags, &na->na_flags, sizeof(uint32_t));
	if (!is_hw) {
		MAP_XENNET_OBJ(last_smac, &na_vp->last_smac, sizeof(uint64_t));
		MAP_XENNET_OBJ(bdg_port, &na_vp->bdg_port, sizeof(int));
		MAP_XENNET_OBJ(mfs, &na_vp->mfs, sizeof(u_int));
	}
	MAP_XENNET_OBJ(up_virt_hdr_len, &na->virt_hdr_len, sizeof(u_int));
	MAP_XENNET_OBJ(nm_buf_size, &na->na_lut.objsize, sizeof(uint32_t));
	MAP_XENNET_OBJ(nm_objtotal, &na->na_lut.objtotal, sizeof(uint32_t));
	prepare_lut(na->na_lut.lut, na->na_lut.objtotal);
	MAP_XENNET_OBJ(xen_lut, na->na_lut.lut, (sizeof(struct lut_entry) * na->na_lut.objtotal));
	if (!is_hw)
		MAP_XENNET_OBJ(na_bdg, na_vp->na_bdg, sizeof(struct nm_bridge));

#undef MAP_XENNET_OBJ
out:
	return err;
fail:
	unmap_xennet_nmifobj(be);
	return err;
}

/* all krings are unmapped by Xen */
int unmap_xennet_kring(struct backend_info *be)
{
	struct xennmif *nmif = be->nmif;
	int err = 0;

	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return -EINVAL;
	}

	if ((err = xennet_map(NULL, be->dev->otherend_id, nmif->if_id, -1,
			      XENNETOP_MEM_unmap_kring, 0, 0, 0, 0, 0, 0)) < 0) {
		XD("failed to unmap xennet");
	}

	return err;
}

int map_xennet_kring(struct backend_info *be)
{
	struct xennmif *nmif = be->nmif;
	struct netmap_adapter *na;
	struct netmap_kring *kring;
	int i, j, err = 0;

	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return -EINVAL;
	}

	na = nmif->na;

	for (i = 0; i < na->num_tx_rings; i++) {
		kring = &na->tx_rings[i];
		if (!kring) {
			XD("no kring %d/%d", i, na->num_tx_rings);
			err = -EINVAL;
			goto unmap_tx;
		}
		//XD("map tx kring[%d][%d]: %p", i, kring->tx, kring);
		err = __map_xennet_obj(kring, be->dev->otherend_id,
				       XENNETOP_MEM_map_kring, na->num_tx_rings,
				       nmif->if_id, kring->ring_id,
				       sizeof(struct netmap_kring), 0);
		if (err < 0) {
unmap_tx:
			XD("failed to map tx kring xennet %d", err);
			for (j = 0; j < i; j++) {
				kring = &na->tx_rings[j];
				unmap_xennet_kring(be);
			}
		}
	}

	for (i = 0; i < na->num_rx_rings; i++) {
		kring = &na->rx_rings[i];
		if (!kring) {
			XD("no kring %d/%d", i, na->num_tx_rings);
			err = -EINVAL;
			goto unmap_rx;
		}
		//XD("map rx kring[%d][%d]: %p", i, kring->tx, kring);
		err = __map_xennet_obj(kring, be->dev->otherend_id,
				       XENNETOP_MEM_map_kring, na->num_rx_rings,
				       nmif->if_id, kring->ring_id,
				       sizeof(struct netmap_kring), 0);
		if (err < 0) {
unmap_rx:
			XD("failed to map rx kring xennet %d", err);
			for (j = 0; j < i; j++) {
				kring = &na->rx_rings[j];
				unmap_xennet_kring(be);
			}
		}
	}

	return err;
}

static int __map_xennet_netmap(struct netmap_adapter *na, domid_t target)
{
	int err = 0;

	if ((err = xennet_map(NULL, target, -1, -1, XENNETOP_MEM_map_netmap, 0,
			      0, 0, 0, 0, 0)) < 0) {
		XD("failed to map xennet %d", err);
	}

	return err;
}

int unmap_xennet_netmap(struct backend_info *be)
{
	int err = 0;
	struct xennmif *nmif = be->nmif;

	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return -EINVAL;
	}

	if ((err = xennet_map(NULL, be->dev->otherend_id, nmif->if_id, -1,
			      XENNETOP_MEM_unmap_netmap, 0,
			      0, 0, 0, 0, 0)) < 0) {
		XD("failed to unmap xennet");
	}

	return err;
}

int map_xennet_netmap(struct backend_info *be)
{
	int err = 0;
	struct xennmif *nmif = be->nmif;
	struct netmap_adapter *na;

	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return -EINVAL;
	}
	na = nmif->na;
	err = __map_xennet_netmap(na, be->dev->otherend_id);
	if (err < 0) {
		XD("failed to map xennet %d", err);
	} else {
		XD("set if id %d", err);
		nmif->if_id = err;
		if (!nmif->is_vp) {
			XD("This is HW if");
			if (!nmif->gref_info) {
				err = alloc_grant_info(nmif);
				if (err) {
					XD("grant_info alloc failed");
					goto out;
				}
			}
			nmif->gref_info->if_id = nmif->if_id;
		} else {
			XD("This is SW if");
			if (nmif->gref_info)
				nmif->gref_info->if_id = nmif->if_id;
		}
	}
out:
	return err;
}


// APIs called from netmap

static void nm_backend_info_exit(struct netmap_adapter *na)
{
	struct backend_info *be = (struct backend_info *) na->xen_be;

	if (be) {
		struct xennmif *nmif = be->nmif;

		if (nmif) {
			kfree(nmif);
		}

		if (be->dev) {
			kfree(be->dev);
		}

		kfree(be);
		na->xen_be = NULL;
	}
};

static int nm_backend_info_init(struct netmap_adapter *na)
{
	struct backend_info *be;
	int err = 0;

	na->xen_be = kzalloc(sizeof(struct backend_info), GFP_KERNEL);
	if (!na->xen_be) {
		XD("failed to alloc be");
		err = -ENOMEM;
		goto fail;
	}
	be = (struct backend_info *) na->xen_be;

	be->dev = kzalloc(sizeof(struct xenbus_device), GFP_KERNEL);
	if (!be->dev) {
		XD("failed to alloc be->dev");
		err = -ENOMEM;
		goto fail;
	}
	be->dev->otherend_id = DOM0ID; // Dom0

	be->nmif = kzalloc(sizeof(struct xennmif), GFP_KERNEL);
	if (!be->nmif) {
		XD("failed to alloc nmif");
		err = -ENOMEM;
		goto fail;
	}
	be->nmif->domid = 0;

	be->nmif->na = na;
	be->nmif->if_id = INVALID_IF_ID;

	return err;
fail:
	nm_backend_info_exit(na);

	return err;
}

static void nm_unmap_netmap(struct netmap_adapter *na)
{
	struct backend_info *be = (struct backend_info *) na->xen_be;
	struct netmap_vp_adapter *na_vp = (struct netmap_vp_adapter *) na;

	if (!be) {
		XD("No be found, do nothing");
		return;
	}

	if (!be->nmif->is_vp) {
		na->xen_be = NULL;
		return;
	}

	nm_bdg_detach(na_vp);

	if (unmap_xennet_kringobj(be) < 0) {
		XD("failed to unmap xennet kringobj");
	}

	xennet_unbind_kring_evtchn_hw(na);
	xennet_unbind_kring_evtchn(be);

	if (unmap_xennet_kring(be) < 0) {
		XD("failed to unmap xennet kring");
	}
	if (unmap_xennet_netmap(be) < 0) {
		XD("failed to unmap xennet");
	}
	nm_backend_info_exit(na);
	XD("netmap is unmapped");
}

static int nm_map_netmap(struct netmap_adapter *na, bool is_user, bool is_hwna)
{
	struct backend_info *be;
	int err = 0;

	if (!na) {
		XD("na is null");
		err = -EINVAL;
		goto out1;
	}

	if (na->xen_be) {
		XD("This is already registered");
		err = -EINVAL;
		goto out1;
	}

	if ((be = backend_info_hwna(na)) != NULL) {
		XD("Direct NIC, %s", na->ifp->if_xname);
		na->xen_be = be;
		be->nmif->na = na;
	} else {
		XD("Connected to VALE, %s", na->name);
		if ((err = nm_backend_info_init(na)) < 0) {
			XD("failed to initialize backend_info");
			goto out1;
		}
		be = (struct backend_info *) na->xen_be;
		be->nmif->is_vp = true;
	}

	if ((err = map_xennet_netmap(be)) < 0) {
		XD("failed to map xennet");
		goto out2;
	}

	if ((err = map_xennet_kring(be)) < 0) {
		XD("failed to map xennet");
		goto out3;
	}

	if (is_user) {
		if ((err = xennet_bind_kring_evtchn(be)) < 0) {
			XD("failed to bind kring evtchn");
			goto out4;
		}
	} else if (is_hwna) {
		if ((err = xennet_bind_kring_evtchn_hw(na)) < 0) {
			XD("failed to bind HW kring evtchn");
			goto out4;
		}
	}

	if ((err = map_xennet_kringobj(be)) < 0) {
		XD("failed to map xennet");
		goto out5;
	}

	if ((err = map_xennet_nmifobj(be)) < 0) {
		XD("failed to map xennet");
		goto out6;
	}

	XD("netmap is mapped");

	return err;
out6:
	if (unmap_xennet_kringobj(be) < 0) {
		XD("failed to unmap xennet kringobj");
	}
out5:
	if (is_user) {
		xennet_unbind_kring_evtchn(be);
	} else if (is_hwna) {
		xennet_unbind_kring_evtchn_hw(na);
	}
out4:
	if (unmap_xennet_kring(be) < 0) {
		XD("failed to unmap xennet kring");
	}
out3:
	if (unmap_xennet_netmap(be) < 0) {
		XD("failed to unmap xennet");
	}
out2:
	nm_backend_info_exit(na);
out1:
	return err;
}

static void nm_bdg_detach(struct netmap_vp_adapter *na_vp)
{
	struct backend_info *be = (struct backend_info *) na_vp->up.xen_be;
	struct xennmif *nmif;
	int err = 0;

	if (!be) {
		XD("no xen_be, not registerd");
		return;
	}

	nmif = be->nmif;
	if (!nmif) {
		XD("no nmif is registered");
		return;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return;
	}

	if ((err = xennet_map(NULL, be->dev->otherend_id, nmif->if_id, -1,
			      XENNETOP_MEM_bdg_detach, 0, 0, 0, 0, 0, 0)) < 0) {
		XD("failed to unmap xennet nmifobj");
	}
}

static int __nm_bind_hwsw(struct netmap_adapter *hwna, struct netmap_adapter *swna, bool bind)
{
	struct backend_info *hwbe = (struct backend_info *) hwna->xen_be;
	struct backend_info *swbe = (struct backend_info *) swna->xen_be;
	struct xennmif *hwnmif, *swnmif;
	int err = 0;

	if (!hwbe) {
		XD("no hw xen_be, not registerd");
		return -EINVAL;
	}

	if (!swbe) {
		XD("no hw xen_be, not registerd");
		return -EINVAL;
	}

	if (hwbe->dev->otherend_id != swbe->dev->otherend_id) {
		XD("Invalid domain request hw %d sw %d",
				hwbe->dev->otherend_id,
				swbe->dev->otherend_id);
		return -EINVAL;
	}

	hwnmif = hwbe->nmif;
	if (!hwnmif) {
		XD("no hwnmif is registered");
		return -EINVAL;
	}

	if (!hwnmif->na) {
		XD("no hw netmap registered");
		return -EINVAL;
	}

	swnmif = swbe->nmif;
	if (!swnmif) {
		XD("no swnmif is registered");
		return -EINVAL;
	}

	if (!swnmif->na) {
		XD("no sw netmap registered");
		return -EINVAL;
	}

	if (bind) {
		if ((err = xennet_map(NULL, hwbe->dev->otherend_id,
				      hwnmif->if_id, swnmif->if_id,
				      XENNETOP_MEM_bind_hwsw, 0, 0, 0, 0, 0, 0)) < 0) {
			XD("failed to bind hwsw");
		}
	} else {
		if ((err = xennet_map(NULL, hwbe->dev->otherend_id,
				      hwnmif->if_id, swnmif->if_id,
				      XENNETOP_MEM_unbind_hwsw, 0, 0, 0, 0, 0, 0)) < 0) {
			XD("failed to bind hwsw");
		}
	}

	return err;
}

static void nm_unbind_hwsw(struct netmap_adapter *hwna, struct netmap_adapter *swna)
{
	__nm_bind_hwsw(hwna, swna, false);
}

static int nm_bind_hwsw(struct netmap_adapter *hwna, struct netmap_adapter *swna)
{
	return __nm_bind_hwsw(hwna, swna, true);
}

static int nm_bdg_attach(struct nm_bridge *b, struct netmap_vp_adapter *na_vp)
{
	struct backend_info *be = (struct backend_info *) na_vp->up.xen_be;
	struct xennmif *nmif;
	int err = 0;

	struct nm_bridge *na_bdg;

	if (!be) {
		XD("no xen_be, not registerd");
		return -EINVAL;
	}

	nmif = be->nmif;
	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return -EINVAL;
	}

#define MAP_XENNET_OBJ(objname, objaddr, objsize) \
	do {									    \
		objname = objaddr;						    \
		err = __map_xennet_obj(objname, be->dev->otherend_id,		    \
				       XENNETOP_MEM_map_nmif_objoff,		    \
				       0,					    \
				       nmif->if_id,				    \
				       0,					    \
				       objsize,					    \
				       offsetof(struct xen_netmapif, objname));	    \
		if (err) {							    \
			XD("map failed %d", err);				    \
			goto fail;						    \
		}								    \
	} while (0)

	MAP_XENNET_OBJ(na_bdg, na_vp->na_bdg, sizeof(struct nm_bridge));

#undef MAP_XENNET_OBJ

	return err;
fail:
	unmap_xennet_nmifobj(be);
	return err;
}

static void nm_unmap_i40e(struct netmap_adapter *na)
{
	struct backend_info *be = (struct backend_info *) na->xen_be;
	struct xennmif *nmif;
	int err = 0;

	if (!be) {
		XD("no xen_be, not registerd");
		return;
	}

	nmif = be->nmif;
	if (!nmif) {
		XD("no nmif is registered");
		return;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return;
	}

	if ((err = xennet_map(NULL, be->dev->otherend_id, nmif->if_id, 0,
			      XENNETOP_MEM_unmap_i40e_objoff, 0, 0, 0, 0, 0, 0)) < 0) {
		XD("failed to unmap i40e");
	}

	if ((err = xennet_map(NULL, be->dev->otherend_id, nmif->if_id, 0,
			      XENNETOP_MEM_unmap_i40e, 0, 0, 0, 0, 0, 0)) < 0) {
		XD("failed to unmap i40e");
	}
}

static int nm_map_i40e(struct netmap_adapter *na,
		       resource_size_t dev_hw_addr, resource_size_t resouce_size)
{
	struct backend_info *be = (struct backend_info *) na->xen_be;
	struct xennmif *nmif;
	int err = 0;

	resource_size_t hw_addr;

	if (!be) {
		XD("no xen_be, not registerd");
		return -EINVAL;
	}

	nmif = be->nmif;
	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return -EINVAL;
	}

#define MAP_XENNET_OBJ_PHYS(objname, objaddr, objsize) \
	do {									    \
		objname = objaddr;						    \
		err = __map_xennet_obj_phys(objname, be->dev->otherend_id,	    \
				       XENNETOP_MEM_map_i40e,			    \
				       0,					    \
				       nmif->if_id,				    \
				       0,					    \
				       objsize,					    \
				       offsetof(struct hwif, objname));		    \
		if (err) {							    \
			XD("map failed %d", err);				    \
			goto fail;						    \
		}								    \
	} while (0)

	ND("try map hw_addr %llx %llu", dev_hw_addr, resouce_size);
	MAP_XENNET_OBJ_PHYS(hw_addr, dev_hw_addr, resouce_size);
#undef MAP_XENNET_OBJ_PHYS

	return err;
fail:
	return err;
}

static int nm_map_i40e_ring(struct netmap_adapter *na, int rid,
			    void *tx_ring, size_t size_tx_ring,
			    void *rx_ring, size_t size_rx_ring,
			    void *tx_rc_ptr, void *rx_rc_ptr,
			    u16 *base_queue_ptr, u16 *queue_index_ptr,
			    u32 *base_vector_ptr,
			    u32 *hung_detected_ptr,
			    u32 *state_ptr,
			    u64 *flags_ptr)
{
	struct backend_info *be = (struct backend_info *) na->xen_be;
	struct xennmif *nmif;
	struct i40e_ring *txr = (struct i40e_ring *) tx_ring;
	struct i40e_ring *rxr = (struct i40e_ring *) rx_ring;
	int err = 0;

	void *hw_tx_rings;
	void *hw_rx_rings;
	void *xen_tx_desc;
	void *xen_rx_desc;
	u16 *base_queue;
	u16 *queue_index;
	u32 *base_vector;
	u32 *hung_detected;
	u32 *state;
	u64 *flags;
	struct i40e_ring_container *tx_rc;
	struct i40e_ring_container *rx_rc;

	if (!be) {
		XD("no xen_be, not registerd");
		return -EINVAL;
	}

	nmif = be->nmif;
	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	if (!nmif->na) {
		XD("no netmap registered");
		return -EINVAL;
	}

#define MAP_XENNET_OBJ(objname, objaddr, objsize, ring_id) \
	do {									    \
		objname = objaddr;						    \
		err = __map_xennet_obj(objname, be->dev->otherend_id,		    \
				       XENNETOP_MEM_map_i40e,			    \
				       0,					    \
				       nmif->if_id,				    \
				       ring_id,					    \
				       objsize,					    \
				       offsetof(struct hwif, objname));		    \
		if (err) {							    \
			XD("map failed %d", err);				    \
			goto fail;						    \
		}								    \
	} while (0)

#define MAP_XENNET_OBJ_RING_OBJ(objname, objaddr, objsize, ring_id) \
	do {									    \
		objname = objaddr;						    \
		err = __map_xennet_obj(objname, be->dev->otherend_id,		    \
				       XENNETOP_MEM_map_i40e_objoff,		    \
				       0,					    \
				       nmif->if_id,				    \
				       ring_id,					    \
				       objsize,					    \
				       offsetof(struct i40e_hwinfo, objname));	    \
		if (err) {							    \
			XD("map failed %d", err);				    \
			goto fail;						    \
		}								    \
	} while (0)

	ND("map hw txring %p", txr);
	MAP_XENNET_OBJ(hw_tx_rings, txr, size_tx_ring, rid);
	ND("map tx ring[%d] desc %p %u", rid, txr->desc, txr->size);
	ND("map hw rxring %p", rxr);
	MAP_XENNET_OBJ(hw_rx_rings, rxr, size_rx_ring, rid);
	ND("map rx ring[%d] desc %p %u", rid, rxr->desc, rxr->size);
	MAP_XENNET_OBJ_RING_OBJ(xen_tx_desc, txr->desc, txr->size, rid);
	MAP_XENNET_OBJ_RING_OBJ(xen_rx_desc, rxr->desc, rxr->size, rid);
	MAP_XENNET_OBJ_RING_OBJ(tx_rc, tx_rc_ptr, sizeof(struct i40e_ring_container), rid);
	MAP_XENNET_OBJ_RING_OBJ(rx_rc, rx_rc_ptr, sizeof(struct i40e_ring_container), rid);
	MAP_XENNET_OBJ_RING_OBJ(base_queue, base_queue_ptr, sizeof(u16), rid);
	MAP_XENNET_OBJ_RING_OBJ(queue_index, queue_index_ptr, sizeof(u16), rid);
	MAP_XENNET_OBJ_RING_OBJ(base_vector, base_vector_ptr, sizeof(u32), rid);
	MAP_XENNET_OBJ_RING_OBJ(hung_detected, hung_detected_ptr, sizeof(u32), rid);
	MAP_XENNET_OBJ_RING_OBJ(state, state_ptr, sizeof(u32), rid);
	MAP_XENNET_OBJ_RING_OBJ(flags, flags_ptr, sizeof(u64), rid);
#undef MAP_XENNET_OBJ_RING
#undef MAP_XENNET_OBJ_RING_OBJ

	return err;
fail:
	return err;
}

static int __xennet_manage_irq(unsigned int irq, unsigned int irqtype,
			       unsigned int if_id, unsigned int ring_id, bool expose)
{
	int err = 0;
	struct xennet_irq_op op;

	memset(&op, 0, sizeof(struct xennet_irq_op));

	if (expose)
		op.op = XENNETOP_IRQ_register;
	else
		op.op = XENNETOP_IRQ_unregister;
	op.dom = DOM0ID;
	op.id = if_id;
	op.id2 = ring_id;
	op.pirq = xen_pirq_from_irq(irq);
	op.type = irqtype;

	err = HYPERVISOR_xennet_op(XENNETOP_irq, &op, 0, 0);
	if (err < 0) {
		XD("hypercall expose failed %d", err);
	}

	return err;
}

static int xennet_unexpose_irq(struct netmap_adapter *na, unsigned int irq,
			       unsigned int irqtype, unsigned int ring_id)
{
	struct backend_info *be = (struct backend_info *) na->xen_be;
	struct xennmif *nmif;

	if (!be) {
		XD("no xen_be, not registerd");
		return -EINVAL;
	}

	nmif = be->nmif;
	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	return __xennet_manage_irq(irq, irqtype, nmif->if_id, ring_id, false);
}

static int xennet_expose_irq(struct netmap_adapter *na, unsigned int irq,
			     unsigned int irqtype, unsigned int ring_id)
{
	struct backend_info *be = (struct backend_info *) na->xen_be;
	struct xennmif *nmif;

	if (!be) {
		XD("no xen_be, not registerd");
		return -EINVAL;
	}

	nmif = be->nmif;
	if (!nmif) {
		XD("no nmif is registered");
		return -EINVAL;
	}

	return __xennet_manage_irq(irq, irqtype, nmif->if_id, ring_id, true);
}

static struct netmap_xennet_ops nm_xen_ops = {
	.map = nm_map_netmap,
	.unmap = nm_unmap_netmap,
	.bdg_attach = nm_bdg_attach,
	.bdg_detach = nm_bdg_detach,
	.bind_hwsw = nm_bind_hwsw,
	.unbind_hwsw = nm_unbind_hwsw,
	.expose_irq = xennet_expose_irq,
	.unexpose_irq = xennet_unexpose_irq,
	.map_i40e = nm_map_i40e,
	.map_i40e_ring = nm_map_i40e_ring,
	.unmap_i40e = nm_unmap_i40e,
};

static struct netmap_xennet_ops *saved_netmap_xen_ops;

static void xennet_set_netmap_ops(void)
{
	saved_netmap_xen_ops = netmap_xen_ops;
	netmap_xen_ops = &nm_xen_ops;
}

static void xennet_restore_netmap_ops(void)
{
	netmap_xen_ops = saved_netmap_xen_ops;
}

int xennet_init(void)
{
	xennet_set_netmap_ops();
	return 0;
};

void xennet_exit(void)
{
	xennet_restore_netmap_ops();

}
