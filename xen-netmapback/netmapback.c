/*
 *
 * Copyright (c) 2016-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Authors: Kenichi Yasukata
 *
 */

#include "common.h"

int num_nmbk_rings;
int num_nmbk_slots;
int num_nmbk_extra_slots;
int xen_drvtx;

SYSBEGIN(nmbk_init);

SYSCTL_DECL(_dev_netmapback);
SYSCTL_NODE(_dev, OID_AUTO, netmapback, CTLFLAG_RW, 0, "Netmapback args");
SYSCTL_INT(_dev_netmapback, OID_AUTO, num_nmbk_rings, CTLFLAG_RW, &num_nmbk_rings, 0 , "");
SYSCTL_INT(_dev_netmapback, OID_AUTO, num_nmbk_slots, CTLFLAG_RW, &num_nmbk_slots, 0 , "");
SYSCTL_INT(_dev_netmapback, OID_AUTO, num_nmbk_extra_slots, CTLFLAG_RW, &num_nmbk_extra_slots, 0 , "");
SYSCTL_INT(_dev_netmapback, OID_AUTO, xen_drvtx, CTLFLAG_RW, &xen_drvtx, 0 , "");

SYSEND;

int invalid_ring_slot(void)
{
	if (num_nmbk_rings < 0 || num_nmbk_rings > 4) {
		XD("Invalid ring num %d", num_nmbk_rings);
		return -1;
	}

	if (num_nmbk_slots < 0 || num_nmbk_slots > 4096) {
		XD("Invalid slot num %d", num_nmbk_slots);
		return -1;
	}

	return 0;
}

/* grant operations for netmap */

void ungrant_netmap(struct backend_info *be)
{
	int i;
	struct xennmif *nmif = be->nmif;

	if (!be || !nmif) {
		XD("no backend or nmif");
		return;
	}

	/* Here it forces to release grants */
	if (nmif->gref_info) {
		for (i = 0; i < nmif->gref_info->num_grefs; i++) {
			if (nmif->gref_info->grefs[i] == -1)
				continue;
			if (!gnttab_end_foreign_access_ref(nmif->gref_info->grefs[i], 0)) {
				 gnttab_free_grant_reference(nmif->gref_info->grefs[i]);
			}
		}
	} else
		XD("no gref_info, skip");

	if (nmif->gi_refs) {
		for (i = 0; i < nmif->gref_info->num_gi_pages; i++) {
			if (nmif->gref_info->grefs[i] == -1)
				continue;
			if (!gnttab_end_foreign_access_ref(nmif->gi_refs[i], 0)) {
				 gnttab_free_grant_reference(nmif->gi_refs[i]);
			}
		}
	} else
		XD("no gi_refs, skip");

	/* This is ugly, but how should we wait? */
	XD("Sleep %u ms for waiting Xen's grant unmap", XEN_GRANT_DESTROY_WAIT_MS);
	msleep(XEN_GRANT_DESTROY_WAIT_MS);

	if (be->nmif->gi_refs) {
		kfree(be->nmif->gi_refs);
		be->nmif->gi_refs = NULL;
	}

	if (be->nmif->gref_info) {
		free_pages_exact(be->nmif->gref_info, be->nmif->gref_info_size);
		be->nmif->gref_info = NULL;
	}
}

static int __grant_netmap(struct xenbus_device *dev,
			  struct netmap_adapter *na,
			  unsigned int num_grefs,
			  grant_ref_t *grefs)
{
	int err;
	int i, j;
	unsigned long pa, pfn, off = 0;

	XD("try to grant %u", num_grefs);

	for (i = 0; i < num_grefs; i++) {
		pa = netmap_mem_ofstophys(na->nm_mem, off);
		if (pa == 0) {
			XD("Bad address");
			err = -EINVAL;
			goto fail;
		}
		pfn = pa >> PAGE_SHIFT;
		if (!pfn_valid(pfn)) {
			XD("Bad pfn");
			err = -EINVAL;
			goto fail;
		}

		err = gnttab_grant_foreign_access(dev->otherend_id,
						  pfn_to_gfn(pfn), 0);
		if (err < 0) {
			xenbus_dev_fatal(dev, err,
					 "granting access to ring page");
			XD("grant access fail");
			goto fail;
		}
		grefs[i] = err;

		off += PAGE_SIZE;
	}

	return 0;
fail:
	for (j = 0; j < i; j++) {
		gnttab_end_foreign_access_ref(grefs[j], 0);
		grefs[i] = -1;
	}
	return err;
}

int alloc_grant_info(struct xennmif *nmif)
{
	int error = 0;
	unsigned int num_pages;
	u_int memsize, memflags;
	struct netmap_adapter *na = nmif->priv->np_na;

	error = netmap_mem_get_info(na->nm_mem, &memsize, &memflags, NULL);
	if (error) {
		XD("netmap_mem_get_info failed");
		goto fail;
	}

	num_pages = memsize / PAGE_SIZE;
	nmif->gref_info_size = sizeof(struct grant_info) + (sizeof(grant_ref_t) * num_pages);

	nmif->gref_info = (struct grant_info *) alloc_pages_exact(nmif->gref_info_size,
							GFP_KERNEL | __GFP_ZERO);
	if (!nmif->gref_info) {
		error = -ENOMEM;
		XD("failed alloc gref info");
		goto fail;
	}

	nmif->na = na;
	nmif->gref_info->num_grefs = num_pages;
	nmif->gref_info->num_gi_pages = (nmif->gref_info_size / PAGE_SIZE) + 1;
fail:
	return error;
}

int grant_netmap(struct backend_info *be)
{
	int error = 0, i;
	const char *message;
	struct xenbus_transaction xbt;
	struct xennmif *nmif =  be->nmif;
	struct xenbus_device *dev = be->dev;
	struct netmap_adapter *na = nmif->priv->np_na;
	struct netmap_if *nifp = nmif->priv->np_nifp;
	char gref_info_str[32];

	if (!nmif->gref_info) {
		error = alloc_grant_info(nmif);
		if (error) {
			XD("grant info alloc failed");
			goto fail;
		}
		nmif->gref_info->if_id = nmif->if_id = INVALID_IF_ID;
		nmif->gref_info->type = BT_SP;
	} else {
		XD("HW already has grant_info");
	}

	nmif->gref_info->nr_offset = netmap_mem_if_offset(na->nm_mem, nifp);
	nmif->gref_info->dom0_nm_mem = na->nm_mem;

	for (i = 0; i < nmif->gref_info->num_grefs; i++) {
		nmif->gref_info->grefs[i] = -1;
	}

	nmif->gi_refs = (grant_ref_t *) kzalloc(sizeof(grant_ref_t) * nmif->gref_info->num_gi_pages,
						GFP_KERNEL);
	if (!nmif->gi_refs) {
		error = -ENOMEM;
		XD("failed alloc gi_refs");
		goto fail_alloc_gi_refs;
	}

	for (i = 0; i < nmif->gref_info->num_gi_pages; i++) {
		nmif->gi_refs[i] = -1;
	}

	error = xenbus_grant_ring(dev, nmif->gref_info,
			nmif->gref_info->num_gi_pages, nmif->gi_refs);
	if (error) {
		XD("fail map info pages");
		goto fail_map_info;
	}

	error = __grant_netmap(dev, na, nmif->gref_info->num_grefs, nmif->gref_info->grefs);
	if (error) {
		XD("fail map netmap");
		goto fail_map_nm;
	}

	do {
		error = xenbus_transaction_start(&xbt);
		if (error) {
			xenbus_dev_fatal(dev, error, "starting transaction");
			goto fail_transaction;
		}

		error = xenbus_printf(xbt, dev->nodename, "gref-info-pages",
					"%u", nmif->gref_info->num_gi_pages);
		if (error) {
			message = "writing gref-info-pages";
			goto abort_transaction;
		}

		for (i = 0; i < nmif->gref_info->num_gi_pages; i++) {
			snprintf(gref_info_str, sizeof(gref_info_str), "gref-info-%d", i);
			error = xenbus_printf(xbt, dev->nodename, gref_info_str,
					"%u", nmif->gi_refs[i]);
			if (error) {
				message = "writing gref-info";
				goto abort_transaction;
			}
		}

		error = xenbus_transaction_end(xbt, 0);
	} while (error == -EAGAIN);

	if (error) {
		xenbus_dev_fatal(dev, error, "completing transaction");
		goto fail_transaction;
	}

	return error;

abort_transaction:
	xenbus_transaction_end(xbt, 1);
	xenbus_dev_fatal(dev, error, "%s", message);
fail_transaction:
	for (i = 0; i < nmif->gref_info->num_grefs; i++) {
		gnttab_end_foreign_access(nmif->gref_info->grefs[i], 0, 0);
		nmif->gref_info->grefs[i] = -1;
	}
fail_map_nm:
	for (i = 0; i < nmif->gref_info->num_gi_pages; i++) {
		gnttab_end_foreign_access(nmif->gi_refs[i], 0, 0);
		nmif->gi_refs[i] = -1;
	}
fail_map_info:
	kfree(be->nmif->gi_refs);
	be->nmif->gi_refs = NULL;
fail_alloc_gi_refs:
	free_pages_exact(be->nmif->gref_info, be->nmif->gref_info_size);
	be->nmif->gref_info = NULL;
fail:
	return error;
}


irqreturn_t xennmif_interrupt(int irq, void *dev_id)
{
	return IRQ_HANDLED;
}

static int xennmif_nm_notify(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na;
	struct xennmif *nmif;
	struct netmap_ring_info *ring_info;
	enum txrx tx = kring->tx;
	uint32_t ring_id = kring->ring_id;

	na = kring->na;
	if (unlikely(!na)) {
		XD("no na");
		return NM_IRQ_COMPLETED;
	}

	nmif = NA_TO_NMIF(na);
	if (unlikely(!nmif)) {
		XD("no nmif");
		return NM_IRQ_COMPLETED;
	}

	ring_info = &nmif->ring_info[ring_id];
	if (unlikely(!ring_info)) {
		XD("no ring_info");
		return NM_IRQ_COMPLETED;
	}

	if (tx == NR_RX) {
		if (likely(ring_info->rx_irq && irq_get_handler_data(ring_info->rx_irq)))
			notify_remote_via_irq(ring_info->rx_irq);
	} else if (tx == NR_TX) {
		notify_remote_via_irq(ring_info->tx_irq);
	}

	return NM_IRQ_COMPLETED;
}


/* dom0 space netmap management */

static struct netmap_ring_info *create_netmap_ring_info(struct xennmif *nmif, int num_rings)
{
	int err, i;
	struct netmap_ring_info *ring_info;

	ring_info = kzalloc(sizeof(struct netmap_ring_info) * num_rings,
				  GFP_KERNEL);
	if (!ring_info) {
		XD("Failed to allocate ring info");
		err = -ENOMEM;
	}

	for (i = 0; i < num_rings; i++) {
		ring_info[i].id = i;
		ring_info[i].nmif = nmif;
		snprintf(ring_info[i].name, sizeof(ring_info[i].name), "netmap-%u", ring_info[i].id);
	}

	return ring_info;
}

static void xennmif_destroy_ring_info(struct xennmif *nmif)
{
	if (nmif->ring_info)
		kfree(nmif->ring_info);
}

void xennmif_unset_netmap(struct xennmif *nmif)
{
	if (nmif->dom_info) {
		dealloc_domain_info(nmif->dom_info);
		nmif->dom_info = NULL;
	}
	xennmif_destroy_ring_info(nmif);

	if (nmif->priv) {
		NA_NMIF(nmif->priv->np_na) = NULL;
		netmap_dtor(nmif->priv);
		nmif->priv = NULL;
		XD("netmap is freed");
	}
}

static void setup_xennmif_notify(struct netmap_adapter *na)
{
	int i;

	for (i = 0; i < na->num_rx_rings; i++) {
		na->rx_rings[i].nm_notify = xennmif_nm_notify;
		na->tx_rings[i].nm_notify = xennmif_nm_notify;
	}
}

int xennmif_set_netmap(struct xennmif *nmif, domid_t domid)
{
	int ret = 0;
	uint32_t nr_ringid = 0, nr_flags = NR_REG_ONE_NIC;

	if (invalid_ring_slot())
		return -EFAULT;

	nmif->dom_info = alloc_domain_info(domid);
	if (nmif->dom_info->nm_mem == NULL) {
		char name[64];
		int error;
		snprintf(name, sizeof(name), "memdom%u", domid);
		/* nm_mem will be deleted by netmap */
		nmif->dom_info->nm_mem = netmap_mem_private_shared_new(
								name,
								PRIV_TX_RINGS,
								PRIV_TX_SLOTS,
								PRIV_RX_RINGS,
								PRIV_RX_SLOTS,
								PRIV_EXTRA_BUFS,
								PRIV_NPIPES,
								&error);
	}

	NMG_LOCK();
	nmif->priv = netmap_priv_new();
	if (nmif->priv == NULL) {
		ret = -ENOMEM;
		NMG_UNLOCK();
		goto fail;
	}
	NMG_UNLOCK();

	snprintf(nmif->nmr.nr_name, sizeof(nmif->nmr.nr_name), "%s",
			nmif->bridge);
	memcpy(nmif->nmr.nr_name, nmif->bridge, sizeof(nmif->nmr.nr_name));
	XD("Make interface %s", nmif->nmr.nr_name);
	nmif->nmr.nr_version = NETMAP_API;
	nmif->nmr.nr_ringid &= ~NETMAP_RING_MASK;
	nmif->nmr.nr_ringid = nr_ringid;
	nmif->nmr.nr_flags = nr_flags;
	nmif->nmr.nm_mem = nmif->dom_info->nm_mem;
	if (nmif->is_vp) {
		nmif->nmr.nr_arg3 = XENNMIF_NUM_EXTRA_SLOTS;
		nmif->nmr.nr_tx_rings = XENNMIF_NUM_TX_RINGS;
		nmif->nmr.nr_rx_rings = XENNMIF_NUM_RX_RINGS;
		nmif->nmr.nr_tx_slots = XENNMIF_NUM_TX_SLOTS;
		nmif->nmr.nr_rx_slots = XENNMIF_NUM_RX_SLOTS;
	} else {
		/* No request */
	}

	ret = netmap_ioctl(nmif->priv, NIOCREGIF, (caddr_t) &nmif->nmr, NULL);
	if (ret != 0) {
		XD("netmap_ioctl failed %d", ret);
		goto fail;
	}
	XD("netmap is allocated");
	XD("tx %d:%d, rx %d:%d, ifp : %p",
		nmif->nmr.nr_tx_rings,
		nmif->nmr.nr_tx_slots,
		nmif->nmr.nr_rx_rings,
		nmif->nmr.nr_rx_slots,
		NA_TO_NMIF(nmif->priv->np_na));

	if (NA_TO_NMIF(nmif->priv->np_na)) {
		/* FIXME:
		 *   We abuse na->ifp for a back-reference.
		 *   This might cause problems if netmap is
		 *   changed.
		 */
		XD("netmap adapter should not have ifp");
		goto fail;
	}
	NA_NMIF(nmif->priv->np_na) = (struct ifnet *) nmif;
	nmif->na = nmif->priv->np_na;

	if (nmif->nmr.nr_tx_rings != nmif->nmr.nr_rx_rings) {
		XD("TX/RX rings should be the same number");
		goto fail;
	}

	nmif->num_rings = nmif->nmr.nr_tx_rings;

	nmif->ring_info = create_netmap_ring_info(nmif, nmif->num_rings);
	if (nmif->ring_info < 0) {
		XD("ring info creation failed");
		ret = PTR_ERR(nmif->ring_info);
		goto fail;
	}

	setup_xennmif_notify(nmif->priv->np_na);

	return ret;

fail:
	xennmif_unset_netmap(nmif);
	return ret;
}



static int __init netmapback_init(void)
{
	int rc = 0;

	if (!xen_domain())
		return -ENODEV;

	num_nmbk_rings = 1;
	num_nmbk_slots = 1024;
	xen_drvtx = 1;

	xenbus_info_init();

	rc = xennmif_xenbus_init();
	if (rc)
		goto failed_init;

	xennet_init();

	return 0;

failed_init:
	return rc;
}
module_init(netmapback_init);

static void __exit netmapback_fini(void)
{
	xennet_exit();
	xennmif_xenbus_fini();
}
module_exit(netmapback_fini);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("xen-netmap-backend");
MODULE_AUTHOR("Kenichi Yasukata");
