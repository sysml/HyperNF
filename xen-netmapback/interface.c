/*
 *
 * Copyright (c) 2016-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Authors: Kenichi Yasukata
 *
 */

#include "common.h"

static void __xennmif_disconnect(struct netmap_ring_info *ring_info)
{
	if (ring_info->tx_irq == ring_info->rx_irq) {
		if (ring_info->tx_irq)
			unbind_from_irqhandler(ring_info->tx_irq, ring_info);
	} else
		XD("tx/rx evtchans are different, this is not currently supported");
}

void xennmif_disconnect(struct xennmif *nmif)
{
	int i; 
	for (i = 0; i < nmif->num_rings; i++) {
		struct netmap_ring_info *ring_info = &nmif->ring_info[i];
		__xennmif_disconnect(ring_info);
	}
}

static int __xennmif_connect(struct netmap_ring_info *ring_info)
{
	int err;

	if (ring_info->tx_evtchn == ring_info->rx_evtchn) {
		err = bind_interdomain_evtchn_to_irqhandler(
			ring_info->nmif->domid, ring_info->tx_evtchn, xennmif_interrupt, 0,
			ring_info->name, ring_info);
		if (err < 0)
			goto err_out;
		ring_info->tx_irq = ring_info->rx_irq = err;
		//disable_irq(ring_info->tx_irq);
	} else {
		XD("tx/rx evtchans are different, this is not currently supported");
		err = -EINVAL;
		goto err_out;
	}

	return 0;
err_out:
	return err;
}

int xennmif_connect(struct backend_info *be)
{
	struct xennmif *nmif = be->nmif;
	int err, i;

	for (i = 0; i < nmif->num_rings; i++) {
		struct netmap_ring_info *ring_info = &nmif->ring_info[i];
		err = __xennmif_connect(ring_info);
		if (err) {
			XD("Failed to connect");
			goto err_out;
		}
	}

	return 0;
err_out:
	return err;
}

void xennmif_free(struct xennmif *nmif)
{
	if (nmif) {
		xennmif_unset_netmap(nmif);
		kfree(nmif);
	}
}

struct xennmif *xennmif_alloc(struct backend_info *be, domid_t domid,
			      unsigned int handle)
{
	int ret = 0;
	struct xennmif *nmif;

	nmif = kzalloc(sizeof(struct xennmif), GFP_KERNEL);
	if (!nmif) {
		ret = ENOMEM;
		goto fail;
	}

	be->nmif = nmif;
	nmif->domid = domid;
	nmif->bridge = be->bridge;
	nmif->is_vp = is_valeif(be);

	if ((ret = xennmif_set_netmap(nmif, domid)) != 0) {
		XD("failed to set netmap");
		goto fail;
	}

	return nmif;

fail:
	xennmif_free(nmif);
	return ERR_PTR(-ret);
}
