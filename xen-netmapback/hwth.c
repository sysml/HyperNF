/*
 *
 * Copyright (c) 2016-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Authors: Kenichi Yasukata
 *
 */

#include "common.h"
#include "xennet.h"

irqreturn_t xennet_hwtx_handler(int irq, void *dev_id)
{
	struct netmap_kring *kring = (struct netmap_kring *) dev_id;
	wake_up(&kring->hwwq);
	return IRQ_HANDLED;
}

static inline bool xennmif_have_tx_work(struct netmap_kring *hw_kring)
{
	struct netmap_adapter *hwna = hw_kring->na;
	struct netmap_vp_adapter *vpna = hwna->na_vp;
	struct netmap_adapter *swna = &vpna->up;
	struct netmap_kring *kring = &swna->rx_rings[hw_kring->ring_id];
	if (xen_drvtx)
		return false;
	netmap_vp_rxsync(kring, 0);
	hw_kring->rhead = hw_kring->rcur = kring->nr_hwtail; // Moved from Hypervisor
	return (nm_prev(hw_kring->rhead, hw_kring->nkr_num_slots - 1) != hw_kring->nr_hwtail);
}

static int call_nm_sync(struct netmap_kring *hw_kring, volatile bool *trigger)
{
	struct netmap_adapter *hwna = hw_kring->na;
	struct netmap_vp_adapter *vpna = hwna->na_vp;
	struct netmap_adapter *swna = &vpna->up;
	struct netmap_kring *kring = &swna->rx_rings[hw_kring->ring_id];
	u_int lim = kring->nkr_num_slots - 1;
	int error;

	if (unlikely(nm_kr_tryget(hw_kring, 1, &error))) {
		XD("try get failed");
		error = (error ? EIO : 0);
		return -EBUSY;
	}

	if (likely(hw_kring->tx == NR_TX)) {
		hw_kring->nm_sync(hw_kring, NAF_FORCE_RECLAIM);
		kring->rhead = kring->rcur = nm_next(hw_kring->nr_hwtail, lim);
		netmap_vp_rxsync(kring, 0);
	} else {
		XD("This is weird, ring have to be for TX");
	}

	nm_kr_put(hw_kring);

	return 0;
}

static int xennmif_call_txsync(struct netmap_kring *kring)
{
	int error = 0;

	error = call_nm_sync(kring, NULL);

	if (unlikely(error)) {
		XD("fail nm sync");
		return error;
	}

	return 0;
}

static void xennmif_wait_for_work(struct netmap_kring *kring)
{
	DEFINE_WAIT(wait);

	if (xennmif_have_tx_work(kring)) {
		return;
	}

	for (;;) {
		long ret;

		prepare_to_wait(&kring->hwwq, &wait, TASK_INTERRUPTIBLE);
		if (xennmif_have_tx_work(kring)) {
			break;
		}
		ret = schedule_timeout(0);
		if (!ret)
			break;
		if (unlikely(kthread_should_stop()))
			break;
	}

	finish_wait(&kring->hwwq, &wait);
}

int xennmif_kthread_tx(void *data)
{
	struct netmap_kring *kring = (struct netmap_kring *) data;

	for (;;) {
		xennmif_wait_for_work(kring);

		if (unlikely(kthread_should_stop()))
			break;

		if (xennmif_have_tx_work(kring))
			xennmif_call_txsync(kring);

		cond_resched();
	}

	return 0;
}

static void __xennet_unbind_kring_evtchn_hw(struct netmap_kring *kring)
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

void xennet_unbind_kring_evtchn_hw(struct netmap_adapter *hwna)
{
	struct netmap_kring *kring;
	int i;

	for (i = 0; i < hwna->num_tx_rings; i++) {
		kring = &hwna->tx_rings[i];
		__xennet_unbind_kring_evtchn_hw(kring);
		if (kring->hwtsk) {
			kthread_stop(kring->hwtsk);
			put_task_struct(kring->hwtsk);
			kring->hwtsk = NULL;
		}
	}
}

static int __xennet_bind_kring_evtchn_hw(struct netmap_kring *kring)
{
	int err = 0;
	uint32_t evtchn = 0;
	char irq_name[128];


	if (kring->xen_irq2) {
		XD("irq2 has a value %u", kring->xen_irq2);
		return 0;
	}

	if (kring->evtchn_port) {
		XD("evtchn has a value %u", kring->evtchn_port);
		return 0;
	}

	err = xennet_alloc_evtchn(&evtchn);
	if (err < 0) {
		XD("failed to alloc evtchn");
		goto out;
	}

	snprintf(irq_name, sizeof(irq_name), "%s-dst", kring->name);
	err = bind_interdomain_evtchn_to_irqhandler(DOMID_SELF,
					evtchn,
					xennet_hwtx_handler,
					smp_processor_id(), irq_name, kring);
	kring->xen_irq2 = err;
	kring->evtchn_port = evtchn;

out:
	return err;
}

int xennet_bind_kring_evtchn_hw(struct netmap_adapter *hwna)
{
	struct netmap_kring *kring;
	char thname[64];
	int i, ret = 0;

	for (i = 0; i < hwna->num_tx_rings; i++) {
		kring = &hwna->tx_rings[i];
		snprintf(thname, sizeof(thname), "netmap-%s-%u", hwna->name, i);
		init_waitqueue_head(&kring->hwwq);
		kring->hwtsk = kthread_create(xennmif_kthread_tx,
					(void *) kring, thname);
		if (IS_ERR(kring->hwtsk)) {
			XD("Couldn't allocate kthread");
			ret = -EFAULT;
			goto err_out;
		}
		get_task_struct(kring->hwtsk);
		wake_up_process(kring->hwtsk);

		if ((ret = __xennet_bind_kring_evtchn_hw(kring)) < 0) {
			XD("Failed to bind kring evtchn %d", i);
			goto err_out;
		}
	}

	return ret;
err_out:
	xennet_unbind_kring_evtchn_hw(hwna);
	return ret;
}
