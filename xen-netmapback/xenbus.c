/*
 *
 * Copyright (c) 2016-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Authors: Kenichi Yasukata
 *
 */

#include "common.h"
#include "xennet.h"

#include <linux/delay.h>

static struct list_head backend_info_list;
static struct list_head domain_info_list;
static spinlock_t be_list_lock;
static spinlock_t dom_list_lock;

int xenbus_info_init(void)
{
	spin_lock_init(&be_list_lock);
	spin_lock_init(&dom_list_lock);
	INIT_LIST_HEAD(&backend_info_list);
	INIT_LIST_HEAD(&domain_info_list);
	return 0;
}

static inline void backend_info_reg(struct backend_info *be, bool reg)
{
	spin_lock(&be_list_lock);
	if (reg)
		list_add(&be->head, &backend_info_list);
	else
		list_del(&be->head);
	spin_unlock(&be_list_lock);
}

struct backend_info *backend_info_get_by_name(char *name)
{
	struct backend_info *be = NULL;
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, &backend_info_list) {
		be = list_entry(pos, struct backend_info, head);
		if (strncmp(be->name, name, strlen(be->name)) == 0) {
			return be;
		}
	}

	return NULL;
}

static inline void domain_info_reg(struct domain_info *dom, bool reg)
{
	spin_lock(&dom_list_lock);
	if (reg)
		list_add(&dom->head, &domain_info_list);
	else
		list_del(&dom->head);
	spin_unlock(&dom_list_lock);
}

struct domain_info *domain_info_get_by_id(domid_t domid)
{
	struct domain_info *dom = NULL;
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, &domain_info_list) {
		dom = list_entry(pos, struct domain_info, head);
		if (dom->domid == domid)
			return dom;
	}

	return NULL;
}

struct domain_info *alloc_domain_info(domid_t domid)
{
	struct domain_info *di;

	di = domain_info_get_by_id(domid);
	if (di) {
		D("domain info already exists");
		atomic_inc(&di->refcnt);
		return di;
	}

	di = kzalloc(sizeof(struct domain_info), GFP_KERNEL);
	if (!di) {
		XD("failed to alloc domain_info");
		return NULL;
	}

	di->domid = domid;
	di->nm_mem = NULL;
	atomic_set(&di->refcnt, 1);
	domain_info_reg(di, true);

	return di;
}

void dealloc_domain_info(struct domain_info *di)
{
	int ref;

	ref = atomic_dec_return(&di->refcnt);
	if (ref > 0)
		return;

	domain_info_reg(di, false);
	di->nm_mem = NULL;
	kfree(di);
}

static void connect(struct backend_info *be)
{
	struct xenbus_device *dev = be->dev;
	struct xennmif *nmif = be->nmif;
	int err, i;
	char *xspath;
	size_t xspathsize;
	const size_t xenstore_path_ext_size = 10; /* sufficient for "/ring-NNN" */

	xspath = kzalloc(strlen(dev->otherend) + xenstore_path_ext_size, GFP_KERNEL);
	if (!xspath) {
		xenbus_dev_fatal(dev, -ENOMEM,
				 "reading ring references");
		goto out;
	}

	for (i = 0; i < nmif->num_rings; i++) {
		struct netmap_ring_info *ring_info = &nmif->ring_info[i];

		xspathsize = strlen(dev->otherend) + xenstore_path_ext_size;
		snprintf(xspath, xspathsize, "%s/ring-%u", dev->otherend, ring_info->id);

		err = xenbus_gather(XBT_NIL, xspath,
				    "event-channel-tx", "%u", &ring_info->tx_evtchn,
				    "event-channel-rx", "%u", &ring_info->rx_evtchn, NULL);
		if (err < 0) {
			XD("ring path : %s", xspath);
			err = xenbus_scanf(XBT_NIL, xspath,
					   "event-channel", "%u", &ring_info->tx_evtchn);
			if (err < 0) {
				XD("fail: read event channel tx rx");
				xenbus_dev_fatal(dev, err,
						 "reading %s/event-channel(-tx/rx)",
						 xspath);
				goto err;
			}
			XD("Get Event Channel");
			ring_info->rx_evtchn = ring_info->tx_evtchn;
		}
	}

	err = xennmif_connect(be);
	if (err) {
		XD("fail: connect");
		xenbus_dev_fatal(dev, err, "fail xennmif connect");
		goto err;
	}

	xennet_set_kring_evtchn(be);

	XD("connect done");
err:
	kfree(xspath);
out:
	return;
}

static void backend_disconnect(struct backend_info *be)
{
	if (be->nmif) {
		//xen_unregister_watchers(be->nmif);
		xennet_unset_kring_evtchn(be);
		xennmif_disconnect(be->nmif);
	}
}

static void backend_connect(struct backend_info *be)
{
	XD("try connect");
	if (be->nmif)
		connect(be);
}

/* Copied from netback at linux-4.6.2 */
static inline void backend_switch_state(struct backend_info *be,
					enum xenbus_state state)
{
	struct xenbus_device *dev = be->dev;

	XD("%s -> %s", dev->nodename, xenbus_strstate(state));
	be->state = state;

	/* If we are waiting for a hotplug script then defer the
	 * actual xenbus state change.
	 */
	//if (!be->have_hotplug_status_watch)
		xenbus_switch_state(dev, state);
}

/* Copied from netback at linux-4.6.2 */
static void set_backend_state(struct backend_info *be,
			      enum xenbus_state state)
{
	XD("%s -> %s", be->dev->nodename, xenbus_strstate(state));
	while (be->state != state) {
		switch (be->state) {
		case XenbusStateClosed:
			switch (state) {
			case XenbusStateInitWait:
			case XenbusStateConnected:
				backend_switch_state(be, XenbusStateInitWait);
				break;
			case XenbusStateClosing:
				backend_switch_state(be, XenbusStateClosing);
				break;
			default:
				BUG();
			}
			break;
		case XenbusStateInitWait:
			switch (state) {
			case XenbusStateConnected:
				backend_connect(be);
				backend_switch_state(be, XenbusStateConnected);
				break;
			case XenbusStateClosing:
			case XenbusStateClosed:
				backend_switch_state(be, XenbusStateClosing);
				break;
			default:
				BUG();
			}
			break;
		case XenbusStateConnected:
			switch (state) {
			case XenbusStateInitWait:
			case XenbusStateClosing:
			case XenbusStateClosed:
				backend_disconnect(be);
				backend_switch_state(be, XenbusStateClosing);
				break;
			default:
				BUG();
			}
			break;
		case XenbusStateClosing:
			switch (state) {
			case XenbusStateInitWait:
			case XenbusStateConnected:
			case XenbusStateClosed:
				backend_switch_state(be, XenbusStateClosed);
				break;
			default:
				BUG();
			}
			break;
		default:
			BUG();
		}
	}
}

static int netmapback_remove(struct xenbus_device *dev)
{
	struct backend_info *be = dev_get_drvdata(&dev->dev);
	int is_vale = is_valeif(be);

	set_backend_state(be, XenbusStateClosed);

	if (!be->nmif) {
		goto iffree_done;
	}
	kobject_uevent(&dev->dev.kobj, KOBJ_OFFLINE);
	if (is_vale) {
		if (detach_xennet_bdg(be) < 0) {
			XD("failed to detach if");
		}
		if (unmap_xennet_nmifobj(be) < 0) {
			XD("failed to unmap xennet kring");
		}
		if (unmap_xennet_kringobj(be) < 0) {
			XD("failed to unmap xennet kring");
		}
		if (unmap_xennet_kring(be) < 0) {
			XD("failed to unmap xennet kring");
		}
		if (unmap_xennet_netmap(be) < 0) {
			XD("failed to unmap xennet");
		}
		ungrant_netmap(be);
		xennmif_free(be->nmif);
		be->nmif = NULL;
	} else {
		if (unmap_xennet_nmifobj(be) < 0) {
			XD("failed to unmap xennet kring");
		}
		if (unmap_xennet_kringobj(be) < 0) {
			XD("failed to unmap xennet kring");
		}
		if (unmap_xennet_kring(be) < 0) {
			XD("failed to unmap xennet kring");
		}
		ungrant_netmap(be);
		xennmif_free(be->nmif);
		if (unmap_xennet_netmap(be) < 0) {
			XD("failed to unmap xennet");
		}
		be->nmif = NULL;
	}
iffree_done:
	backend_info_reg(be, false);
	kfree(be->hotplug_script);
	kfree(be);
	dev_set_drvdata(&dev->dev, NULL);
	XD("exit");
	return 0;
}

static int backend_create_xennmif(struct backend_info *be)
{
	int err = 0;
	long handle;
	struct xenbus_device *dev = be->dev;
	struct xennmif *nmif;

	if (be->nmif != NULL)
		return 0;

	err = xenbus_scanf(XBT_NIL, dev->nodename, "handle", "%li", &handle);
	if (err != 1) {
		xenbus_dev_fatal(dev, err, "reading handle");
		return (err < 0) ? err : -EINVAL;
	}

	nmif = xennmif_alloc(be, dev->otherend_id, handle);
	if (IS_ERR(nmif)) {
		err = PTR_ERR(nmif);
		xenbus_dev_fatal(dev, err, "creating interface");
		return err;
	}

	if ((err = grant_netmap(be)) < 0) {
		XD("Failed to map netmap");
		goto out1;
	}

	if (!is_valeif(be)) {
		XD("HW should be already registered");
		goto done;
	}

	if ((err = map_xennet_netmap(be)) < 0) {
		XD("failed to map xennet");
		goto out2;
	}

	if ((err = map_xennet_kring(be)) < 0) {
		XD("failed to map xennet");
		goto out3;
	}

	if ((err = map_xennet_kringobj(be)) < 0) {
		XD("failed to map xennet");
		goto out4;
	}

	if ((err = map_xennet_nmifobj(be)) < 0) {
		XD("failed to map xennet");
		goto out5;
	}
done:
	kobject_uevent(&dev->dev.kobj, KOBJ_ONLINE);

	return 0;
out5:
	if (unmap_xennet_kringobj(be) < 0) {
		XD("failed to unmap xennet kringobj");
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
	ungrant_netmap(be);
out1:
	xennmif_free(be->nmif);
	be->nmif = NULL;

	return err;
}

static int netmapback_probe(struct xenbus_device *dev,
			    const struct xenbus_device_id *id)
{
	int err;
	struct xenbus_transaction xbt;
	const char *script, *bridge;
	struct backend_info *be = kzalloc(sizeof(struct backend_info),
					  GFP_KERNEL);
	XD("New backend info %p", be);

	if (!be) {
		xenbus_dev_fatal(dev, -ENOMEM,
				 "allocating backend structure");
		return -ENOMEM;
	}

	backend_info_reg(be, true);

	be->dev = dev;
	dev_set_drvdata(&dev->dev, be);

	do {
		err = xenbus_transaction_start(&xbt);
		if (err) {
			xenbus_dev_fatal(dev, err, "starting transaction");
			goto fail;
		}
		err = xenbus_transaction_end(xbt, 0);
	} while (err == -EAGAIN);

	if (err) {
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto fail;
	}

	bridge = xenbus_read(XBT_NIL, dev->nodename, "bridge", NULL);
	if (IS_ERR(bridge)) {
		err = PTR_ERR(bridge);
		xenbus_dev_fatal(dev, err, "reading bridge");
		goto fail;
	}
	XD("Bridge %s", bridge);
	be->bridge = bridge;

	script = xenbus_read(XBT_NIL, dev->nodename, "script", NULL);
	if (IS_ERR(script)) {
		err = PTR_ERR(script);
		xenbus_dev_fatal(dev, err, "reading script");
		goto fail;
	}
	XD("hotplug_script %s", script);
	be->hotplug_script = script;

	err = xenbus_switch_state(dev, XenbusStateInitWait);
	if (err)
		goto fail;

	be->state = XenbusStateInitWait;

	bzero(be->name, sizeof(be->name));
	if (is_valeif(be)) {
		if (!validate_valeif_name(be)) {
			XD("VALE interface name is not complete %s", be->bridge);
			goto fail;
		}
		strncpy(be->name, be->bridge, (size_t)IFNAMSIZ);
		XD("VALE interface %s", be->name);
	} else {
		struct ifnet *ifp;
		ifp = ifunit_ref(be->bridge);
		strncpy(be->name, ifp->if_xname, (size_t)IFNAMSIZ);
		if_rele(ifp);
		XD("HW interface %s", be->name);
	}

	err = backend_create_xennmif(be);
	if (err)
		goto fail;

	XD("nmif is created successfully");
	return 0;

fail:
	pr_debug("failed\n");
	netmapback_remove(dev);
	return err;
}

static int netmapback_uevent(struct xenbus_device *xdev,
			     struct kobj_uevent_env *env)
{
	struct backend_info *be = dev_get_drvdata(&xdev->dev);

	if (!be)
		return 0;

	if(add_uevent_var(env, "script=%s", be->hotplug_script))
		return -ENOMEM;

	if (!be->nmif)
		return 0;
	//XD("return uevent var %s", nmif_get_ifname(be->nmif));
	return add_uevent_var(env, "nmif=%s", nmif_get_ifname(be->nmif));
}

/* Copied from netback at linux-4.6.2 */
static void frontend_changed(struct xenbus_device *dev,
			     enum xenbus_state frontend_state)
{
	struct backend_info *be = dev_get_drvdata(&dev->dev);

	XD("%s -> %s", dev->otherend, xenbus_strstate(frontend_state));

	be->frontend_state = frontend_state;

	switch (frontend_state) {
	case XenbusStateInitialising:
		set_backend_state(be, XenbusStateInitWait);
		break;

	case XenbusStateInitialised:
		break;

	case XenbusStateConnected:
		set_backend_state(be, XenbusStateConnected);
		break;

	case XenbusStateClosing:
		set_backend_state(be, XenbusStateClosing);
		break;

	case XenbusStateClosed:
		set_backend_state(be, XenbusStateClosed);
		if (xenbus_dev_is_online(dev))
			break;
		/* fall through if not online */
	case XenbusStateUnknown:
		set_backend_state(be, XenbusStateClosed);
		device_unregister(&dev->dev);
		break;

	default:
		xenbus_dev_fatal(dev, -EINVAL, "saw state %d at frontend",
				 frontend_state);
		break;
	}
}

static const struct xenbus_device_id netmapback_ids[] = {
	{ "nmif" },
	{ "" }
};

static struct xenbus_driver netmapback_driver = {
	.ids = netmapback_ids,
	.probe = netmapback_probe,
	.remove = netmapback_remove,
	.uevent = netmapback_uevent,
	.otherend_changed = frontend_changed,
};

int xennmif_xenbus_init(void)
{
	XD("INIT max grants %d", gnttab_max_grant_frames());
	return xenbus_register_backend(&netmapback_driver);
}

void xennmif_xenbus_fini(void)
{
	XD("FINI");
	return xenbus_unregister_driver(&netmapback_driver);
}
