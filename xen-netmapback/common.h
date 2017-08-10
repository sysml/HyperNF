/*
 *
 * Copyright (c) 2016-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Authors: Kenichi Yasukata
 *
 */

#ifndef __XEN_NETMAPBACK__COMMON_H__
#define __XEN_NETMAPBACK__COMMON_H__

#include <linux/module.h>
#include <linux/netdevice.h>

#include <linux/kthread.h>

#include <bsd_glue.h>

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>
#include <dev/netmap/netmap_virt.h>

#include <xen/xenbus.h>
#include <xen/grant_table.h>
#include <xen/events.h>

#include <xen/xen.h>

#define NA_NMIF(na) ((na)->ifp2)
#define NA_TO_NMIF(na) ((struct xennmif *)((na)->ifp2))

#define XD(fmt, ...) \
	printk(KERN_INFO "[%s]: "fmt"\n", __func__, ##__VA_ARGS__);

/* Queue name is interface name with "-qNNN" appended */
#define QUEUE_NAME_SIZE (IFNAMSIZ + 5)

#define MAX_RING_REINIT 3

extern int num_nmbk_rings;
extern int num_nmbk_slots;
extern int xen_drvtx;

#define XENNMIF_NUM_TX_RINGS (num_nmbk_rings)
#define XENNMIF_NUM_RX_RINGS XENNMIF_NUM_TX_RINGS
#define XENNMIF_NUM_TX_SLOTS (num_nmbk_slots)
#define XENNMIF_NUM_RX_SLOTS XENNMIF_NUM_TX_SLOTS
#define XENNMIF_NUM_EXTRA_SLOTS (num_nmbk_extra_slots)

#define PRIV_TX_RINGS (2*(XENNMIF_NUM_TX_RINGS+1))
#define PRIV_RX_RINGS (PRIV_TX_RINGS)
#define PRIV_TX_SLOTS (2*XENNMIF_NUM_TX_SLOTS)
#define PRIV_RX_SLOTS (PRIV_TX_SLOTS)
#define PRIV_EXTRA_BUFS (0)
#define PRIV_NPIPES (0)

#define XEN_GRANT_DESTROY_WAIT_MS (1000)

#define BT_SP 2
#define BT_COS 4

#define INVALID_IF_ID (-1)

struct xennmif;

/* This object is shared between front and back */
struct grant_info {
	uint16_t num_gi_pages;
	uint16_t num_grefs;
	uint32_t nr_offset;
	uint16_t if_id;
	uint16_t type;
	void *dom0_nm_mem;
	grant_ref_t grefs[0];
};

struct netmap_ring_info {
	int id;
	char name[QUEUE_NAME_SIZE];
	unsigned int tx_evtchn, rx_evtchn;
	int tx_irq, rx_irq;
	struct xennmif *nmif;
	wait_queue_head_t wq;
};

struct domain_info {
	domid_t domid;
	struct list_head head;
	struct netmap_mem_d *nm_mem;
	atomic_t refcnt;
};

struct xennmif {
	domid_t domid;
	struct domain_info *dom_info;

	struct net_device *dev;
	struct netmap_adapter *na;

	struct ifnet *ifp;
	struct nmreq nmr;
	struct netmap_priv_d *priv;

	const char *bridge;

	unsigned int num_rings;
	struct netmap_ring_info *ring_info;

	struct grant_info *gref_info;
	grant_ref_t *gi_refs;
	size_t gref_info_size;

	uint16_t if_id;

	uint16_t is_vp;
};

struct backend_info {
	struct xenbus_device *dev;
	struct xennmif *nmif;
	enum xenbus_state state;
	enum xenbus_state frontend_state;
	const char *bridge;
	const char *hotplug_script;
	struct list_head head;
	char name[IFNAMSIZ];
};

int xennmif_xenbus_init(void);
void xennmif_xenbus_fini(void);

int grant_netmap(struct backend_info *be);
void ungrant_netmap(struct backend_info *be);

void xennmif_disconnect(struct xennmif *nmif);
int xennmif_connect(struct backend_info *be);

struct xennmif *xennmif_alloc(struct backend_info *be, domid_t domid, unsigned int handle);
void xennmif_free(struct xennmif *nmif);

irqreturn_t xennmif_interrupt(int irq, void *dev_id);

int xennmif_set_netmap(struct xennmif *nmif, domid_t domid);
void xennmif_unset_netmap(struct xennmif *nmif);

int xenbus_info_init(void);
struct backend_info *backend_info_get_by_name(char *name);

int alloc_grant_info(struct xennmif *nmif);

struct domain_info *alloc_domain_info(domid_t domid);
void dealloc_domain_info(struct domain_info *di);

int xennet_alloc_evtchn(int *port);
int xennet_free_evtchn(int port);

void xennet_unbind_kring_evtchn_hw(struct netmap_adapter *hwna);
int xennet_bind_kring_evtchn_hw(struct netmap_adapter *hwna);

int xennet_init(void);
void xennet_exit(void);


static inline char *nmif_get_ifname(struct xennmif *nmif)
{
	char *nr_name = nmif->nmr.nr_name;
	char vale_base[] = "vale\0";
	int i;

	if (!nr_name) {
		XD("nr_name is not set");
		return NULL;
	}

	if (strncmp(vale_base, nr_name, 4)) {
		//XD("This is not vale interface %s", nr_name);
		return nr_name;
	}

	for (i = 0; i < strlen(nr_name); i++) {
		if ((*(char *)(nr_name + i)) == ':')
			return ((char *)(nr_name + i + 1));
	}

	return NULL;
}

static inline int validate_valeif_name(struct backend_info *be)
{
	const char *nr_name = be->bridge;
	char *ret;
	if ((ret = strchr(nr_name, ':')) == NULL) {
		return 0;
	}
	return 1;
}

static inline int is_valeif(struct backend_info *be)
{
	const char *nr_name = be->bridge;
	char vale_base[] = "vale\0";

	if (!nr_name) {
		return 0;
	}

	if (strncmp(vale_base, nr_name, 4)) {
		return 0;
	}

	return 1;
}

#endif
