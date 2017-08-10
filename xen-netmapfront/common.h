/*
 *
 * Copyright (c) 2016-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Authors: Kenichi Yasukata
 *
 */

#ifndef _XEN_NETMAPFRONT_COMMON_H
#define _XEN_NETMAPFRONT_COMMON_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <net/tcp.h>
#include <linux/udp.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <net/ip.h>
#include <linux/vmalloc.h>

#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>

#include <xen/xen.h>
#include <xen/xenbus.h>
#include <xen/events.h>
#include <xen/page.h>
#include <xen/platform_pci.h>
#include <xen/grant_table.h>
#include <xen/xen-ops.h>
#include <xen/privcmd.h>
#include <xen/balloon.h>

#include <xen/interface/io/netif.h>
#include <xen/interface/memory.h>
#include <xen/interface/grant_table.h>

#include "bsd_glue.h"

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>
#include "netmap_linux_config.h"

#define XEN_NETMAPIF_MAX_TX_SIZE (ETH_FRAME_LEN)
#define MAX_XEN_SKB_FRAGS (65536 / ETH_DATA_LEN + 1)

/* helper macro */
#define _NETMAP_OFFSET(type, ptr, offset) \
	((type)(void *)((char *)(ptr) + (offset)))

#define NETMAP_IF(_base, _ofs)  _NETMAP_OFFSET(struct netmap_if *, _base, _ofs)

#define NETMAP_TXRING(nifp, index) _NETMAP_OFFSET(struct netmap_ring *, \
	nifp, (nifp)->ring_ofs[index] )

#define NETMAP_RXRING(nifp, index) _NETMAP_OFFSET(struct netmap_ring *, \
	nifp, (nifp)->ring_ofs[index + (nifp)->ni_tx_rings + 1] )

#define NETMAP_BUF(ring, index)			 \
	((char *)(ring) + (ring)->buf_ofs + ((index)*(ring)->nr_buf_size))

#define NETMAP_BUF_IDX(ring, buf)		       \
	( ((char *)(buf) - ((char *)(ring) + (ring)->buf_ofs) ) / \
		(ring)->nr_buf_size )

#define XD(fmt, ...) \
	printk(KERN_INFO "[%s]: "fmt"\n", __func__, ##__VA_ARGS__);

#define XENBUS_MAX_NETMAP_GRANTS (44000)

#define XENBUS_PAGES(_grants)	(DIV_ROUND_UP(_grants, XEN_PFN_PER_PAGE))

#define XENBUS_MAX_NETMAP_PAGES	(XENBUS_PAGES(XENBUS_MAX_NETMAP_GRANTS))


#define xennet_op 41

#define XENNET_ok  0
#define XENNET_bad_domain 1

#define XENNETOP_none 0
#define XENNETOP_sync 3
#define XENNETOP_pktgen 6

#define XENNETOP_MEM_map 1
#define XENNETOP_MEM_unmap 2

#define XENNET_MAX_IF 4

#define XENNETOP_PKTGEN_SETDATA 1
#define XENNETOP_PKTGEN_TX 2



struct netmapfront_info;

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
	uint16_t if_id;
	uint16_t type;
	struct xenbus_device *xbdev;
	struct netmapfront_info *info;
	struct netmap_ring *tx_ring, *rx_ring;
	unsigned int tx_evtchn, rx_evtchn;
	unsigned int tx_irq, rx_irq;
	struct napi_struct napi;
	spinlock_t tx_lock;
	spinlock_t rx_lock ____cacheline_aligned_in_smp;
	NM_SELINFO_T si[NR_TXRX];	/* global wait queues */
};

struct netmapfront_info {
	struct list_head head;
	struct net_device *netdev;

	struct xenbus_device *xbdev;

	int master;
	void *nm_mem;
	unsigned long nr_memsize;
	struct grant_info *gi;
	unsigned int gref_info_pages;
	struct netmap_if *nifp;

	unsigned int num_rings;
	struct netmap_ring_info *ring_info;
	unsigned long pages_vm_start;
	int otherend_id;

	int np_txpoll;

	atomic_t nm_refs;
	uint16_t nm_mode;
	spinlock_t nm_lock;

	struct netmapfront_stats __percpu *rx_stats;
	struct netmapfront_stats __percpu *tx_stats;

	atomic_t rx_gso_checksum_fixup;
};

long __privcmd_hypercall(struct privcmd_hypercall *hypercall);

long kick_backend(struct netmap_ring_info *ring_info, enum txrx tx);

void nm_ref_get(struct netmapfront_info *info);
void nm_ref_put(struct netmapfront_info *info);

int vnetmap_init(void);
void vnetmap_exit(void);

int
vnetmap_notify(struct netmap_ring_info *ring_info, int flags);
void nm_os_selinfo_init(NM_SELINFO_T *si);

#endif
