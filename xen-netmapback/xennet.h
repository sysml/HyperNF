/*
 *
 * Copyright (c) 2016-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Authors: Kenichi Yasukata
 *
 */

#ifndef __LINUX_XENNET_MODULE_H
#define __LINUX_XENNET_MODULE_H

#include <xen/interface/xen.h>

#define DOM0ID 0

#define __HYPERVISOR_xennet_op 41

#define XENNET_ok  0
#define XENNET_bad_domain 1

#define XENNETOP_mem_netmap 1
#define XENNETOP_irq 2
#define XENNETOP_sync 3

#define XENNETOP_MEM_map_netmap 1
#define XENNETOP_MEM_unmap_netmap 2
#define XENNETOP_MEM_map_kring 3
#define XENNETOP_MEM_unmap_kring 4
#define XENNETOP_MEM_map_nmif_objoff 5
#define XENNETOP_MEM_unmap_nmif_objoff 6
#define XENNETOP_MEM_map_kring_objoff 7
#define XENNETOP_MEM_unmap_kring_objoff 8
//#define XENNETOP_MEM_bdg_attach 9 // Not used, but reserve
#define XENNETOP_MEM_bdg_detach 10
#define XENNETOP_MEM_bind_hwsw 11
#define XENNETOP_MEM_unbind_hwsw 12
#define XENNETOP_MEM_map_i40e 51
#define XENNETOP_MEM_unmap_i40e 52
#define XENNETOP_MEM_map_i40e_objoff 53
#define XENNETOP_MEM_unmap_i40e_objoff 54

#define XENNETOP_IRQ_register 1
#define XENNETOP_IRQ_unregister 2

#define XENNET_IRQTYPE_I40E 1

struct xennet_mem_op {
	domid_t dom;
	domid_t target_dom;
	int16_t status;
	int16_t id;
	int16_t id2;
	int16_t op;
	int16_t op2;
	uint64_t objoff;
	uint64_t pgoff;
	phys_addr_t pa;
	uint32_t len;
	uint32_t nr_frames;
	GUEST_HANDLE(xen_pfn_t) frame_list;
};

DEFINE_GUEST_HANDLE_STRUCT(xennet_mem_op);

struct xennet_irq_op {
	domid_t dom;
	int16_t id;
	int16_t id2;
	int16_t op;
	int16_t pirq;
	int16_t type;
};

DEFINE_GUEST_HANDLE_STRUCT(xennet_irq_op);

struct xennet_sync_op {
	int16_t id;
	int16_t op;
	uint16_t ring_id;
};

DEFINE_GUEST_HANDLE_STRUCT(xennet_sync_op);

int map_xennet_netmap(struct backend_info *be);
int unmap_xennet_netmap(struct backend_info *be);
int map_xennet_kring(struct backend_info *be);
int unmap_xennet_kring(struct backend_info *be);
int map_xennet_nmifobj(struct backend_info *be);
int unmap_xennet_nmifobj(struct backend_info *be);
int map_xennet_kringobj(struct backend_info *be);
int unmap_xennet_kringobj(struct backend_info *be);
int detach_xennet_bdg(struct backend_info *be);
void xennet_set_kring_evtchn(struct backend_info *be);
void xennet_unset_kring_evtchn(struct backend_info *be);

struct hwif {
	void **hw_tx_rings;
	void **hw_rx_rings;
	u32 *txd_cmd;
	u32 itr_countdown;
	void *hwinfo;
	void __iomem *hw_addr;
};

struct xen_netmapif {
	//struct domain *d;
	void *d;
	void *backend_d;
	uint16_t id;

	uint16_t num_tx_rings;
	uint16_t num_rx_rings;
	struct netmap_kring **tx_rings;
	struct netmap_kring **rx_rings;

	struct hwif hwif;

	void *hwnmif;
	void *swnmif;

	int retry;
	// netmap_adapter related objs
	struct nm_bridge *na_bdg;

	uint32_t *up_na_flags;
	uint64_t *last_smac;

	int *bdg_port;
	u_int *mfs;

	/* Offset of ethernet header for each packet. */
	u_int *up_virt_hdr_len;

	uint32_t *nm_buf_size;
	uint32_t *nm_objtotal;

	struct lut_entry *xen_lut;
};

enum i40e_latency_range {
	I40E_LOWEST_LATENCY = 0,
	I40E_LOW_LATENCY = 1,
	I40E_BULK_LATENCY = 2,
	I40E_ULTRA_LATENCY = 3,
};

struct i40e_ring_container {
	/* array of pointers to rings */
	void *ring;
	unsigned int total_bytes;	/* total bytes processed this int */
	unsigned int total_packets;	/* total packets processed this int */
	u16 count;
	enum i40e_latency_range latency_range;
	u16 itr;
};

struct i40e_hwinfo {
	void *xen_tx_desc;
	void *xen_rx_desc;
	u16 *base_queue;
	u16 *queue_index;
	u32 *base_vector;
	u32 *hung_detected;
	u32 *state;
	u64 *flags;
	u16 pf_q;
	u16 ring_id;
	void *nmif;
	struct i40e_ring_container *tx_rc;
	struct i40e_ring_container *rx_rc;
};

// Copied from linux

struct i40e_queue_stats {
	u64 packets;
	u64 bytes;
};

struct i40e_tx_queue_stats {
	u64 restart_queue;
	u64 tx_busy;
	u64 tx_done_old;
	u64 tx_linearize;
	u64 tx_force_wb;
	u64 tx_lost_interrupt;
};

struct i40e_rx_queue_stats {
	u64 non_eop_descs;
	u64 alloc_page_failed;
	u64 alloc_buff_failed;
	u64 page_reuse_count;
	u64 realloc_count;
};

struct i40e_ring {
	struct i40e_ring *next;		/* pointer to next ring in q_vector */
	void *desc;			/* Descriptor ring memory */
	void *dev; //struct device *dev;		/* Used for DMA mapping */
	void *netdev; //struct net_device *netdev;	/* netdev ring maps to */
	union {
		void *tx_bi; // struct i40e_tx_buffer *tx_bi;
		void *rx_bi; // struct i40e_rx_buffer *rx_bi;
	};
	unsigned long state;
	u16 queue_index;		/* Queue number of ring */
	u8 dcb_tc;			/* Traffic class of ring */
	u8 __iomem *tail;

	/* high bit set means dynamic, use accessor routines to read/write.
	 * hardware only supports 2us resolution for the ITR registers.
	 * these values always store the USER setting, and must be converted
	 * before programming to a register.
	 */
	u16 rx_itr_setting;
	u16 tx_itr_setting;

	u16 count;			/* Number of descriptors */
	u16 reg_idx;			/* HW register index of the ring */
	u16 rx_hdr_len;
	u16 rx_buf_len;
	u8  dtype;
#define I40E_RX_DTYPE_NO_SPLIT      0
#define I40E_RX_DTYPE_HEADER_SPLIT  1
#define I40E_RX_DTYPE_SPLIT_ALWAYS  2
#define I40E_RX_SPLIT_L2      0x1
#define I40E_RX_SPLIT_IP      0x2
#define I40E_RX_SPLIT_TCP_UDP 0x4
#define I40E_RX_SPLIT_SCTP    0x8

	/* used in interrupt processing */
	u16 next_to_use;
	u16 next_to_clean;

	u8 atr_sample_rate;
	u8 atr_count;

	unsigned long last_rx_timestamp;

	bool ring_active;		/* is ring online or not */
	bool arm_wb;		/* do something to arm write back */
	u8 packet_stride;

	u16 flags;
#define I40E_TXR_FLAGS_WB_ON_ITR	BIT(0)
#define I40E_TXR_FLAGS_LAST_XMIT_MORE_SET BIT(2)

	/* stats structs */
	struct i40e_queue_stats	stats;
	struct u64_stats_sync syncp;
	union {
		struct i40e_tx_queue_stats tx_stats;
		struct i40e_rx_queue_stats rx_stats;
	};

	unsigned int size;		/* length of descriptor ring in bytes */
	dma_addr_t dma;			/* physical address of ring */

	void *vsi; //struct i40e_vsi *vsi;		/* Backreference to associated VSI */
	void *q_vector; // struct i40e_q_vector *q_vector;	/* Backreference to associated vector */

	struct rcu_head rcu;		/* to avoid race on free */
} ____cacheline_internodealigned_in_smp;

#endif
