#ifndef _UAPI_NOS_TRACK_H
#define _UAPI_NOS_TRACK_H
#include <linux/types.h>

/* use alloc_bootmem, do not need this :-~) */
// #define START_RESERVE_MEM 	(16<<20) //arm/mips
// #define START_RESERVE_MEM 	(0x10000000) //for x86, the low addr reserved by IO.

#ifdef CONFIG_NTRACK_BOOTM_SIZE
 #define NTRACK_BOOTM_SIZE (CONFIG_NTRACK_BOOTM_SIZE * (0x1<<20))
#else
 #define NTRACK_BOOTM_SIZE (64 * (0x1<<20))
#endif

#define NTRACK_PKT_PRIV_SIZE (128)

#define NOS_USER_INFO_SIZE			(128)
#define NOS_FLOW_INFO_SIZE			(128)

#define NOS_USER_FLAGS_TYPE_USER 	(1<<0)
#define NOS_USER_TRACK_TIMEOUT		(HZ * 3600 * 24) //hour ?

typedef unsigned long utimes_t;

/* kernel & user ... multi modules comm used */
typedef struct nos_user_hdr {
	uint16_t flags;
	uint8_t type;
	uint8_t status; /*bitmap, status.*/
	uint32_t rule_magic; /* user node match ipset rule magic, as conf update, this need sync. */
	utimes_t time_stamp; /* notify, statistics */
	uint64_t recv_bytes, xmit_bytes; /* statisc */
	uint64_t recv_pkts, xmit_pkts;

	uint64_t src_ipgrp_bits;
	uint32_t u_usr_crc;
	uint8_t u_grp_id;
	uint8_t src_zone_id;
#define NOS_RULE_TYPE_AUTH 0
#define NOS_RULE_TYPE_MAX 1
	uint8_t rule_idx[NOS_RULE_TYPE_MAX];
	uint8_t dummy_pad[1];
} user_hdr_t;

typedef struct nos_flow_hdr {
	uint32_t flags;
	uint16_t proto;

	utimes_t time_stamp;
	uint64_t recv_bytes, xmit_bytes;
	uint64_t recv_pkts, xmit_pkts; /* statistics */
} flow_hdr_t;
/* end of comm */

/* markup the only flow. */
typedef struct nos_flow_tuple {
	uint32_t ip_src;
	uint32_t ip_dst;
	uint16_t port_src;
	uint16_t port_dst;
	uint8_t  proto;
	uint8_t  dummy_pad[3];
} flow_tuple_t;

/* each node have 16 byte header */
#define NOS_USER_DATA_SIZE (NOS_USER_INFO_SIZE - 16 - sizeof(struct nos_user_hdr))
#define NOS_FLOW_DATA_SIZE (NOS_FLOW_INFO_SIZE - 16 - sizeof(struct nos_flow_tuple) - sizeof(struct nos_flow_hdr))
typedef struct nos_user_info {
	/* !!! keep this 16 byte header sync, DO not modify !!! */
	uint32_t magic;
	uint32_t id;
	uint32_t refcnt;
	uint32_t ip;
	/* end */

	struct nos_user_hdr hdr;

	char private[NOS_USER_DATA_SIZE];
} user_info_t;

typedef struct nos_flow_info {
	/* !!! keep this 16 byte header sync, DO not modify !!! */
	uint32_t magic;
	uint32_t id;
	uint32_t ui_src_id;
	uint32_t ui_dst_id;
	/* end */

	struct nos_flow_tuple tuple;
	struct nos_flow_hdr hdr;

	char private[NOS_FLOW_DATA_SIZE];
} flow_info_t;

#endif /* _UAPI_NOS_TRACK_H */
