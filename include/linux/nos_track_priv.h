#ifndef _NOS_TRACK_PRIV_H__
#define _NOS_TRACK_PRIV_H__

#include <asm/atomic.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/timer.h>
#include <linux/skbuff.h>

struct tbq_backlog {
	struct list_head list;
	struct tbq_token_ctrl *tc;
	uint32_t octets;
	uint32_t weight;
	int32_t drr_deficit;
};

struct tbq_flow_backlog {
	struct tbq_backlog base;
	struct list_head packets;
	struct tbq_flow_track *tf;
};

struct tbq_flow_track {
	struct list_head list;
	uint16_t dummy;
	uint16_t app_id;
	uint16_t uname_match;	//mo
	uint32_t rule_mask;
	uint8_t weight[32];
	struct tbq_flow_backlog backlog[2];
};

struct nos_track {
	struct nos_flow_info *flow;
	struct nos_user_info *ui_src;
	struct nos_user_info *ui_dst;
	struct tbq_flow_track tbq;
};

struct nos_user_track {
	uint32_t ip;
	uint32_t magic;
	struct hlist_node hash_node;
	struct timer_list timeout;
	spinlock_t lock;
	uint32_t refcnt;
	uint32_t flags;
	void *tbq;
};

struct nos_flow_track {
	uint32_t magic;
	struct nos_user_track *ut_src;
	struct nos_user_track *ut_dst;
};

struct nos_track_event {
	struct list_head list;
	void (* on_user_free)(struct nos_user_track *);
	void (* on_flow_free)(struct tbq_flow_track *);
};

struct nos_track_stats {
	atomic64_t nr_flow_alloc;
	atomic64_t nr_flow_free;
	atomic64_t nr_ring_drop;
};

extern void* nos_track_cap_base;
extern uint32_t nos_track_cap_size;
extern uint32_t nos_user_info_max, nos_flow_info_max;
extern struct nos_track_stats *nos_track_stats;

extern uint32_t nos_auth_no_flow_timeout;

int nos_track_init(void);
int nos_track_alloc(struct nos_track *track, struct nos_flow_tuple *tuple, struct sk_buff *skb);
void nos_track_free(struct nos_track *track);

struct nos_user_track *nos_get_user_track(struct nos_track *track);
struct nos_flow_track *nos_get_flow_track(struct nos_track *track);

void nos_user_info_hold(struct nos_user_info *ui);

void nos_track_event_register(struct nos_track_event *ev);
void nos_track_event_unregister(struct nos_track_event *ev);

#endif /* _NOS_TRACK_PRIV_H__ */
