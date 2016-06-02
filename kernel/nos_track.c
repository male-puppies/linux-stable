#include <linux/nos_track.h>
#include <linux/nos_mempool.h>
#include <linux/bootmem.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/timer.h>


/* for sysctl read */
void		*nt_shm_base = NULL;
uint32_t 	nt_shm_size = NTRACK_BOOTM_SIZE;
uint32_t 	nt_cap_block_sz = 0;
uint32_t 	nt_user_offset = 0;
uint32_t 	nt_flow_offset = 0;

/* for modules use */
void 		*nos_track_cap_base = NULL;
uint32_t 	nos_track_cap_size = 0;
uint32_t 	nos_user_info_max, nos_flow_info_max;
struct nos_track_stats *nos_track_stats;

EXPORT_SYMBOL(nt_cap_block_sz);
EXPORT_SYMBOL(nos_track_cap_base);
EXPORT_SYMBOL(nos_track_cap_size);
EXPORT_SYMBOL(nos_track_stats);
EXPORT_SYMBOL(nos_user_info_max);
EXPORT_SYMBOL(nos_flow_info_max);

/* for local use */
static uint32_t nos_user_track_hash_size;
static uint32_t nos_user_track_max;
static uint32_t nos_flow_track_max;

static struct nos_user_track *nos_user_tracks;
static struct nos_flow_track *nos_flow_tracks;

static struct nos_mempool nos_user_track_pool;
static struct nos_mempool nos_flow_track_pool;

static struct hlist_head *nos_user_track_hash;
static spinlock_t nos_user_track_hash_lock;

static atomic_t nos_user_magic = ATOMIC_INIT(0);
static atomic_t nos_flow_magic = ATOMIC_INIT(0);

static struct nos_user_info *nos_user_info_base;
static struct nos_flow_info *nos_flow_info_base;

static struct {
	struct list_head list;
	spinlock_t lock;
} nos_track_events;

static void nos_user_track_put(struct nos_user_track *);

static void utrack_timeout_fn(unsigned long d)
{
	struct nos_user_track *ut = (struct nos_user_track*)d;

	nos_user_track_put(ut);
}

static struct nos_user_info *
nos_user_info_init(struct nos_user_track *ut)
{
	int32_t user_id = ut - nos_user_tracks;
	struct nos_user_info *ui = nos_user_info_base + user_id;

	ui->id = user_id;
	ui->ip = ut->ip;
	ui->refcnt = ut->refcnt;

	memset(&ui->hdr, 0, sizeof(ui->hdr));
	memset(ui->private, 0, sizeof(ui->private));

	smp_wmb();

	ui->magic = ut->magic;

	return ui;
}

static inline void
nos_user_info_update_refcnt(struct nos_user_track *ut)
{
	int32_t user_id = ut - nos_user_tracks;
	struct nos_user_info *ui = nos_user_info_base + user_id;
	ui->refcnt = ut->refcnt;
}

static struct nos_flow_info *
nos_flow_info_init(struct nos_flow_track *ft, struct nos_flow_tuple *tuple)
{
	int32_t flow_id = ft - nos_flow_tracks;
	struct nos_flow_info *fi = nos_flow_info_base + flow_id;

	fi->id = flow_id;
	fi->user_id = ft->user - nos_user_tracks;
	fi->peer_id = ft->peer - nos_user_tracks;
	fi->tuple = *tuple;

	memset(fi->private, 0, sizeof(fi->private));

	smp_wmb();

	fi->magic = ft->magic;

	return fi;
}

static inline int utrack_is_user(struct nos_user_track *ut)
{
	return ut->flags & NOS_USER_FLAGS_TYPE_USER;
}
nos_user_match_fn_t nos_user_match_fn = NULL;

static struct nos_user_track *nos_user_track_get(uint32_t ip, struct sk_buff *skb)
{
	struct nos_user_track *user;
	struct nos_user_info *ui;
	struct hlist_head *slot;
	uint32_t slot_index;
	nos_user_match_fn_t fn;

	slot_index = ip % nos_user_track_hash_size;

	spin_lock_bh(&nos_user_track_hash_lock);

	slot = &nos_user_track_hash[slot_index];

	hlist_for_each_entry(user, slot, hash_node) {
		if (user->ip == ip) {
			spin_lock_bh(&user->lock);
			if (user->refcnt == 0) {
				spin_unlock_bh(&user->lock);
				break;
			}
			++user->refcnt;
			nos_user_info_update_refcnt(user);
			spin_unlock_bh(&user->lock);
			goto out;
		}
	}

	user = nos_mempool_get(&nos_user_track_pool);
	if (user == NULL) {
		goto out;
	}

	user->ip = ip;
	user->refcnt = 1;
	user->magic = atomic_add_return(2, &nos_user_magic);
	spin_lock_init(&user->lock);

	/* is user or peer ? */
	ui = nos_user_info_init(user);
	fn = rcu_dereference(nos_user_match_fn);
	if (fn && skb && fn(ui, skb)) {
		/* mark user */
		user->flags |= NOS_USER_FLAGS_TYPE_USER;
		++ user->refcnt;
		setup_timer(&user->timeout, utrack_timeout_fn, (unsigned long)user);
		user->timeout.expires = jiffies + NOS_USER_TRACK_TIMEOUT;
		add_timer(&user->timeout);
	}

	hlist_add_head(&user->hash_node, slot);
	user->tbq = NULL;

#if 0
	printk("[nos_track] ADD USER: %pI4h\t(%6d / %6d)\n",
			&ip, nos_user_track_pool.nr_used, nos_user_track_pool.nr_free);
#endif

out:
	spin_unlock_bh(&nos_user_track_hash_lock);
	return user;
}
EXPORT_SYMBOL(nos_user_match_fn);

static void
nos_user_track_put(struct nos_user_track *user)
{
	struct nos_track_event *ev;
	int32_t refcnt;

	BUG_ON(user == NULL);

	spin_lock_bh(&user->lock);
	refcnt = --user->refcnt;
	nos_user_info_update_refcnt(user);
	spin_unlock_bh(&user->lock);

	BUG_ON(refcnt < 0);

	if (refcnt != 0)
		return;

	spin_lock_bh(&nos_track_events.lock);
	list_for_each_entry(ev, &nos_track_events.list, list) {
		ev->on_user_free(user);
	}
	spin_unlock_bh(&nos_track_events.lock);

	BUG_ON(user->tbq != NULL);

	// set delete mark
	nos_user_info_base[user - nos_user_tracks].magic = user->magic | 1U;

	spin_lock_bh(&nos_user_track_hash_lock);
	hlist_del(&user->hash_node);
	spin_unlock_bh(&nos_user_track_hash_lock);
#if 0
	printk("[nos_track] DEL: %pI4h\t(%6d / %6d)\n",
			&user->ip, nos_user_track_pool.nr_used - 1, nos_user_track_pool.nr_free + 1);
#endif
	nos_mempool_put(&nos_user_track_pool, user);
}

static void
nos_track_check(struct nos_track *track)
{
	struct nos_flow_info *fi = track->flow;
	struct nos_user_info *ui_src = track->user;
	struct nos_user_info *ui_dst = track->peer;
	uint32_t user_id = ui_src - nos_user_info_base;
	uint32_t peer_id = ui_dst - nos_user_info_base;

	if (user_id >= nos_user_track_max || user_id != fi->user_id) {
		pr_warn_ratelimited("nos_flow_info error: %d, %d\n", user_id, fi->user_id);
	}

	if (peer_id >= nos_user_track_max || peer_id != fi->peer_id) {
		pr_warn_ratelimited("nos_flow_info error: %d, %d\n", peer_id, fi->peer_id);
	}
}

int
nos_track_alloc(struct nos_track *track, struct nos_flow_tuple *tuple, struct sk_buff *skb)
{
	struct nos_flow_track *flow = NULL;
	struct nos_user_track *user = NULL;
	struct nos_user_track *peer = NULL;

	flow = nos_mempool_get(&nos_flow_track_pool);
	if (flow == NULL)
		goto fail;

	user = nos_user_track_get(tuple->ip_src, skb);
	peer = nos_user_track_get(tuple->ip_dst, NULL);

	if (user == NULL || peer == NULL)
		goto fail;

	if (utrack_is_user(user)) {
		flow->user = user;
		flow->peer = peer;
	} else if (utrack_is_user(peer)) {
		flow->user = peer;
		flow->peer = user;
	} else {
		flow->user = user;
		flow->peer = peer;
	}

	flow->magic = atomic_add_return(2, &nos_flow_magic);

	track->flow = nos_flow_info_init(flow, tuple);
	track->user = &nos_user_info_base[track->flow->user_id];
	track->peer = &nos_user_info_base[track->flow->peer_id];
	atomic64_inc(&nos_track_stats->nr_flow_alloc);

	memset(&track->tbq, 0, sizeof(track->tbq));

	return 0;

fail:
	if (flow != NULL) {
		if (user != NULL)
			nos_user_track_put(user);
		if (peer != NULL)
			nos_user_track_put(peer);
		nos_mempool_put(&nos_flow_track_pool, flow);
	}
	track->flow = NULL;
	track->user = NULL;
	track->peer = NULL;
	return -1;
}
EXPORT_SYMBOL(nos_track_alloc);

void
nos_track_free(struct nos_track *track)
{
	struct nos_flow_track *flow;
	struct nos_track_event *ev;
	int flow_id;

	if (track->flow == NULL) {
		return;
	}

	flow_id = track->flow - nos_flow_info_base;
	BUG_ON(flow_id < 0 || flow_id >= nos_flow_track_max);

	nos_track_check(track);

	flow = &nos_flow_tracks[flow_id];

	spin_lock_bh(&nos_track_events.lock);
	list_for_each_entry(ev, &nos_track_events.list, list) {
		ev->on_flow_free(&track->tbq);
	}
	spin_unlock_bh(&nos_track_events.lock);

	track->flow->magic = flow->magic | 1U; // delete mark

	nos_user_track_put(flow->user);
	nos_user_track_put(flow->peer);

	nos_mempool_put(&nos_flow_track_pool, flow);

	atomic64_inc(&nos_track_stats->nr_flow_free);
}
EXPORT_SYMBOL(nos_track_free);

struct nos_user_track *
nos_get_user_track(struct nos_track *track)
{
	int user_id;

	BUG_ON(track->flow == NULL);
	BUG_ON(track->user == NULL);
	BUG_ON(track->peer == NULL);

	user_id = track->user - nos_user_info_base;
	BUG_ON(user_id < 0 || user_id >= nos_user_track_max);
	return nos_user_tracks + user_id;
}
EXPORT_SYMBOL(nos_get_user_track);

struct nos_flow_track *
nos_get_flow_track(struct nos_track *track)
{
	int flow_id;

	BUG_ON(track->flow == NULL);
	BUG_ON(track->user == NULL);
	BUG_ON(track->peer == NULL);

	flow_id = track->flow - nos_flow_info_base;
	BUG_ON(flow_id < 0 || flow_id >= nos_flow_track_max);
	return nos_flow_tracks + flow_id;
}
EXPORT_SYMBOL(nos_get_flow_track);

void nos_track_event_register(struct nos_track_event *ev)
{
	spin_lock_bh(&nos_track_events.lock);
	list_add_tail(&ev->list, &nos_track_events.list);
	spin_unlock_bh(&nos_track_events.lock);
}
EXPORT_SYMBOL(nos_track_event_register);

void nos_track_event_unregister(struct nos_track_event *ev)
{
	spin_lock_bh(&nos_track_events.lock);
	list_del(&ev->list);
	spin_unlock_bh(&nos_track_events.lock);
}
EXPORT_SYMBOL(nos_track_event_unregister);

/* just for view */
static struct resource nosmem_res = {
	.name  = "nos track",
	.start = 0,
	.end   = 0,
	.flags = IORESOURCE_BUSY | IORESOURCE_MEM | IORESOURCE_DMA
};

static int nos_vars_init(void)
{
	nos_track_cap_size = nt_shm_size / 4;
	nos_user_track_max = nt_shm_size / 4 / sizeof(user_info_t);
	nos_flow_track_max = nt_shm_size / 4 / sizeof(flow_info_t);

	nos_user_track_hash_size = nos_user_track_max / 4;

	nos_user_info_max = nos_user_track_max;
	nos_flow_info_max = nos_flow_track_max;

	return 0;
}

static int nos_mmap_init(void)
{
	void *base = phys_to_virt(nt_shm_base);
	nos_track_cap_base = base;
	printk("nos_track_cap_base: %p, size: %x\n", nos_track_cap_base, nos_track_cap_size);

	nos_user_info_base = base + nos_track_cap_size;
	nos_flow_info_base = (void *)(nos_user_info_base + nos_user_track_max);
	nos_track_stats = (void *)(nos_flow_info_base + nos_flow_track_max);

	nt_user_offset = (unsigned long)nos_user_info_base - (unsigned long)nos_track_cap_base;
	nt_flow_offset = (unsigned long)nos_flow_info_base - (unsigned long)nos_track_cap_base;

	printk("nos shm: %p size: %x\n", nt_shm_base, nt_shm_size);

	printk("nos_user_info_base: %p (phys: %x)\n",
		nos_user_info_base, virt_to_phys(nos_user_info_base));
	printk("nos_flow_info_base: %p (phys: %x)\n",
		nos_flow_info_base, virt_to_phys(nos_flow_info_base));
	printk("nos_track_stats: %p (phys: %x)\n",
		nos_track_stats, virt_to_phys(nos_track_stats));

	if (virt_to_phys(nos_track_stats - 1) > nosmem_res.end) {
		printk("nosmem_res oom: [%llu - %llu]\n", (uint64_t)nosmem_res.start, (uint64_t)nosmem_res.end);
		return -1;
	}

	// delete mark: magic & 1 == 1
	memset(nos_user_info_base, 0xAF, nos_user_track_max * sizeof(struct nos_user_info));
	memset(nos_flow_info_base, 0xBF, nos_flow_track_max * sizeof(struct nos_flow_info));
	return 0;
}

int nos_track_init()
{
	int i;

	/* check struct align. */
	BUG_ON(sizeof(user_info_t) != NOS_USER_INFO_SIZE);
	BUG_ON(sizeof(flow_info_t) != NOS_FLOW_INFO_SIZE);

	if(!nt_shm_base) {
		printk("nos track reserve mem nil.\n");
		return -ENOMEM;
	}

	if(nos_vars_init()) {
		printk("nos track pars setup error.\n");
		return -ENOMEM;
	}

	if(nos_mmap_init()) {
		printk("nos track mmap init failed.\n");
		return -ENOMEM;
	}

	nos_user_tracks = vmalloc(nos_user_track_max * sizeof(struct nos_user_track));
	if(!nos_user_tracks) {
		printk("nos track user pool nomem.\n");
		goto __error;
	}
	nos_mempool_init(&nos_user_track_pool, "nos_user_track", nos_user_track_max);
	for (i = 0; i < nos_user_track_max; i++) {
		nos_mempool_put(&nos_user_track_pool, &nos_user_tracks[i]);
	}

	nos_flow_tracks = vmalloc(nos_flow_track_max * sizeof(struct nos_flow_track));
	if(!nos_flow_tracks) {
		printk("nos track flow pool nomem.\n");
		goto __error;
	}
	nos_mempool_init(&nos_flow_track_pool, "nos_flow_track", nos_flow_track_max);
	for (i = 0; i < nos_flow_track_max; i++) {
		nos_mempool_put(&nos_flow_track_pool, &nos_flow_tracks[i]);
	}

	spin_lock_init(&nos_user_track_hash_lock);
	nos_user_track_hash = vmalloc(nos_user_track_hash_size * sizeof(struct hlist_head));
	if(!nos_user_track_hash) {
		printk("nos uhash no mem.\n");
		goto __error;
	}
	for (i = 0; i < nos_user_track_hash_size; i++) {
		INIT_HLIST_HEAD(&nos_user_track_hash[i]);
	}

	INIT_LIST_HEAD(&nos_track_events.list);
	spin_lock_init(&nos_track_events.lock);

	printk("nos_track_init() OK [user size: %d, flow size: %d]\n",
		(int)sizeof(struct nos_user_info), (int)sizeof(struct nos_flow_info));
	printk("\t[user priv size: %d, flow priv size: %d]\n",
		NOS_USER_DATA_SIZE, NOS_FLOW_DATA_SIZE);

	return 0;

__error:
	if(nos_user_tracks)
		vfree(nos_user_tracks);
	if(nos_flow_tracks)
		vfree(nos_flow_tracks);
	if(nos_user_track_hash)
		vfree(nos_user_track_hash);
	return -ENOMEM;
}
EXPORT_SYMBOL(nos_track_init);

/* kernel reserve memory */
void __init ntrack_mem_reserve(void)
{
	int ret;

	nt_shm_base = alloc_bootmem(nt_shm_size);
	if (!nt_shm_base) {
		pr_warn("nos reservation failed - mem in use %lx\n", (unsigned long)nt_shm_base);
		return;
	}
	nt_shm_base = virt_to_phys(nt_shm_base);

	nosmem_res.start = nt_shm_base;
	nosmem_res.end = nosmem_res.start + nt_shm_size - 1;
	ret = insert_resource(&iomem_resource, &nosmem_res);
	if (ret) {
		pr_err("Resource %ldMB of mem at %ldMB for nos_track failed. %d\n",
			((unsigned long)nt_shm_size >> 20),
			((unsigned long)nt_shm_base >> 20), ret);
	} else {
		pr_info("Resource %ldMB of mem at %ldMB for nos_track.\n",
			((unsigned long)nt_shm_size >> 20),
			((unsigned long)nt_shm_base >> 20));
	}
}

static int __init set_ntrack_mem_size(char *str)
{
	int ret;

	if (*str++ != '=' || !*str) {
		nt_shm_size = NTRACK_BOOTM_SIZE;
		ret = 1;
		goto __finished;
	}

	ret = kstrtouint(str, 0, &nt_shm_size);
	if(ret) {
		nt_shm_size = NTRACK_BOOTM_SIZE;
		ret = 1;
		goto __finished;
	}

	if(nt_shm_size > 0 && nt_shm_size <= 64) {
		nt_shm_size = (nt_shm_size<<20);
	} else {
		nt_shm_size = NTRACK_BOOTM_SIZE;
	}

__finished:
	printk("nos track setup reserve mem: %x\n", nt_shm_size);
    return ret;
}
__setup("ntrack_mem", set_ntrack_mem_size);
