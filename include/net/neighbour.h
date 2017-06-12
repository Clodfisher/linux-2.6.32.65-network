#ifndef _NET_NEIGHBOUR_H
#define _NET_NEIGHBOUR_H

#include <linux/neighbour.h>

/*
 *	Generic neighbour manipulation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 * 	Changes:
 *
 *	Harald Welte:		<laforge@gnumonks.org>
 *		- Add neighbour cache statistics like rtstat
 */

#include <asm/atomic.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>

#include <linux/err.h>
#include <linux/sysctl.h>
#include <linux/workqueue.h>
#include <net/rtnetlink.h>

/*
 * NUD stands for "neighbor unreachability detection"
 */

#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)                  //定时器状态，与定时器有关的状态
#define NUD_VALID	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)   //有效状态，除了初始状态外的状态, NUD_INCOMPLETE,NUD_FAILE
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)                             //连接状态，已经有确切的结论的状态可到达，
                                                                                            //可直接发送数据包给邻居结构

struct neighbour;

/*
 * 对于每个设备上邻居协议行为进行调整的一组参数(邻居洗衣参数配置)。由于在大部分接口上可以启动多个协议(例如，IPv4和IPv6)，
 * 所以一个net_device结构可以关联多个
 * neigh_parms结构
*/
struct neigh_parms
{
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
	struct net_device *dev;//指向该neigh_parms实例所对应的网络设备
	struct neigh_parms *next;//将所有neigh_params实例连接在一起，每个neigh_table实例都有各自的neigh_parms队列
	int	(*neigh_setup)(struct neighbour *);
	void	(*neigh_cleanup)(struct neighbour *);
	struct neigh_table *tbl;//指向该neigh_parms实例所属的邻居表

	void	*sysctl_table;//邻居表的sysctl表，对于arp是在arp模块初始化函数arp_init()中对其初始化的，这样用户可以通过proc文件系统
	                      //来读写邻居表的参数

	int dead;//该字段值如果为1，则该邻居参数实例正在被删除，不能再使用，也不能再创建对应网络设备的邻居项。例如在网络设备禁用时调用
	         //neigh_parms_release()设置
	atomic_t refcnt;//引用计数
	struct rcu_head rcu_head;//为控制同步访问而设置的参数

	int	base_reachable_time;//为计算reachable_time的基准值,30s
	int	retrans_time;//重传一个请求前延迟的jiffies值。默认值为1s
	int	gc_staletime;//一个邻居项如果持续闲置(没有被使用)时间到达gc_staletime且没有被引用则会将被删除.默认值为60s
	int	reachable_time;//其为NUD_REACHEABLE状态超时时间，该值为随机值，介于
	                   //base_reachable_time/2和3*base_reachable_time/2之间的一个随机值。
	                   //通常300s在neigh_periodic_work()中更新一次
	int	delay_probe_time;//邻居项维持在NUD_DELAY状态delay_probe_time之后进入NUD_PROBE状态，或者处于NUD_REACHABLE状态的邻居项闲置时间
	                     //超过delay_probe_time后，直接进入NUD_DELAY状态

	int	queue_len;//proxy_queue队列长度上限。
	int	ucast_probes;//在请求ARP守护进程前尝试发送单播探测次数，默认值为3
	int	app_probes;//一般情况下为0，当使用了arpd守护进程时才会设置它的值
	int	mcast_probes;//多播或广播在标识一个邻居项不可达之前最多尝试解析的次数，默认值为3次
	int	anycast_delay;//在响应一个IPv6邻居请求消息之前最多延迟的jiffies值，对anycast的支持还没有实现，默认值为1s
	int	proxy_delay;//当接收到一个对未知代理ARP地址ARP请求时，将延迟porxy_delay jiffies响应。这用来在一些情况下防止ARP报文的洪泛，默认值为0.8s
	int	proxy_qlen;//允许在proxy-ARP地址上排队的数据包数，默认值为64
	int	locktime;//一个ARP项至少在缓存中保存的jiffies值.在存在多余一个的可能映射的情况下，这通常是因为网络配置错误，用来防止ARP缓存抖动。默认值为1s
};

/* 用来存储统计信息，一个该结构实例对应一个网络设备上的一种邻居协议 */
struct neigh_statistics
{
	unsigned long allocs;		/* number of allocated neighs 记录已分配的neighbour结构实例总数，包括已释放的实例 */
	unsigned long destroys;		/* number of destroyed neighs 在neigh_destroy中删除的邻居项总和 */
	unsigned long hash_grows;	/* number of hash resizes  扩容hash_buckets散列表的次数 */

	unsigned long res_failed;	/* number of failed resolutions 尝试解析一个邻居地址的失败次数，这并不是发送arp请求报文的次数，
	                              而是对于一个邻居来说，在neigh_timer_handler()中所有尝试都失败之后才进行计数 */

	unsigned long lookups;		/* number of lookups 调用neigh_lookup()的总次数 */
	unsigned long hits;		/* number of hits (among lookups) 调用neigh_lookup() 成功返回总次数 */

	/* IPV6分别用来标识接收到发往组播或单播地址的ARP请求报文总数 */
	unsigned long rcv_probes_mcast;	/* number of received mcast ipv6 */
	unsigned long rcv_probes_ucast; /* number of received ucast ipv6 */

	/* 分别调用neigh_periodic_timer()或neigh_forced_gc()的次数 */
	unsigned long periodic_gc_runs;	/* number of periodic GC runs */
	unsigned long forced_gc_runs;	/* number of forced GC runs */

	unsigned long unres_discards;	/* number of unresolved drops */
};

#define NEIGH_CACHE_STAT_INC(tbl, field)				\
	do {								\
		preempt_disable();					\
		(per_cpu_ptr((tbl)->stats, smp_processor_id())->field)++; \
		preempt_enable();					\
	} while (0)

/*
 * 存储邻居的有关信息，例如L2和L3地址，NUD状态，访问邻居经过的设备等。注意，一个neighbour项不是与一台主机有关，而是
 * 与一个L3地址相关，因为一台主机可能有多个L3地址。例如路由器就有多个接口，因此也有多个L3地址
*/
struct neighbour
{//邻居数据结构
	struct neighbour	*next;//组成队列的指针，通过next把邻居项插入到散列表桶链表上，总在桶的前部插入新的邻居项
	struct neigh_table	*tbl;//邻居表结构，该邻居项所在的邻居表，如果该邻居项对应的是一个ipv4地址，则该字段指向arp_tbl
	struct neigh_parms	*parms;//邻居参数结构
	struct net_device		*dev;//网络设备指针，对每个邻居来说，只能有一个可用来访问该邻居的网络设备
	unsigned long		used;//使用时间,代表最近使用该邻居项的时间，该字段值并不总是与数据传输同步更新，当邻居不处于NUD_CONNECTED
	                         //状态时，该值在neigh_event_send()更新中，而当邻居状态处于NUD_CONNECTED状态时，该值有时会通过gc_timer定时器处理函数更新
	unsigned long		confirmed;//确认时间,代表最近收到来自对应邻居项的报文时间，传输层通过neigh_confirm()来更新，邻居子系统用neigh_update()更新
	unsigned long		updated;//更新时间(重新设置状态后的时间)
	__u8			flags;//标志位
	__u8			nud_state;//状态标志
	__u8			type;//类型，该值经常被设置为RTN_UNICAST,RTN_LOCAL,RTN_BROADCAST，等
	__u8			dead;//生存标志，如果设置为1，则意味着该邻居项正在被删除，最总通过垃圾回收将其删除
	atomic_t		probes;//失败计数器,发送arp的探测数，该值在定时器处理函数中被检测，当该值达到指定的上限，该邻居项变进入NUD_FAILED状态
	rwlock_t		lock;//读写锁，用来控制访问邻居项的读写锁
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];//MAC地址，通常其他地址不会超过32B，因此设置为32
	struct hh_cache		*hh;//链路头部缓存，加速发送，指向缓存的二层协议首部hh_cache结构实例链表
	atomic_t		refcnt;//引用计数器
	int			(*output)(struct sk_buff *skb);//发送函数指针，用来将报文输出到该邻居。在邻居项的整个生命周期中，由于其状态时不断变化的，
	                                           //从而导致该函数指针会指向不同的输出函数。例如当邻居为可达时，调用neigh_connect将output
	                                           //设置为neigh_ops->connected_output
	struct sk_buff_head	arp_queue;//需要处理的数据包队列
	struct timer_list	timer;//定时队列,用来管理多种超时情况的定时器
	const struct neigh_ops	*ops;//指向邻居项函数指针表实例，每一种邻居协议都提供3到4种不同的邻居项函数指针表，实际用哪一种还需要根据
	                             //三层协议地址的类型、网络设备的类型等
	u8			primary_key[0];//主键值，一般是网关地址，该实际使用空间是根据三层协议地址长度动态分配的，例如IPV4为32位目标IP地址
};

/*
 * 一组函数，用来表示L3协议(如IP)和dev_queue_xmit之间的接口。
 * 邻居项函数指针表由在邻居的生存周期中不同时期被调用的多个函数指针组成，其中有多个函数指针是实现三层(IPV4中的IP层)与
 * dev_queue_xmit()之间的调用调用桥梁，使用于不同的状态。
*/
struct neigh_ops
{
	int			family;//标识所属的地址族，比如ARP为AF_INET等
	void			(*solicit)(struct neighbour *, struct sk_buff*);//发送请求报文函数，在发送第一个报文时，需要新的邻居项，发送
	                                                                //报文被缓存到arp队列中，然后调用solicit()发送请求报文
	void			(*error_report)(struct neighbour *, struct sk_buff*);//当邻居项缓存这未发送的报文，而该邻居项不可到达时，被调用
	                                                                     //来向三层报告错误的函数，ARP中为arp_error_report()，最终会
	                                                                     //给报文发送方发送一个主机不可达的ICMP差错报文。
	int			(*output)(struct sk_buff*);//最通用的输出函数，可用于所有情况。此输出函数实现了完整的输出过程，因此存在较多的校验与
	                                       //操作，以确保报文的输出，因此该函数相对消耗资源。此外，不要将neigh_ops->output与
	                                       //neighbour->output()混淆
	int			(*connected_output)(struct sk_buff*);//在确定邻居可到达时，及状态为NUD_CONNECTED时使用的输出函数.由于所有输出所需要
													 //的信息都已具备，因此该函数只是简单地添加二层首部，也因此比output()快的多。
	int			(*hh_output)(struct sk_buff*);//已缓存了二层首部的情况下使用的输出函数
	int			(*queue_xmit)(struct sk_buff*);//实际上，以上几个输出函数，除了hh_output外，并不真正传输数据包，只是在准备好二层首部
	                                           //之后，调用queue_xmit接口。
};

/*
 *pneigh_entry结构实例用来保存允许代理的条件，只有和结构中的接收设备以及目标地址相匹配才能代理，所有pneigh_entry实例都存储在
 *邻居表phash_buckets散列表中，称之为代理项。可通过ip neigh add proxy命令添加
*/
struct pneigh_entry
{
	struct pneigh_entry	*next;//将pneigh_entry结构实例链接到phash_buckets散列表的一个桶中
#ifdef CONFIG_NET_NS
	struct net		*net;
#endif
	struct net_device	*dev;//通过该网络设备接收到的ARP请求报文才能代理
	u8			flags;//NTF_PROXY代理表现标志，用ip命令在代理的邻居时会添加此标志，ip neigh add proxy 10.0.0.4 dev eth0
	u8			key[0];//存储三次协议地址，存储空间根据neigh_table结构的key_len字段分配，只有目的地址和该三次协议地址分配的arp请求
	                   //报文才能代理
};

/*
 *	neighbour table manipulation 邻居表操作
 *  描述一种邻居协议的参数、功能函数、以及邻居项散列表。每个邻居协议都有该结构的一个实例。内核中的arp_tbl就是ARP地址解析协议的邻居表结构。
 *  所有实例都插入到一个静态变量neigh_tables指向的一个全局表中，
 *  并由neigh_table_lock来加锁保护。该锁只保护全局表的完整性，并不对表中每个条目的内容进行保护.
 */
struct neigh_table
{//邻居表结构
	struct neigh_table	*next;//指向队列中的下一个邻居表，该链表中除了ARP的arp_tbl，还有IPV6T和DECNE实例nd_tbl和dn_neigh_table等
	int			family;//地址族，ARP为AF_INET
	int			entry_size;//邻居项结构的大小，对arp_tbl来说，初始化为sizeof(neighbour)+4,
	                       //这是因为在ARP中neighbour解耦股最后一个成员零长数组primary_key，实际指向一个ipv4地址长4
	int			key_len;//IP地址长度，因为ipv4中为IP地址，因此为4
	__u32			(*hash)(const void *pkey, const struct net_device *);//哈希函数指针，用来计算哈希值,arp中为arp_hash()
	int			(*constructor)(struct neighbour *);//创建邻居结构的函数指针,在arp中为arp_constructor，由邻居表现创建函数neigh_create调用
	int			(*pconstructor)(struct pneigh_entry *);//IPv6使用的创建函数指针
	void			(*pdestructor)(struct pneigh_entry *);//IPv6使用的释放函数指针
	void			(*proxy_redo)(struct sk_buff *skb);//处理函数指针，用来处理在neigh_table->queue缓存队列中的代理ARP报文。
	char			*id;//协议名称作为ID，用来分配neighbour结构实例的缓冲池名字符串，arp_tbl的该字段为"arp_cache"
	struct neigh_parms	parms;//邻居参数结构,存储一些与协议相关的可调节参数。如重传超时时间、proxy_queue队列长度等
	/* HACK. gc_* shoul follow parms without a gap! */
	int			gc_interval;//垃圾回收处理邻居项的间隔时间，默认值为30s
	int			gc_thresh1;//缓存中最少要保持多少条邻居项，如果缓存中的邻居项数少于该值，不会执行垃圾回收，arp_tbl设置为128
	int			gc_thresh2;//回收中等阈值(软上限，垃圾回收机制运行在回收前保持缓存中的邻居项超过该值5s)，arp_tbl设置为512
	int			gc_thresh3;//回收最大阈值(硬上限),一旦缓存中实际的邻居项数超过该值即执行垃圾回收，arp_tbl设置为1024
	unsigned long		last_flush;//最近回收时间，记录最近一次调用neigh_forced_gc()强制刷新邻居表的时间，用来作为是否进行垃圾回收的判断条件
	struct delayed_work	gc_work;//垃圾回收定时器
	struct timer_list 	proxy_timer;//代理定时器，处理proxy_queue队列的定时器，当proxy_queue队列为空时，第一个arp报文加入队列就会启动
	                                //该定时器，该定时器在neigh_table_init()中初始化，处理历程为neigh_proxy_process().
	struct sk_buff_head	proxy_queue;//代理队列,对于接收到的需要进行代理的ARP报文，会先将其缓存到proxy_queue队列中，在定时器处理函数
	                                //中在对其进行处理
	atomic_t		entries;//整个表中邻居结构数量，在用neigh_alloc()创建和用neigh_destroy()释放邻居项时计数
	rwlock_t		lock;//读写锁，例如neigh_lookup()只需要读邻居表，而neigh_periodic_timer()则需要读写邻居表
	unsigned long		last_rand;//最近更新时间，用于记录neigh_parms结构中reachable_time成员最近一次被更新的时间
	struct kmem_cache		*kmem_cachep;//用于分配邻居结构的高速缓存
	struct neigh_statistics	*stats;//邻居统计结构，有关邻居表中邻居项的各类统计数据
	struct neighbour	**hash_buckets;//邻居结构的哈希桶，如果邻居项数超出散列表容量，可动态扩容
	unsigned int		hash_mask;//哈希桶的长度，邻居散列表桶数减1，以方便用来计算关键字
	__u32			hash_rnd;//随机数，用来在hash_buckets散列表扩容时计算关键字，以免受到ARP攻击
	struct pneigh_entry	**phash_buckets;//保存IP地址的队列(目的代理)，在neigh_table_no_netlink()中完成初始化
};

/* flags for neigh_update() */
//指当前的L2地址可以被lladdr覆盖。管理型改变使用这个标识来区分replace和add命令。协议代码可以使用这个标识来给一个L2地址设置一个最小生存期。
#define NEIGH_UPDATE_F_OVERRIDE			0x00000001
//如果输入参数中提供的链路层地址lladdr与当前已知的邻居neigh->ha的链路层地址不同，那么这个地址就是可疑的(也就是说，邻居的状态转移到NUD_STATE,
//以便出发可到达性认证)。
#define NEIGH_UPDATE_F_WEAK_OVERRIDE		0x00000002
//标识IPV6 NTF_ROUTER标识可以被覆盖。
#define NEIGH_UPDATE_F_OVERRIDE_ISROUTER	0x00000004
//标识这个邻居是个路由器。这个标识用于初始化neighbour->flags中的ipv6标识NTF_ROUTER.
#define NEIGH_UPDATE_F_ISROUTER			0x40000000
//管理性改变。意思是说改变来自用户空间命令。
#define NEIGH_UPDATE_F_ADMIN			0x80000000

extern void			neigh_table_init(struct neigh_table *tbl);
extern void			neigh_table_init_no_netlink(struct neigh_table *tbl);
extern int			neigh_table_clear(struct neigh_table *tbl);
extern struct neighbour *	neigh_lookup(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern struct neighbour *	neigh_lookup_nodev(struct neigh_table *tbl,
						   struct net *net,
						   const void *pkey);
extern struct neighbour *	neigh_create(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern void			neigh_destroy(struct neighbour *neigh);
extern int			__neigh_event_send(struct neighbour *neigh, struct sk_buff *skb);
extern int			neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new, 
					     u32 flags);
extern void			neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_resolve_output(struct sk_buff *skb);
extern int			neigh_connected_output(struct sk_buff *skb);
extern int			neigh_compat_output(struct sk_buff *skb);
extern struct neighbour 	*neigh_event_ns(struct neigh_table *tbl,
						u8 *lladdr, void *saddr,
						struct net_device *dev);

extern struct neigh_parms	*neigh_parms_alloc(struct net_device *dev, struct neigh_table *tbl);
extern void			neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms);

static inline
struct net			*neigh_parms_net(const struct neigh_parms *parms)
{
	return read_pnet(&parms->net);
}

extern unsigned long		neigh_rand_reach_time(unsigned long base);

extern void			pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
					       struct sk_buff *skb);
extern struct pneigh_entry	*pneigh_lookup(struct neigh_table *tbl, struct net *net, const void *key, struct net_device *dev, int creat);
extern struct pneigh_entry	*__pneigh_lookup(struct neigh_table *tbl,
						 struct net *net,
						 const void *key,
						 struct net_device *dev);
extern int			pneigh_delete(struct neigh_table *tbl, struct net *net, const void *key, struct net_device *dev);

static inline
struct net			*pneigh_net(const struct pneigh_entry *pneigh)
{
	return read_pnet(&pneigh->net);
}

extern void neigh_app_ns(struct neighbour *n);
extern void neigh_for_each(struct neigh_table *tbl, void (*cb)(struct neighbour *, void *), void *cookie);
extern void __neigh_for_each_release(struct neigh_table *tbl, int (*cb)(struct neighbour *));
extern void pneigh_for_each(struct neigh_table *tbl, void (*cb)(struct pneigh_entry *));

struct neigh_seq_state {
	struct seq_net_private p;
	struct neigh_table *tbl;
	void *(*neigh_sub_iter)(struct neigh_seq_state *state,
				struct neighbour *n, loff_t *pos);
	unsigned int bucket;
	unsigned int flags;
#define NEIGH_SEQ_NEIGH_ONLY	0x00000001
#define NEIGH_SEQ_IS_PNEIGH	0x00000002
#define NEIGH_SEQ_SKIP_NOARP	0x00000004
};
extern void *neigh_seq_start(struct seq_file *, loff_t *, struct neigh_table *, unsigned int);
extern void *neigh_seq_next(struct seq_file *, void *, loff_t *);
extern void neigh_seq_stop(struct seq_file *, void *);

extern int			neigh_sysctl_register(struct net_device *dev, 
						      struct neigh_parms *p,
						      int p_id, int pdev_id,
						      char *p_name,
						      proc_handler *proc_handler,
						      ctl_handler *strategy);
extern void			neigh_sysctl_unregister(struct neigh_parms *p);

static inline void __neigh_parms_put(struct neigh_parms *parms)
{
	atomic_dec(&parms->refcnt);
}

static inline struct neigh_parms *neigh_parms_clone(struct neigh_parms *parms)
{
	atomic_inc(&parms->refcnt);
	return parms;
}

/*
 *	Neighbour references
 */
/*
* 只有此函数才调用实际执行删除任务的函数neigh_destroy，每次对一个结构的引用释放后，就调用以此neigh_release函数
* 它将改机构的引用计数器减1。当引用计数器变为0时，neigh_release就调用neigh_destroy函数来真正删除该结构.
*/
static inline void neigh_release(struct neighbour *neigh)
{
	if (atomic_dec_and_test(&neigh->refcnt))
		neigh_destroy(neigh);
}

static inline struct neighbour * neigh_clone(struct neighbour *neigh)
{
	if (neigh)
		atomic_inc(&neigh->refcnt);
	return neigh;
}

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)

static inline void neigh_confirm(struct neighbour *neigh)
{
	if (neigh)
		neigh->confirmed = jiffies;
}

/*
 neigh_event_send()用于检测邻居项状态是否有效，如果邻居项状态为NUD_CONNECTED、NUD_DELAY或NUD_PROBE，
 可以直接发送，因此返回0表示有效；否则调用__neigh_event_send()作进一步检测，如果无效则放弃报文。

 * 在这个过程中，由于邻居结构是新创建的，我们需要特别注意:它的状态被设置为NUD_NONE初始状态(neigh_alloc()函数),
 * 这里以新建的邻居结构来看neigh_evnt_send()函数如何处理
 * neigh_event_send -> __neigh_event_send
 * 只处理nud_state在NUD_NONE, NUD_STALE, NUD_INCOMPLETE状态时的情况：
*/
static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	neigh->used = jiffies;//首先记录当前的使用时间
	//检查邻居结构是否处于连接、延迟、探测状态
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);//此时邻居结构为空闲状态，因此转入此函数
	return 0;
}

static inline int neigh_hh_output(struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned seq;
	int hh_len;

	do {
		int hh_alen;

		seq = read_seqbegin(&hh->hh_lock);
		hh_len = hh->hh_len;
		hh_alen = HH_DATA_ALIGN(hh_len);
		memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
	} while (read_seqretry(&hh->hh_lock, seq));

	skb_push(skb, hh_len);
	return hh->hh_output(skb);
}

/*
 * 该函数用neigh_lookup包裹。当查找失败和该函数的输入参数中设置了create标识时，该函数就使用neigh_create函数来建立一个neighbour项。
*/
static inline struct neighbour *
__neigh_lookup(struct neigh_table *tbl, const void *pkey, struct net_device *dev, int creat)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n || !creat)
		return n;

	n = neigh_create(tbl, pkey, dev);
	return IS_ERR(n) ? NULL : n;
}

/*
 * 该函数使用neigh_lookup函数来查看要查找的邻居项是否存在，并且当查找失败时，总是创建一个新的neighbour实例。
 * 除了不需要输入creat标识外，该函数基本上和__neigh_lookup函数相同。
 * 第一个参数:邻居表结构arp_tbl
 * 第二个参数:路由网关地址
 * 第三个参数:网络设备
*/
static inline struct neighbour *
__neigh_lookup_errno(struct neigh_table *tbl, const void *pkey,
  struct net_device *dev)
{
	/*根据下一跳ip地址和输出dev查找对应的邻居表项，如果查找到(之前查找过)则直接返回*/
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n)//找到了邻居结构就返回给上一级函数
		return n;

	
	return neigh_create(tbl, pkey, dev);//如果没有查找到则创建对应的邻居表项
}

struct neighbour_cb {
	unsigned long sched_next;
	unsigned int flags;
};

#define LOCALLY_ENQUEUED 0x1

#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)

#endif
