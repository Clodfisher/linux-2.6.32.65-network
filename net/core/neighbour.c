/*
 *	Generic address resolution entity
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 *	Fixes:
 *	Vitaly E. Lavrov	releasing NULL neighbor in neigh_add.
 *	Harald Welte		Add neighbour cache statistics like rtstat
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif
#include <linux/times.h>
#include <net/net_namespace.h>
#include <net/neighbour.h>
#include <net/dst.h>
#include <net/sock.h>
#include <net/netevent.h>
#include <net/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/log2.h>

#define NEIGH_DEBUG 1

#define NEIGH_PRINTK(x...) printk(x)
#define NEIGH_NOPRINTK(x...) do { ; } while(0)
#define NEIGH_PRINTK0 NEIGH_PRINTK
#define NEIGH_PRINTK1 NEIGH_NOPRINTK
#define NEIGH_PRINTK2 NEIGH_NOPRINTK

#if NEIGH_DEBUG >= 1
#undef NEIGH_PRINTK1
#define NEIGH_PRINTK1 NEIGH_PRINTK
#endif
#if NEIGH_DEBUG >= 2
#undef NEIGH_PRINTK2
#define NEIGH_PRINTK2 NEIGH_PRINTK
#endif

#define PNEIGH_HASHMASK		0xF

static void neigh_timer_handler(unsigned long arg);
static void __neigh_notify(struct neighbour *n, int type, int flags);
static void neigh_update_notify(struct neighbour *neigh);
static int pneigh_ifdown(struct neigh_table *tbl, struct net_device *dev);

static struct neigh_table *neigh_tables;
#ifdef CONFIG_PROC_FS
static const struct file_operations neigh_stat_seq_fops;
#endif

/*
   Neighbour hash table buckets are protected with rwlock tbl->lock.

   - All the scans/updates to hash buckets MUST be made under this lock.
   - NOTHING clever should be made under this lock: no callbacks
     to protocol backends, no attempts to send something to network.
     It will result in deadlocks, if backend/driver wants to use neighbour
     cache.
   - If the entry requires some non-trivial actions, increase
     its reference count and release table lock.

   Neighbour entries are protected:
   - with reference count.
   - with rwlock neigh->lock

   Reference count prevents destruction.

   neigh->lock mainly serializes ll address data and its validity state.
   However, the same lock is used to protect another entry fields:
    - timer
    - resolution queue

   Again, nothing clever shall be made under neigh->lock,
   the most complicated procedure, which we allow is dev->hard_header.
   It is supposed, that dev->hard_header is simplistic and does
   not make callbacks to neighbour tables.

   The last lock is neigh_tbl_lock. It is pure SMP lock, protecting
   list of neighbour tables. This list is used only in process context,
 */

static DEFINE_RWLOCK(neigh_tbl_lock);

/*
 * 该函数用于处理neighbour结构不能删除的临时情况，因为有人仍然要调用这个neighbour结构。函数neigh_blackhole会丢弃在输入接口
 * 上接收的任何封包。为了确保任何试图给邻居传送封包的行为不会发生,这样处理是必需的。因为邻居的数据结构件要被删除。
*/
static int neigh_blackhole(struct sk_buff *skb)
{
	kfree_skb(skb);
	return -ENETDOWN;
}

static void neigh_cleanup_and_release(struct neighbour *neigh)
{
	if (neigh->parms->neigh_cleanup)
		neigh->parms->neigh_cleanup(neigh);

	__neigh_notify(neigh, RTM_DELNEIGH, 0);
	neigh_release(neigh);
}

/*
 * It is random distribution in the interval (1/2)*base...(3/2)*base.
 * It corresponds to default IPv6 settings and is not overridable,
 * because it is really reasonable choice.
 * 它是在间隔（1/2）* base ...（3/2）* base中的随机分布。 它对应于默认的IPv6设置，并不是可以覆盖的，因为它是真正合理的选择。
 */

unsigned long neigh_rand_reach_time(unsigned long base)
{
	return (base ? (net_random() % base) + (base >> 1) : 0);
}
EXPORT_SYMBOL(neigh_rand_reach_time);

/*
 * 该函数会删除缓存hash表中所有的符合条件的元素。同时满足一下两个条件:
 * 1.引用计数值为1，表示没有函数或结构使用该元素，而且删除该元素不影响保持剩余引用的子系统。
 * 2.该元素不是NUD_PERMANENT态。在该状态的元素是静态配置的，因此不会过期。
*/
static int neigh_forced_gc(struct neigh_table *tbl)
{
	int shrunk = 0;
	int i;

	NEIGH_CACHE_STAT_INC(tbl, forced_gc_runs);

	/* 在同步清理时，会遍历所有的邻居项(而不像异步回收时，只搜索散列表的一个桶)，将引用计数为1且非静态的邻居项全部清除。
	   最后返回是否执行了清理的标志，若返回值为1表示执行了清理，0表示没有清理邻居项。
	*/
	write_lock_bh(&tbl->lock);
	for (i = 0; i <= tbl->hash_mask; i++) {
		struct neighbour *n, **np;

		np = &tbl->hash_buckets[i];
		while ((n = *np) != NULL) {
			/* Neighbour record may be discarded if:
			 * - nobody refers to it.
			 * - it is not permanent
			 */
			write_lock(&n->lock);
			if (atomic_read(&n->refcnt) == 1 &&
			    !(n->nud_state & NUD_PERMANENT)) {
				*np	= n->next;
				n->dead = 1;
				shrunk	= 1;
				write_unlock(&n->lock);
				neigh_cleanup_and_release(n);
				continue;
			}
			write_unlock(&n->lock);
			np = &n->next;
		}
	}

	tbl->last_flush = jiffies;

	write_unlock_bh(&tbl->lock);

	return shrunk;
}

static void neigh_add_timer(struct neighbour *n, unsigned long when)
{
	neigh_hold(n);//递增邻居结构的使用计数
	/*
	 * 定时器链入队列会立即执行定时函数，这个定时器是在前面neigh_alloc()函数设置的,其定时执行函数为neigh_timer_handler()
	 * 基本任务是检测邻居结构的时间，并调整它的状态。
	*/
	if (unlikely(mod_timer(&n->timer, when))) {//设置定时器的定时执行时间链入定时队列
		printk("NEIGH: BUG, double timer add, state is %x\n",
		       n->nud_state);
		dump_stack();
	}
}

static int neigh_del_timer(struct neighbour *n)
{
	if ((n->nud_state & NUD_IN_TIMER) &&
	    del_timer(&n->timer)) {
		neigh_release(n);
		return 1;
	}
	return 0;
}

static void pneigh_queue_purge(struct sk_buff_head *list)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(list)) != NULL) {
		dev_put(skb->dev);
		kfree_skb(skb);
	}
}

static void neigh_flush_dev(struct neigh_table *tbl, struct net_device *dev)
{
	int i;

	for (i = 0; i <= tbl->hash_mask; i++) {
		struct neighbour *n, **np = &tbl->hash_buckets[i];

		while ((n = *np) != NULL) {
			if (dev && n->dev != dev) {
				np = &n->next;
				continue;
			}
			*np = n->next;
			write_lock(&n->lock);
			neigh_del_timer(n);
			n->dead = 1;

			if (atomic_read(&n->refcnt) != 1) {
				/* The most unpleasant situation.
				   We must destroy neighbour entry,
				   but someone still uses it.

				   The destroy will be delayed until
				   the last user releases us, but
				   we must kill timers etc. and move
				   it to safe state.
				 */
				__skb_queue_purge(&n->arp_queue);
				n->output = neigh_blackhole;
				if (n->nud_state & NUD_VALID)
					n->nud_state = NUD_NOARP;
				else
					n->nud_state = NUD_NONE;
				NEIGH_PRINTK2("neigh %p is stray.\n", n);
			}
			write_unlock(&n->lock);
			neigh_cleanup_and_release(n);
		}
	}
}

/*
 * 当类似的ip link set eth0 lladdr 01:02:03:04:05:06命令调用neigh_changeaddr函数改变地址时，这个函数会扫描协议缓存中
 * 的所有项，并将与要改变地址的设备相关的项标记为停用(dead)。垃圾回收进程负责处理这些停用项。
*/
void neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev)
{
	write_lock_bh(&tbl->lock);
	neigh_flush_dev(tbl, dev);
	write_unlock_bh(&tbl->lock);
}
EXPORT_SYMBOL(neigh_changeaddr);

/* 一、作用:
 * 邻居子系统维护的邻居项中，不管什么时候只要邻居项中有一个主要元素(L3地址，L2地址或接口设备)变化了，那么该项也就失效了。
 * 此时，内核必须确保邻居协议能够指导这些信息是否发生变化。
 * 其他的内核子系统要调用该函数，以通知邻居子系统有关设备和L3地址的变化。
 * L3地址改变的通知由L3协议送出。
 * 二、能生产邻居洗衣感兴趣的外部世界的行为和函数如下所示:
 * 1.设备关闭:每个邻居项都与一个设备相关联。因此，如果该设备停止运行了，那么所有与之相关的邻居项都要被删除。
 * 2.L3地址改变:如果管理员改变了接口配置，以前通过该接口可到达的主机有可能通过它已无法到达。改变接口的L3地址触发neigh_ifdown函数。
 * 3.协议关闭:如果作为模块安装的L3协议从内核中卸载了，那么所有相关的连接项件不再有用，必须要删除。
 * 三、函数对neighbour结构上要执行的动作:
 *     他会浏览所有的neighbour结构，找到与触发事件的设备相关的结构，然后使其不再可用，不会立即删除，因为邻居子系统内可能仍引用。
 *     在neigh_ifdown把缓存中的与有问题的设备相关的项清理掉之后，就调用pneigh_ifdown清理代理缓存和代理服务器的proxy_queue队列中的相关项.
 * 1.停止所有未决的定时器。
 * 2.将相关邻居项的状态改为NUD_NOARP态，这样试图使用该邻居项的任何流量不再会触发solicitation请求。
 * 3.使用neigh->output指向neigh_blackhole，以便丢弃送到该邻居的封包而不是将其提交。
 * 4.调用skb_queue_purge,将所有在arp_queue队列中待处理的封包丢弃。
*/
int neigh_ifdown(struct neigh_table *tbl, struct net_device *dev)
{
	write_lock_bh(&tbl->lock);
	neigh_flush_dev(tbl, dev);
	pneigh_ifdown(tbl, dev);
	write_unlock_bh(&tbl->lock);

	del_timer_sync(&tbl->proxy_timer);
	pneigh_queue_purge(&tbl->proxy_queue);
	return 0;
}
EXPORT_SYMBOL(neigh_ifdown);
/*
 * 该函数用于分配新的neighbour数据存储空间,该函数也用于初始化一些参数，例如，嵌入的定时器，引用计数器，指向关联的neigh_table(邻居协议)
 * 结构的指针和对分配的neighbour结构数目的整体统计。此函数使用邻居子系统初始化时建立的内存池。如果当前分配的邻居结构数目大于配置的阈值，
 * 并且接下来的垃圾回收器试图释放某块内存失败了，该函数就无法完成分配。
 * 参数为tbl:待分配邻居项所在的邻居表
*/
static struct neighbour *neigh_alloc(struct neigh_table *tbl)
{
	struct neighbour *n = NULL;
	unsigned long now = jiffies;
	int entries;

	/* time_after()函数检测最后一次回收到现在的实际间隔，如果需要回收就启动neigh_forced_gc()函数，
	 * 依据邻居结构的使用计数和状态进行回收
	*/
	entries = atomic_inc_return(&tbl->entries) - 1;//获取邻居结构数量
	if (entries >= tbl->gc_thresh3 ||
	    (entries >= tbl->gc_thresh2 &&
	     time_after(now, tbl->last_flush + 5 * HZ))) {//检测是否需要回收:前者的时间戳大于后者的时间戳 b-a<0
		if (!neigh_forced_gc(tbl) &&//启动同步垃圾回收
		    entries >= tbl->gc_thresh3)//回收后数量仍然超过最大阈值
			goto out_entries;
	}

    //在邻居表指定的高速缓存中分配结构空间
	n = kmem_cache_zalloc(tbl->kmem_cachep, GFP_ATOMIC);
	if (!n)
		goto out_entries;

	__skb_queue_head_init(&n->arp_queue);//初始化邻居结构的队列头(存储需要处理的封包)
	rwlock_init(&n->lock);
	n->updated	  = n->used = now;//记录当前时间
	n->nud_state	  = NUD_NONE;//设置状态
	n->output	  = neigh_blackhole;//设置发送函数
	n->parms	  = neigh_parms_clone(&tbl->parms);//记录邻居参数结构
	setup_timer(&n->timer, neigh_timer_handler, (unsigned long)n);//初始化定时器，定时器函数为neigh_timer_handler
	/*
	setup_timer 调用/include/linux/time.h中函数
	static inline void setup_timer_key(struct timer_list * timer,
				const char *name,
				struct lock_class_key *key,
				void (*function)(unsigned long),
				unsigned long data)
{
	timer->function = function;        //记录邻居结构的定时执行函数neigh_timer_handler()
	timer->data = data;                //记录邻居结构的地址
	init_timer_key(timer, name, key);  //初始化定时器
}
    这里只是初始化了定时器，并没有将它链入内核的定时器执行队列，因此初始化后还会执行定时函数neigh_timer_handler(),
    在后面__neigh_event_send()函数的过程中看到这个定时器的启动
	*/

	NEIGH_CACHE_STAT_INC(tbl, allocs);//递增分配计数器
	n->tbl		  = tbl;//记录邻居表
	atomic_set(&n->refcnt, 1);//设置使用计数
	n->dead		  = 1;//初始删除标志
out:
	return n;

out_entries:
	atomic_dec(&tbl->entries);//递减邻居结构计数器
	goto out;
}

static struct neighbour **neigh_hash_alloc(unsigned int entries)
{
	unsigned long size = entries * sizeof(struct neighbour *);
	struct neighbour **ret;

	if (size <= PAGE_SIZE) {
		ret = kzalloc(size, GFP_ATOMIC);
	} else {
		ret = (struct neighbour **)
		      __get_free_pages(GFP_ATOMIC|__GFP_ZERO, get_order(size));
	}
	return ret;
}

static void neigh_hash_free(struct neighbour **hash, unsigned int entries)
{
	unsigned long size = entries * sizeof(struct neighbour *);

	if (size <= PAGE_SIZE)
		kfree(hash);
	else
		free_pages((unsigned long)hash, get_order(size));
}

/*
函数原型：
static void neigh_hash_grow(struct neigh_table *tbl, unsigned long new_entries)
作用：
在创建邻居项时，如果在计入要创建的邻居项后，邻居表邻居项的计数超过了邻居散列表的容量，就会调用neigh_hash_grow()扩容邻居散列表。
参数：
tbl,待扩容邻居项散列表所属的邻居表，ARP中的arp_tbl
new_entries,扩容后邻居散列表的容量

*/
static void neigh_hash_grow(struct neigh_table *tbl, unsigned long new_entries)
{
	struct neighbour **new_hash, **old_hash;
	unsigned int i, new_hash_mask, old_entries;

	NEIGH_CACHE_STAT_INC(tbl, hash_grows);

	BUG_ON(!is_power_of_2(new_entries));
	/*
	调用neigh_hash_alloc()为邻居项散列表重新分配内存，在该函数中，根据待分配的内存量大于PAGE_SIZE与否来确定使用
	kzalloc()或是get_free_pages()分配内存
	*/
	new_hash = neigh_hash_alloc(new_entries);
	if (!new_hash)
		return;

	old_entries = tbl->hash_mask + 1;
	new_hash_mask = new_entries - 1;
	old_hash = tbl->hash_buckets;

	get_random_bytes(&tbl->hash_rnd, sizeof(tbl->hash_rnd));//重新计算随机值hash_rand
	/*
	先将原先邻居项散列表中的邻居项移动到扩容后的邻居项散列表中，然后将新散列项列表及其hash_mask保存到邻居表中
	*/
	for (i = 0; i < old_entries; i++) {
		struct neighbour *n, *next;

		for (n = old_hash[i]; n; n = next) {
			unsigned int hash_val = tbl->hash(n->primary_key, n->dev);

			hash_val &= new_hash_mask;
			next = n->next;

			n->next = new_hash[hash_val];//在相应的散列桶中的队列首部添加
			new_hash[hash_val] = n;
		}
	}
	tbl->hash_buckets = new_hash;
	tbl->hash_mask = new_hash_mask;

	neigh_hash_free(old_hash, old_entries);//调用neigh_hash_free()释放旧邻居散列表所占用的内存
}
/*
 * 该函数会在arp_tbl中检查要查找的元素(网关和设备)是否存在，并且在查找成功时返回指向该元素的指针。
作用：
邻居项的查找非常频繁：添加邻居项时需要查找邻居项是否已存在；删除邻居项时需要查找待删除的邻居项是否存在。
参数：
tbl，为待查找的邻居表
pkey和dev,是查找条件，即三层协议地址和邻居项的输出设备
*/
struct neighbour *neigh_lookup(struct neigh_table *tbl, const void *pkey,
			       struct net_device *dev)
{
	struct neighbour *n;
	int key_len = tbl->key_len;//取得地址长度
	u32 hash_val;

	NEIGH_CACHE_STAT_INC(tbl, lookups);//递增查找邻居表计数器

	read_lock_bh(&tbl->lock);
	hash_val = tbl->hash(pkey, dev);//调用邻居表中的哈希运算函数确定哈希值
	//在哈希桶中查找指定设备、指定网关的邻居结构
	for (n = tbl->hash_buckets[hash_val & tbl->hash_mask]; n; n = n->next) {
		if (dev == n->dev && !memcmp(n->primary_key, pkey, key_len)) {
			neigh_hold(n);//递增邻居结构的计数器
			NEIGH_CACHE_STAT_INC(tbl, hits);//递增邻居表的命中计数器
			break;
		}
	}
	read_unlock_bh(&tbl->lock);
	return n;//返还找到的邻居结构
}
EXPORT_SYMBOL(neigh_lookup);

struct neighbour *neigh_lookup_nodev(struct neigh_table *tbl, struct net *net,
				     const void *pkey)
{
	struct neighbour *n;
	int key_len = tbl->key_len;
	u32 hash_val;

	NEIGH_CACHE_STAT_INC(tbl, lookups);

	read_lock_bh(&tbl->lock);
	hash_val = tbl->hash(pkey, NULL);
	for (n = tbl->hash_buckets[hash_val & tbl->hash_mask]; n; n = n->next) {
		if (!memcmp(n->primary_key, pkey, key_len) &&
		    net_eq(dev_net(n->dev), net)) {
			neigh_hold(n);
			NEIGH_CACHE_STAT_INC(tbl, hits);
			break;
		}
	}
	read_unlock_bh(&tbl->lock);
	return n;
}
EXPORT_SYMBOL(neigh_lookup_nodev);

/**
*作用:用来完整地创建一个邻居项，并将其添加到散列表上，最后返回指向该邻居项的指针
*tbl: 待创建邻居表项所属的邻居表,在ARP中为arp_tbl
*pkey: 下一跳三层协议地址，作为邻居表项的关键字
*dev: 该邻居表项的输出设备,与要创建的邻居项相关的设备。因为每个neighbour项都与一个L3地址相关联，并且后者总是与一个设备相关联，
*     所以neighbour实例就与一个设备相关联。
**/
struct neighbour *neigh_create(struct neigh_table *tbl, const void *pkey,
			       struct net_device *dev)
{
	u32 hash_val;
	int key_len = tbl->key_len;//取得IP地址长度作为键值
	int error;
	/*
	首先为新的邻居表项struct neighbour分配空间，并做一些初始化。
	传入的参数tbl就是全局量arp_tbl，分配空间的大小是tbl->entry_size，
	而这个值在声明arp_tbl时初始化为sizeof(struct neighbour) + 4，多出的4个字节就是key值存放的地方。
	*/
	struct neighbour *n1, *rc, *n = neigh_alloc(tbl);/*分配一个邻居结构实例*/

	if (!n) {//分配失败返回
		rc = ERR_PTR(-ENOBUFS);
		goto out;
	}

	/*将三层地址和输出设备设置到邻居表项中*/
	memcpy(n->primary_key, pkey, key_len);//key_len必要的，因为neighbour结构是被与协议无关的缓存查找函数使用，并且各种邻居协议表示地址的字节长度不同。
	n->dev = dev;//由于neighbour项中包括了对net_device结构中dev的引用，内核会使用dev_hold来对后者的引用计数器加1，以此来保证该设备在neighbour结构存在是不会被删除。
	dev_hold(dev);//增加设备的计数器

	/* Protocol specific setup. 执行与邻居协议相关的初始化函数，结合arp_tbl结构的内容，实际执行ARP中为arp_constructor*/
	if (tbl->constructor &&	(error = tbl->constructor(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}

	/* Device specific setup. 设备执行的初始化工作由neigh_setup虚函数完成*/
	if (n->parms->neigh_setup &&//如果指定了安装函数就执行它
	    (error = n->parms->neigh_setup(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}
	
	/*将创建的邻居表项插入邻居表项hash表中*/
	//confirmed字段，表示该邻居是可到达的,正常情况下，该字段由可到达性证明来更新，并且其值设置为jiffies表示的当前时间，
	//但是这里，从新建的角度来说，neigh_create函数会把confirmed值减去一小段时间(reachable_time值的一半)，这样就使得邻居
	//状态能比平常和要求有可到达性证据时，稍快点转移到NUD_STALE态
	n->confirmed = jiffies - (n->parms->base_reachable_time << 1);//确定时间，其中jiffies为当前时间

	write_lock_bh(&tbl->lock);

    //如果邻居结构数量超过了哈希桶的长度
	if (atomic_read(&tbl->entries) > (tbl->hash_mask + 1))
		neigh_hash_grow(tbl, (tbl->hash_mask + 1) << 1);//调整哈希桶,扩增1倍

	hash_val = tbl->hash(pkey, dev) & tbl->hash_mask;//计算哈希值

	if (n->parms->dead) {//邻居配置参数正在被删除，不能再使用，因此也就不能再继续创建邻居项了
		rc = ERR_PTR(-EINVAL);
		goto out_tbl_unlock;
	}

	//在哈希桶中查找要插入的队列
	for (n1 = tbl->hash_buckets[hash_val]; n1; n1 = n1->next) {
		if (dev == n1->dev && !memcmp(n1->primary_key, pkey, key_len)) {
			neigh_hold(n1);
			rc = n1;//记录相同地址和设备的邻居结构，直接返回找到的邻居结构
			goto out_tbl_unlock;
		}
	}

	n->next = tbl->hash_buckets[hash_val];//指向队列中下一个邻居结构
	tbl->hash_buckets[hash_val] = n;//链入哈希桶
	n->dead = 0;//清除删除标志
	neigh_hold(n);//递增使用计数
	write_unlock_bh(&tbl->lock);
	NEIGH_PRINTK2("neigh %p is created.\n", n);
	rc = n;//记录新创建的邻居结构
out:
	return rc;//返回邻居结构
out_tbl_unlock:
	write_unlock_bh(&tbl->lock);
out_neigh_release:
	neigh_release(n);//找到了相同的邻居结构就释放新建的
	goto out;
}
EXPORT_SYMBOL(neigh_create);

static u32 pneigh_hash(const void *pkey, int key_len)
{
	u32 hash_val = *(u32 *)(pkey + key_len - 4);
	hash_val ^= (hash_val >> 16);
	hash_val ^= hash_val >> 8;
	hash_val ^= hash_val >> 4;
	hash_val &= PNEIGH_HASHMASK;
	return hash_val;
}

static struct pneigh_entry *__pneigh_lookup_1(struct pneigh_entry *n,
					      struct net *net,
					      const void *pkey,
					      int key_len,
					      struct net_device *dev)
{
	while (n) {
		if (!memcmp(n->key, pkey, key_len) &&
		    net_eq(pneigh_net(n), net) &&
		    (n->dev == dev || !n->dev))
			return n;
		n = n->next;
	}
	return NULL;
}

struct pneigh_entry *__pneigh_lookup(struct neigh_table *tbl,
		struct net *net, const void *pkey, struct net_device *dev)
{
	int key_len = tbl->key_len;
	u32 hash_val = pneigh_hash(pkey, key_len);

	return __pneigh_lookup_1(tbl->phash_buckets[hash_val],
				 net, pkey, key_len, dev);
}
EXPORT_SYMBOL_GPL(__pneigh_lookup);

struct pneigh_entry * pneigh_lookup(struct neigh_table *tbl,
				    struct net *net, const void *pkey,
				    struct net_device *dev, int creat)
{
	struct pneigh_entry *n;
	int key_len = tbl->key_len;
	u32 hash_val = pneigh_hash(pkey, key_len);

	read_lock_bh(&tbl->lock);
	n = __pneigh_lookup_1(tbl->phash_buckets[hash_val],
			      net, pkey, key_len, dev);
	read_unlock_bh(&tbl->lock);

	if (n || !creat)
		goto out;

	ASSERT_RTNL();

	n = kmalloc(sizeof(*n) + key_len, GFP_KERNEL);
	if (!n)
		goto out;

	write_pnet(&n->net, hold_net(net));
	memcpy(n->key, pkey, key_len);
	n->dev = dev;
	if (dev)
		dev_hold(dev);

	if (tbl->pconstructor && tbl->pconstructor(n)) {
		if (dev)
			dev_put(dev);
		release_net(net);
		kfree(n);
		n = NULL;
		goto out;
	}

	write_lock_bh(&tbl->lock);
	n->next = tbl->phash_buckets[hash_val];
	tbl->phash_buckets[hash_val] = n;
	write_unlock_bh(&tbl->lock);
out:
	return n;
}
EXPORT_SYMBOL(pneigh_lookup);


int pneigh_delete(struct neigh_table *tbl, struct net *net, const void *pkey,
		  struct net_device *dev)
{
	struct pneigh_entry *n, **np;
	int key_len = tbl->key_len;
	u32 hash_val = pneigh_hash(pkey, key_len);

	write_lock_bh(&tbl->lock);
	for (np = &tbl->phash_buckets[hash_val]; (n = *np) != NULL;
	     np = &n->next) {
		if (!memcmp(n->key, pkey, key_len) && n->dev == dev &&
		    net_eq(pneigh_net(n), net)) {
			*np = n->next;
			write_unlock_bh(&tbl->lock);
			if (tbl->pdestructor)
				tbl->pdestructor(n);
			if (n->dev)
				dev_put(n->dev);
			release_net(pneigh_net(n));
			kfree(n);
			return 0;
		}
	}
	write_unlock_bh(&tbl->lock);
	return -ENOENT;
}

static int pneigh_ifdown(struct neigh_table *tbl, struct net_device *dev)
{
	struct pneigh_entry *n, **np;
	u32 h;

	for (h = 0; h <= PNEIGH_HASHMASK; h++) {
		np = &tbl->phash_buckets[h];
		while ((n = *np) != NULL) {
			if (!dev || n->dev == dev) {
				*np = n->next;
				if (tbl->pdestructor)
					tbl->pdestructor(n);
				if (n->dev)
					dev_put(n->dev);
				release_net(pneigh_net(n));
				kfree(n);
				continue;
			}
			np = &n->next;
		}
	}
	return -ENOENT;
}

static void neigh_parms_destroy(struct neigh_parms *parms);

static inline void neigh_parms_put(struct neigh_parms *parms)
{
	if (atomic_dec_and_test(&parms->refcnt))
		neigh_parms_destroy(parms);
}

/*
 *	neighbour must already be out of the table;
 *  删除邻居结构的函数，要做的事情如下:
 *  1.停止所有未决的定时器。
 *  2.释放所有对外部数据结构的引用，例如关联的设备及缓存的L2帧头.
 *  3.如果一个邻居协议提供了destructor方法，该邻居协议就会执行这个方法自己清理邻居项。
 *  4.如果arp_queue队列非空，就要将其清空(删除其所有元素)。
 *  5.将表示主机使用的neighbour项总数的全局计数器减1.
 *  6.是否该neighbour结构(将其占用的内存空间返还给内存池)。
 */
void neigh_destroy(struct neighbour *neigh)
{
	struct hh_cache *hh;

	NEIGH_CACHE_STAT_INC(neigh->tbl, destroys);

	if (!neigh->dead) {
		printk(KERN_WARNING
		       "Destroying alive neighbour %p\n", neigh);
		dump_stack();
		return;
	}

	if (neigh_del_timer(neigh))
		printk(KERN_WARNING "Impossible event.\n");

	while ((hh = neigh->hh) != NULL) {
		neigh->hh = hh->hh_next;
		hh->hh_next = NULL;

		write_seqlock_bh(&hh->hh_lock);
		hh->hh_output = neigh_blackhole;
		write_sequnlock_bh(&hh->hh_lock);
		if (atomic_dec_and_test(&hh->hh_refcnt))
			kfree(hh);
	}

	write_lock_bh(&neigh->lock);
	__skb_queue_purge(&neigh->arp_queue);
	write_unlock_bh(&neigh->lock);

	dev_put(neigh->dev);
	neigh_parms_put(neigh->parms);

	NEIGH_PRINTK2("neigh %p is destroyed.\n", neigh);

	atomic_dec(&neigh->tbl->entries);
	kmem_cache_free(neigh->tbl->kmem_cachep, neigh);
}
EXPORT_SYMBOL(neigh_destroy);

/* Neighbour state is suspicious;
   disable fast path.

   Called with write_locked neigh.
 */
static void neigh_suspect(struct neighbour *neigh)
{
	struct hh_cache *hh;

	NEIGH_PRINTK2("neigh %p is suspected.\n", neigh);

	neigh->output = neigh->ops->output;

	for (hh = neigh->hh; hh; hh = hh->hh_next)
		hh->hh_output = neigh->ops->output;
}

/* Neighbour state is OK;
   enable fast path.

   Called with write_locked neigh.
 */
static void neigh_connect(struct neighbour *neigh)
{
	struct hh_cache *hh;

	NEIGH_PRINTK2("neigh %p is connected.\n", neigh);

	neigh->output = neigh->ops->connected_output;//可以看到neigh->output被初始化为connected_output，对ARP就是neigh_connected_output

	for (hh = neigh->hh; hh; hh = hh->hh_next)
		hh->hh_output = neigh->ops->hh_output;
}

 /*
 工作队列会异步的更改NUD状态,neigh_periodic_work用于NUD_STALE
 注意neigh_timer_handler是每个表项一个的，而neigh_periodic_work是唯一的
 当neigh处于NUD_STALE状态时，此时它等待一段时间，主机引用到它，从而转入NUD_DELAY状态；
 没有引用，则转入NUD_FAIL，被释放。不同于NUD_INCOMPLETE、NUD_DELAY、NUD_PROBE、NUD_REACHABLE状态时的定时器，
 这里使用的异步机制，通过定期触发neigh_periodic_work()来检查NUD_STALE状态。
*/
static void neigh_periodic_work(struct work_struct *work)
{
	/*
	neigh_periodic_work定期执行，但要保证表项不会刚添加就被neigh_periodic_work清理掉，
	这里的策略是：gc_staletime大于1/2 base_reachable_time。默认的，gc_staletime = 30，
	base_reachable_time = 30。也就是说，neigh_periodic_work会每15HZ执行一次，
	但表项在NUD_STALE的存活时间是30HZ，这样，保证了每项在最差情况下也有(30 - 15)HZ的生命周期。
	*/
	struct neigh_table *tbl = container_of(work, struct neigh_table, gc_work.work);
	struct neighbour *n, **np;
	unsigned int i;

	NEIGH_CACHE_STAT_INC(tbl, periodic_gc_runs);

	write_lock_bh(&tbl->lock);

	/*
	 *	periodically recompute ReachableTime from random function 从随机函数定期重新计算ReachableTime
	 */
	//每300s将邻居表所有neigh_parms结构实例的NUD_REACHABLE状态超时时间reachable_time更新为一个新的随机值。
	if (time_after(jiffies, tbl->last_rand + 300 * HZ)) {
		struct neigh_parms *p;
		tbl->last_rand = jiffies;
		for (p = &tbl->parms; p; p = p->next)
			p->reachable_time =
				neigh_rand_reach_time(p->base_reachable_time);
	}

    //遍历整个邻居表，每个hash_buckets的每个表项，如果在gc_staletime内仍未被引用过，则会从邻居表中清除。
	for (i = 0 ; i <= tbl->hash_mask; i++) {
		np = &tbl->hash_buckets[i];

		while ((n = *np) != NULL) {
			unsigned int state;

			write_lock(&n->lock);

			//对于静态邻居项或处于定时器状态的邻居项不处理直接跳过
			state = n->nud_state;
			if (state & (NUD_PERMANENT | NUD_IN_TIMER)) {
				write_unlock(&n->lock);
				goto next_elt;
			}

			//如果邻居项的最后使用时间在最后确认时间之前，则调整最后使用时间为最后确认时间
			if (time_before(n->used, n->confirmed))
				n->used = n->confirmed;
			/*
				调用neigh_release()删除释放符合两种条件的邻居项:
				1.应用计数为1且状态为NUD_FAILED
				2.引用计数为1且闲置时间超过了指定上限gc_staletime
			*/
			if (atomic_read(&n->refcnt) == 1 &&
			    (state == NUD_FAILED ||
			     time_after(jiffies, n->used + n->parms->gc_staletime))) {
				*np = n->next;
				n->dead = 1;
				write_unlock(&n->lock);
				neigh_cleanup_and_release(n);
				continue;
			}
			write_unlock(&n->lock);

next_elt:
			np = &n->next;
		}
		/*
		 * It's fine to release lock here, even if hash table
		 * grows while we are preempted.
		 * 在这里释放锁定是正确的，即使哈希表在我们被抢占的时候增长。
		 */
		write_unlock_bh(&tbl->lock);
		cond_resched();
		write_lock_bh(&tbl->lock);
	}
	/* Cycle through all hash buckets every base_reachable_time/2 ticks.
	 * ARP entry timeouts range from 1/2 base_reachable_time to 3/2
	 * base_reachable_time.
	 */
	// 在工作最后，再次添加该工作到队列中，并延时1/2 base_reachable_time开始执行，
	// 这样，完成了neigh_periodic_work工作每隔1/2 base_reachable_time执行一次。
	schedule_delayed_work(&tbl->gc_work,
			      tbl->parms.base_reachable_time >> 1);
	write_unlock_bh(&tbl->lock);
}

static __inline__ int neigh_max_probes(struct neighbour *n)
{
	struct neigh_parms *p = n->parms;
	return (n->nud_state & NUD_PROBE ?
		p->ucast_probes :
		p->ucast_probes + p->app_probes + p->mcast_probes);
}

static void neigh_invalidate(struct neighbour *neigh)
{
	struct sk_buff *skb;

	NEIGH_CACHE_STAT_INC(neigh->tbl, res_failed);
	NEIGH_PRINTK2("neigh %p is failed.\n", neigh);
	neigh->updated = jiffies;

	/* It is very thin place. report_unreachable is very complicated
	   routine. Particularly, it can hit the same neighbour entry!

	   So that, we try to be accurate and avoid dead loop. --ANK
	 */
	while (neigh->nud_state == NUD_FAILED &&
	       (skb = __skb_dequeue(&neigh->arp_queue)) != NULL) {
		write_unlock(&neigh->lock);
		neigh->ops->error_report(neigh, skb);
		write_lock(&neigh->lock);
	}
	__skb_queue_purge(&neigh->arp_queue);
}

/* Called when a timer expires for a neighbour entry. */
/*
 * 其中neigh_timer_handler定时器、neigh_periodic_work工作队列会异步的更改NUD状态，
 * neigh_timer_handler用于NUD_INCOMPLETE, NUD_DELAY, NUD_PROBE, NUD_REACHABLE状态；
 * neigh_periodic_work用于NUD_STALE。注意neigh_timer_handler是每个表项一个的，
 * 而neigh_periodic_work是唯一的，NUD_STALE状态的表项没必要单独使用定时器，
 * 定期检查过期就可以了，这样大大节省了资源
 *
 邻居项各个状态中，有些属于定时状态，对于这些状态其转变由定时器处理函数来处理。
 每个邻居项都有一个定时器，该定时器在创建邻居项时被初始化，它的处理函数为neigh_timer_handler()。
*/
static void neigh_timer_handler(unsigned long arg)
{
	unsigned long now, next;
	struct neighbour *neigh = (struct neighbour *)arg;
	unsigned state;
	int notify = 0;

	write_lock(&neigh->lock);

	state = neigh->nud_state;
	now = jiffies;
	next = now + HZ;

	//不处理那些不处于定时状态的邻居项
	if (!(state & NUD_IN_TIMER)) {//定时器状态，与定时器有关的状态:NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE
#ifndef CONFIG_SMP
		printk(KERN_WARNING "neigh: timer & !nud_in_timer\n");
#endif
		goto out;
	}

	if (state & NUD_REACHABLE) {
		if (time_before_eq(now,
				   neigh->confirmed + neigh->parms->reachable_time)) {
			//如果超时，但期间收到对方的报文，不更改状态，并重置超时时间为neigh->confirmed+reachable_time
			NEIGH_PRINTK2("neigh %p is still alive.\n", neigh);
			next = neigh->confirmed + neigh->parms->reachable_time;
		} else if (time_before_eq(now,
					  neigh->used + neigh->parms->delay_probe_time)) {
		    //如果超时，期间未收到对方报文，但主机使用过该项，则迁移至NUD_DELAY状态，
		    //并重置超时时间为neigh->used+delay_probe_time
			NEIGH_PRINTK2("neigh %p is delayed.\n", neigh);
			neigh->nud_state = NUD_DELAY;
			neigh->updated = jiffies;
			neigh_suspect(neigh);
			next = now + neigh->parms->delay_probe_time;
		} else {
		    //如果超时，且既未收到对方报文，也未使用过该项，则怀疑该项可能不可用了，
		    //迁移至NUD_STALE状态，而不是立即删除，neigh_periodic_work()会定时的清除NUD_STALE状态的表项。
			NEIGH_PRINTK2("neigh %p is suspected.\n", neigh);
			neigh->nud_state = NUD_STALE;
			neigh->updated = jiffies;
			neigh_suspect(neigh);
			notify = 1;
		}
	} else if (state & NUD_DELAY) {
		if (time_before_eq(now,
				   neigh->confirmed + neigh->parms->delay_probe_time)) {
		    //如果超时，期间收到对方报文，迁移至NUD_REACHABLE，记录下次检查时间到next
		    //NUD_DELAY -> NUD_REACHABLE的状态转移，在arp_process中也提到过，收到arp reply时会有表项状态
		    //NUD_DELAY -> NUD_REACHABLE。它们两者的区别在于arp_process处理的是arp的确认报文，
		    //而neigh_timer_handler处理的是4层的确认报文。
			NEIGH_PRINTK2("neigh %p is now reachable.\n", neigh);
			neigh->nud_state = NUD_REACHABLE;
			neigh->updated = jiffies;
			neigh_connect(neigh);
			notify = 1;
			next = neigh->confirmed + neigh->parms->reachable_time;
		} else {
			//如果超时，期间未收到对方的报文，迁移至NUD_PROBE，记录下次检查时间到next
			NEIGH_PRINTK2("neigh %p is probed.\n", neigh);
			neigh->nud_state = NUD_PROBE;
			neigh->updated = jiffies;
			atomic_set(&neigh->probes, 0);
			next = now + neigh->parms->retrans_time;
		}
	} else {
		/* NUD_PROBE|NUD_INCOMPLETE */
		//当neigh处于NUD_PROBE或NUD_INCOMPLETE状态时，记录下次检查时间到next，因为这两种状态需要发送ARP解析报文，
		//它们过程的迁移依赖于ARP解析的进程。
		next = now + neigh->parms->retrans_time;
	}

	/*
	 * 经过定时器超时后的状态转移，如果neigh处于NUD_PROBE或NUD_INCOMPLETE，则会发送ARP报文，
	 * 先会检查报文发送的次数，如果超过了限度，表明对方主机没有回应，则neigh进入NUD_FAILED，被释放掉。
	*/
	if ((neigh->nud_state & (NUD_INCOMPLETE | NUD_PROBE)) &&
	    atomic_read(&neigh->probes) >= neigh_max_probes(neigh)) {
		neigh->nud_state = NUD_FAILED;
		notify = 1;
		neigh_invalidate(neigh);
	}

	// 设置定时器下次到期时间
	if (neigh->nud_state & NUD_IN_TIMER) {
		if (time_before(next, jiffies + HZ/2))
			next = jiffies + HZ/2;
		if (!mod_timer(&neigh->timer, next))
			neigh_hold(neigh);
	}
	/*
	 * 如果邻居表项状态处于NUD_INCOMPLETE 或NUD_PROBE，且发送ARP请求次数未达到上限，则向邻居发送ARP请求 
     * neigh->ops->solicit在创建表项neigh时被赋值，一般是arp_solicit，并且增加探测计算neigh->probes
	*/
	if (neigh->nud_state & (NUD_INCOMPLETE | NUD_PROBE)) {
		/*根据缓存队列中的第一个�*/
		struct sk_buff *skb = skb_peek(&neigh->arp_queue);
		/* keep skb alive even if arp_queue overflows 即使arp_queue溢出，仍然保持活动 */
		if (skb)
			skb = skb_copy(skb, GFP_ATOMIC);
		write_unlock(&neigh->lock);
		neigh->ops->solicit(neigh, skb);/*发送ARP请求*///neigh->ops->solicit被初始化为arp_solicit()，用来构造和发送ARP请求。但是发送完请求后呢？
		atomic_inc(&neigh->probes);     //自然是等待ARP应答了，当收到ARP应答后，最终会调用arp_process()函数处理。
		kfree_skb(skb);
	} else {
out:
		write_unlock(&neigh->lock);
	}

	//向感兴趣的模块通知NETEVENT_NEIGH_UPDATE事件，如果编译时支持ARPD,则需通知arpd进程
	if (notify)
		neigh_update_notify(neigh);

	neigh_release(neigh);
}

/*
 *所以neigh_resolve_output的执行结果，就是1）将邻居表项置为NUD_INCOMPLETE；
 *2）将待发送的报文存入邻居表项的缓存队列。看到这里就很奇怪了，邻居表项中的mac地址还是没有找到啊，
 *再说数据包被放入邻居表项队列中去以后由谁来发送呢？
 *注意前面neigh_add_timer还启动了邻居表项的状态定时器。这个状态定时器的处理函数为neigh_timer_handler。
*/
int __neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	int rc;
	unsigned long now;

	write_lock_bh(&neigh->lock);

	rc = 0;
	/*邻居状态处于NUD_CONNECTED、NUD_DELAY或NUD_PROBE则直接返回 */
	if (neigh->nud_state & (NUD_CONNECTED | NUD_DELAY | NUD_PROBE))
		goto out_unlock_bh;//如果连接，延迟，探测状态就退出

	now = jiffies;//记录当前时间，重新设置状态前的实际

	/* 此时剩下的未考察状态为NUD_STALE 、 NUD_INCOMPLETE和UND_NONE，
	因此如果当前状态不为NUD_STALE和NUD_INCOMPLETE 则必为UND_NONE */
	if (!(neigh->nud_state & (NUD_STALE | NUD_INCOMPLETE))) {//如果不是过期状态或未完成状态
		/*如果允许发送arp广播请求报文或者允许应用程序发送请求报文来解析邻居地址，
		则将邻居项状态设置为NUD_INCOMPLETE，并启动邻居状态处理定时器*/
		/*
		 在发送ARP报文时有3个参数- ucast_probes, mcast_probes, app_probes，分别代表单播次数，
		 广播次数，app_probes比较特殊，一般情况下为0，当使用了arpd守护进程时才会设置它的值。
		 如果已经收到过对方的报文，即知道了对方的MAC-IP，ARP解析会使用单播形式，次数由ucast_probes决定；
		 如果未收到过对方报文，此时ARP解析只能使用广播形式，次数由mcasat_probes决定。
		*/
		if (neigh->parms->mcast_probes + neigh->parms->app_probes) {//检查邻居参数结构的探测值
			atomic_set(&neigh->probes, neigh->parms->ucast_probes);//记录探测值
			neigh->nud_state     = NUD_INCOMPLETE;//修改为未完成状态
			neigh->updated = jiffies;//记录当前时间，重新设置状态后的时间
			neigh_add_timer(neigh, now + 1);//设置定时器
		} else {//没有设定探测值
		/*否则邻居项只能转换为NUD_FAILED 状态，并释放待输出报文，同时返回1，标示邻居项无效，不能输出*/
			neigh->nud_state = NUD_FAILED;//修改为失败状态
			neigh->updated = jiffies;//记录当前时间，重新设置状态后的时间
			write_unlock_bh(&neigh->lock);

			kfree_skb(skb);//释放发送的数据包
			return 1;
		}
	} else if (neigh->nud_state & NUD_STALE) {//如果是过期状态
		/*
		如果邻居项当前状态为NUD_STALE,由于有报文输出了，因此状态转变为NUD_DELAY,并设置邻居状态处理定时器。
		状态NUD_DELAY表示可以输出，因此也返回0
		*/
		NEIGH_PRINTK2("neigh %p is delayed.\n", neigh);
		neigh->nud_state = NUD_DELAY;//修改为延迟状态
		neigh->updated = jiffies;//记录当前时间，重新设置状态后的时间
		neigh_add_timer(neigh,
				jiffies + neigh->parms->delay_probe_time);//设置定时器
	}

    /* 
    如果邻居项当前状态为NUD_INCOMPLETE，说明请求报文已经发送，但尚未收到应答。此时如果请求缓存队列长度还未达到上限，
	则将待输出报文缓存到该队列中，否则只能丢弃该报文。无论是那种情况都返回1，表示还不能发送报文	
    */
	if (neigh->nud_state == NUD_INCOMPLETE) {//如果是未完成状态
		if (skb) {//需要发送数据包
			/*如果请求缓存项队列长度还未达到上限，则将待输出报文缓存到队列中，否则只能丢弃该报文。
			  无论那种情况都返回1，表示还不能发送报文*/
			if (skb_queue_len(&neigh->arp_queue) >=
			    neigh->parms->queue_len) {//检测队列长度，是否大于设置值
				struct sk_buff *buff;
				buff = __skb_dequeue(&neigh->arp_queue);//取出不能完成的数据包，从队列中脱链
				kfree_skb(buff);//释放数据包
				NEIGH_CACHE_STAT_INC(neigh->tbl, unres_discards);
			}
			__skb_queue_tail(&neigh->arp_queue, skb);//每一个neighbour项都有它自己的一个小的、私有的arp_queue队列。将发送数据包链入队列
		}
		rc = 1;
	}
out_unlock_bh:
	write_unlock_bh(&neigh->lock);
	return rc;
}
EXPORT_SYMBOL(__neigh_event_send);

static void neigh_update_hhs(struct neighbour *neigh)
{
	struct hh_cache *hh;
	void (*update)(struct hh_cache*, const struct net_device*, const unsigned char *)
		= NULL;

	if (neigh->dev->header_ops)
		update = neigh->dev->header_ops->cache_update;

	if (update) {
		for (hh = neigh->hh; hh; hh = hh->hh_next) {
			write_seqlock_bh(&hh->hh_lock);
			update(hh, neigh->dev, neigh->ha);
			write_sequnlock_bh(&hh->hh_lock);
		}
	}
}



/* Generic update routine.
   -- lladdr is new lladdr or NULL, if it is not supplied.
   -- new    is new state.
   -- flags
	NEIGH_UPDATE_F_OVERRIDE allows to override existing lladdr,
				if it is different.
	NEIGH_UPDATE_F_WEAK_OVERRIDE will suspect existing "connected"
				lladdr instead of overriding it
				if it is different.
				It also allows to retain current state
				if lladdr is unchanged.
	NEIGH_UPDATE_F_ADMIN	means that the change is administrative.

	NEIGH_UPDATE_F_OVERRIDE_ISROUTER allows to override existing
				NTF_ROUTER flag.
	NEIGH_UPDATE_F_ISROUTER	indicates if the neighbour is known as
				a router.

   Caller MUST hold reference count on the entry.
 */
 /*
  * 用于更新neighbour结构链路层地址和邻居结构状态的通用函数，最后发送前面挂入到队列汇总的数据包。
  * neigh----指向要更新的neighbour结构
  * lladdr---新的链路层(L2)地址。lladdr并不总是初始化为一个新值。虽然参数指定了硬件地址，但在处理中根据状态等条件还可能会进行调整
             例如,当调用neigh_update来删除一个neighbour结构时(设置其状态为NUD_FAILED,"删除邻居")
  *          会给lladdr传递一个NULL值。
  * new------新的NUD状态。
  * flags----用于传递信息，例如，是否要覆盖一个已有的链路层地址等。
*/
int neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new,
		 u32 flags)
{
	u8 old;
	int err;
	int notify = 0;
	struct net_device *dev;
	int update_isrouter = 0;

	write_lock_bh(&neigh->lock);//锁定neighbour

	dev    = neigh->dev;//获取网络设备结构
	old    = neigh->nud_state;//获取邻居结构的原来状态
	err    = -EPERM;

	/*邻居表项mac地址的填充*/
	/*
     *只有管理命令(NEIGH_UPDATE_F_ADMIN)可以改变当前状态是NUD_NOARP态或NUD_PERMANENT态的邻居的状态。
	*/
	if (!(flags & NEIGH_UPDATE_F_ADMIN) &&
	    (old & (NUD_NOARP | NUD_PERMANENT)))
		goto out;//约束条件不满足，程序就会退出

	if (!(new & NUD_VALID)) {//当新状态new不是一个合法状态时，如果它是NUD_NONE态或NUD_INCOMPLETE态，就要停止启动了的邻居定时器
		neigh_del_timer(neigh);//is the new state NUD_VALID,not 停止定时器
		if (old & NUD_CONNECTED)
			neigh_suspect(neigh);//若旧状态是NUD_CONNECTED，调用函数将邻居先标记为可疑的(要求进行可到达性认证)。
		neigh->nud_state = new;//设置新状态
		err = 0;
		notify = old & NUD_VALID;//通知APRD
		//当原先状态是NUD_INCOMPLETE或NUD_PROBE状态时，可能有暂时因为地址没有解析而暂存在neigh->arp_queue中的报文，
		//而现在表项更新到NUD_FAILED，即解析无法成功，那么这么暂存的报文也只能被丢弃neigh_invalidate。
		if ((old & (NUD_INCOMPLETE | NUD_PROBE)) &&
		    (new & NUD_FAILED)) {
			neigh_invalidate(neigh);
			notify = 1;
		}
		goto out;
	}

	/* Compare new lladdr with cached one */
	if (!dev->addr_len) {
		/* First case: device needs no address. */
		lladdr = neigh->ha;
	} else if (lladdr) {
		/* The second case: if something is already cached
		   and a new address is proposed:
		   - compare new & old
		   - if they are different, check override flag
		 */
		if ((old & NUD_VALID) &&
		    !memcmp(lladdr, neigh->ha, dev->addr_len))
			lladdr = neigh->ha;
	} else {
		/* No address is supplied; if we know something,
		   use it, otherwise discard the request.
		 */
		err = -EINVAL;
		if (!(old & NUD_VALID))
			goto out;
		lladdr = neigh->ha;
	}

	/*
	如果新状态为NUD_CONNECTED，说明邻居处于连接状态，可以直接根据该邻居项发送数据包，因此需要更新确认时间。
	设置更新时间
	*/
	if (new & NUD_CONNECTED)
		neigh->confirmed = jiffies;
	neigh->updated = jiffies;//记录当前时间

	/* If entry was valid and address is not changed,
	   do not change entry state, if new one is STALE.
	   如果条目有效并且地址未更改，则不要更改条目状态，如果新的是STALE。
	 */
	err = 0;
	update_isrouter = flags & NEIGH_UPDATE_F_OVERRIDE_ISROUTER;//NEIGH_UPDATE_F_OVERRIDE_ISROUTER,只在IPV6中存在
	if (old & NUD_VALID) {
		if (lladdr != neigh->ha && !(flags & NEIGH_UPDATE_F_OVERRIDE)) {
			update_isrouter = 0;
			if ((flags & NEIGH_UPDATE_F_WEAK_OVERRIDE) &&
			    (old & NUD_CONNECTED)) {
				lladdr = neigh->ha;
				new = NUD_STALE;
			} else
				goto out;
		} else {
			// NUD_REACHABLE状态时，新状态为NUD_STALE是在下面这段代码里面除去了，
			// 因为NUD_REACHABLE状态更好，不应该回退到NUD_STALE状态。
			if (lladdr == neigh->ha && new == NUD_STALE &&
			    ((flags & NEIGH_UPDATE_F_WEAK_OVERRIDE) ||
			     (old & NUD_CONNECTED))
			    )
				new = old;
		}
	}

	//新旧状态不同时，首先删除定时器，如果新状态需要定时器，则重新设置定时器，最后设置表项neigh为新状态new。
	if (new != old) {
		neigh_del_timer(neigh);//摘除定时器
		if (new & NUD_IN_TIMER)//每个邻居的定时器的每次启动都会导致该邻居的引用计数加1
			neigh_add_timer(neigh, (jiffies +
						((new & NUD_REACHABLE) ?
						 neigh->parms->reachable_time :
						 0)));//重新设置定时器
		neigh->nud_state = new;//修改邻居结构的状态
	}

    //如果邻居表项中的地址发生了更新，有了新的地址值lladdr，那么更新表项地址neigh->ha，
    //并更新与此表项相关的所有缓存表项neigh_update_hhs。
	if (lladdr != neigh->ha) {//如果服务器MAC地址与原来记录的不同
		memcpy(&neigh->ha, lladdr, dev->addr_len);//记录服务器MAC地址
		neigh_update_hhs(neigh);
		if (!(new & NUD_CONNECTED))
			neigh->confirmed = jiffies -
				      (neigh->parms->base_reachable_time << 1);//调整确定时间
		notify = 1;
	}
	if (new == old)//如果修改状态与原始状态相同就直接返回
		goto out;
	if (new & NUD_CONNECTED)//检查是否为连接状态
		neigh_connect(neigh); //设置neigh->output，重新设置邻居结构的发送函数
	else
		neigh_suspect(neigh); //设置邻居结构的发送函数
	/* 如果邻居表项由无效状态变为有效状态(注:之前状态为NUD_INCOMPLETE，属于无效状态，而即将变为NUD_REACHABLE为有效状态的一种) */
	if (!(old & NUD_VALID)) {
		struct sk_buff *skb;

		/* Again: avoid dead loop if something went wrong */
		/*遍历邻居表项的缓存队列arp_queue，将缓存在队列中的报文逐个输出*/
		while (neigh->nud_state & NUD_VALID &&
		       (skb = __skb_dequeue(&neigh->arp_queue)) != NULL) {
			struct neighbour *n1 = neigh;
			write_unlock_bh(&neigh->lock);
			/* On shaper/eql skb->dst->neighbour != neigh :( */
			if (skb_dst(skb) && skb_dst(skb)->neighbour)
				n1 = skb_dst(skb)->neighbour;
			//终于将邻居表项中的mac填充了，构建出了完整的邻居表项，也终于将数据包发送出去。
			//这里使用的发送函数为neigh->output在neigh_connect中被设置。 
			//对于设置邻居结构的发送函数，其结果仍然是neigh_resolve_output()函数，
			//接下来调用该函数，将前面__neigh_event_send()函数链入到ARP队列的数据包，逐一发送给服务器
			n1->output(skb);
			write_lock_bh(&neigh->lock);
		}
		__skb_queue_purge(&neigh->arp_queue);
	}
out:
	if (update_isrouter) {
		neigh->flags = (flags & NEIGH_UPDATE_F_ISROUTER) ?
			(neigh->flags | NTF_ROUTER) :
			(neigh->flags & ~NTF_ROUTER);
	}
	write_unlock_bh(&neigh->lock);//解锁neighbour

	//发出通知,通过内核的通知链和netlink发布邻居结构更新的消息，前面的arp_init()函数已经向内核登记了ARP的通知节点
	//arp_notifier，netlink则被IPROUTER2用来控制邻居子系统。
	if (notify)//aprd需要一个通知吗?如果编译时支持ARPD,则还需要通知ARPD进程
		neigh_update_notify(neigh);

	return err;
}
EXPORT_SYMBOL(neigh_update);

struct neighbour *neigh_event_ns(struct neigh_table *tbl,
				 u8 *lladdr, void *saddr,
				 struct net_device *dev)
{
	struct neighbour *neigh = __neigh_lookup(tbl, saddr, dev,
						 lladdr || !dev->addr_len);//查找邻居结构
	if (neigh)
		neigh_update(neigh, lladdr, NUD_STALE,
			     NEIGH_UPDATE_F_OVERRIDE);
	return neigh;
}
EXPORT_SYMBOL(neigh_event_ns);

/*
 * 此函数实现通过邻居项为指定路由缓存项建立硬件首部缓存
*/
static void neigh_hh_init(struct neighbour *n, struct dst_entry *dst,
			  __be16 protocol)
{
	struct hh_cache	*hh;
	struct net_device *dev = dst->dev;

	/*根据协议在邻居项的硬件缓存列表中查找对应的硬件首部缓存。如果查找命中，
	则使用该硬件首部缓存为路由缓存建立硬件首部缓存。
	*/
	for (hh = n->hh; hh; hh = hh->hh_next)
		if (hh->hh_type == protocol)
			break;

	/*如果查找未果，则创建新的硬件首部缓存，并将其添加到邻居项的硬件缓存列表中，同时根据状态设置合适的hh_output函数指针
	*/
	if (!hh && (hh = kzalloc(sizeof(*hh), GFP_ATOMIC)) != NULL) {
		seqlock_init(&hh->hh_lock);
		hh->hh_type = protocol;
		atomic_set(&hh->hh_refcnt, 0);
		hh->hh_next = NULL;

		if (dev->header_ops->cache(n, hh)) {
			kfree(hh);
			hh = NULL;
		} else {
			atomic_inc(&hh->hh_refcnt);
			hh->hh_next = n->hh;
			n->hh	    = hh;
			if (n->nud_state & NUD_CONNECTED)
				hh->hh_output = n->ops->hh_output;
			else
				hh->hh_output = n->ops->output;
		}
	}
	/* 将查找命中的或是新创建的硬件首部缓存设置到路由缓存项中 */
	if (hh)	{
		atomic_inc(&hh->hh_refcnt);
		dst->hh = hh;
	}
}

/* This function can be used in contexts, where only old dev_queue_xmit
   worked, f.e. if you want to override normal output path (eql, shaper),
   but resolution is not made yet.
   该函数是为了保证向下兼容。在引入邻居基础结构以前，由它负责调用dev_queue_xmit函数，即使L2地址还没有准备好。
 */

int neigh_compat_output(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;

	__skb_pull(skb, skb_network_offset(skb));

	if (dev_hard_header(skb, dev, ntohs(skb->protocol), NULL, NULL,
			    skb->len) < 0 &&
	    dev->header_ops->rebuild(skb))
		return 0;

	return dev_queue_xmit(skb);
}
EXPORT_SYMBOL(neigh_compat_output);

/* Slow and careful. */
/*作用:
 *当邻居项不处于NUD_CONNECTED状态时，不允许快速路径发送报文。函数neigh_resolve_output()用于慢速而安全的输出，
 *通常用来初始化neigh_ops结构实例的output函数指针，当邻居项从NUD_CONNECTED转而非NUD_CONNECTED状态，便会调用
 *neigh_suspect将邻居项的output设置为neigh_resolve_output()
 *注意:
 * 该函数在数据传输前将L3地址解析为L2地址。因此，当L3地址和L2地址的对应关系还没有建立或者需要对其确认时，
 * 就会用到该函数。如果创建一个
 * neighbour新结构并且需要对其L3地址进行解析时，除了"特殊情况"外，neigh_resolve_output是作为默认函数使用的。
 * 当主机需要解析地址，会调用neigh_resolve_output，主机引用表项明显会涉及到表项的NUD状态迁移，
 * NUD_NONE->NUD_INCOMPLETE，NUD_STALE->NUD_DELAY。
*/
int neigh_resolve_output(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);/*取得对应的路由缓存*/
	struct neighbour *neigh;
	int rc = 0;

	if (!dst || !(neigh = dst->neighbour))//如果路由项或它的邻居结构都没有存在就返回
		goto discard;

	/*指向三层（ip）头部*/
	__skb_pull(skb, skb_network_offset(skb));

	/*确保用于输出的邻居项状态有效才能发送数据包*/
	if (!neigh_event_send(neigh, skb)) {//检查邻居结构是否可用，如果可用继续发送，返回0为可用
		int err;
		struct net_device *dev = neigh->dev;
		/*如果邻居项的输出设备支持hard_header_cache，同时路由缓存项中的二层首部缓存尚未建立，
		则先为该路由缓存建立硬件首部缓存(struce hh_cache)，
		然后在输出的报文前添加该硬件首部，否则直接在报文前添加硬件首部*/
		if (dev->header_ops->cache && !dst->hh) {
			write_lock_bh(&neigh->lock);
			if (!dst->hh)
				neigh_hh_init(neigh, dst, dst->ops->protocol);
			err = dev_hard_header(skb, dev, ntohs(skb->protocol),
					      neigh->ha, NULL, skb->len);
			write_unlock_bh(&neigh->lock);
		} else {
			read_lock_bh(&neigh->lock);
			err = dev_hard_header(skb, dev, ntohs(skb->protocol),
					      neigh->ha, NULL, skb->len);
			read_unlock_bh(&neigh->lock);
		}
		
		/*如果添加硬件首部成功，则调用queue_xmit()将报文输出到网络设备*/
		if (err >= 0)
			rc = neigh->ops->queue_xmit(skb);
		else
			goto out_kfree_skb;
	}
out:
	return rc;
discard:
	NEIGH_PRINTK1("neigh_resolve_output: dst=%p neigh=%p\n",
		      dst, dst ? dst->neighbour : NULL);
out_kfree_skb:
	rc = -EINVAL;
	kfree_skb(skb);
	goto out;
}
EXPORT_SYMBOL(neigh_resolve_output);

/* As fast as possible without hh cache */
/*
   此函数初始化neigh_ops结构实例的connected_output函数指针。
   当邻居项从非NUD_CONNECTED转到NUD_CONNECTED状态，
   便调用neigh_connect()将邻居项的output设置为neigh_connected_output()。

 * 该函数只是填充L2枕头，然后调用neigh_ops->queue_xmit。因此，它希望L2地址被解析。neighbour结构在NUD_CONNECTED状态会用到这个函数。
*/
int neigh_connected_output(struct sk_buff *skb)
{
	int err;
	struct dst_entry *dst = skb_dst(skb);
	struct neighbour *neigh = dst->neighbour;
	struct net_device *dev = neigh->dev;

	__skb_pull(skb, skb_network_offset(skb));

	read_lock_bh(&neigh->lock);
	/*构建报文二层mac头部,在待输出的报文添加硬件首部，以太网上，则添加以太网帧首部 */
	err = dev_hard_header(skb, dev, ntohs(skb->protocol),
			      neigh->ha, NULL, skb->len);
	read_unlock_bh(&neigh->lock);
	//如果添加硬件首部成功，则调用queue_xmit()将报文输出到网络设备。
	if (err >= 0)
		err = neigh->ops->queue_xmit(skb);/*发送skb*/
	else {
		err = -EINVAL;
		kfree_skb(skb);
	}
	return err;
}
EXPORT_SYMBOL(neigh_connected_output);

/*
  proxy_timer定时器是在neigh_table_init_no_netlink()中初始化的，其处理函数为neigh_proxy_process()。每当proxy_timer到期时，
  该函数就会从缓存队列中逐个取出并处理报文，直至全部处理完毕。
*/
static void neigh_proxy_process(unsigned long arg)
{
	struct neigh_table *tbl = (struct neigh_table *)arg;
	long sched_next = 0;
	unsigned long now = jiffies;
	struct sk_buff *skb, *n;

	spin_lock(&tbl->proxy_queue.lock);

	skb_queue_walk_safe(&tbl->proxy_queue, skb, n) {//遍历proxy_queue队列
		long tdif = NEIGH_CB(skb)->sched_next - now;

		//如果延时的时间已经超出当前请求报文的延时时间，则将该请求报文从队列中取下，然后根据邻居表proxy_redo接口的有效性以
		//以及输出设备是否启用来决定是调用proxy_redo()处理之还是丢弃之。
		if (tdif <= 0) {
			struct net_device *dev = skb->dev;
			__skb_unlink(skb, &tbl->proxy_queue);
			if (tbl->proxy_redo && netif_running(dev))
				tbl->proxy_redo(skb);
			else
				kfree_skb(skb);

			dev_put(dev);
		} else if (!sched_next || tdif < sched_next)//重新计算并设置proxy_timer定时器下次到期时间。
			sched_next = tdif;
	}
	del_timer(&tbl->proxy_timer);
	if (sched_next)
		mod_timer(&tbl->proxy_timer, jiffies + sched_next);
	spin_unlock(&tbl->proxy_queue.lock);
}

/*
 * 当在延时处理的代理请求报文时，会调用pneigh_enqueue()将请求报文缓存到proxy_queue队列中，
 * 然后设置proxy_timer定时器，到定时器到期时再处理该请求报文。
*/
void pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
		    struct sk_buff *skb)
{
	//有当前时间，随机数和proxy_dely计算请求报文的延时时间。
	unsigned long now = jiffies;
	unsigned long sched_next = now + (net_random() % p->proxy_delay);

	//如果邻居表的代理报文缓存队列长度已达到上限，则将报文丢弃
	if (tbl->proxy_queue.qlen > p->proxy_qlen) {
		kfree_skb(skb);
		return;
	}

	//将之前计算得到的延时时间和LOCALLY_ENQUEUED标志保存到该请求报文的控制块中。
	NEIGH_CB(skb)->sched_next = sched_next;
	NEIGH_CB(skb)->flags |= LOCALLY_ENQUEUED;

	//先去活proxy_timer定时器，然后在原到期时间和计算得到的延期时间之中取近者为新到期时间。
	spin_lock(&tbl->proxy_queue.lock);
	if (del_timer(&tbl->proxy_timer)) {
		if (time_before(tbl->proxy_timer.expires, sched_next))
			sched_next = tbl->proxy_timer.expires;
	}
	//把skb的路由缓存项置空后将其添加到proxy_queue队列
	skb_dst_drop(skb);
	dev_hold(skb->dev);
	__skb_queue_tail(&tbl->proxy_queue, skb);
	mod_timer(&tbl->proxy_timer, sched_next);//重新设置proxy_timer定时器下次到期时间
	spin_unlock(&tbl->proxy_queue.lock);
}
EXPORT_SYMBOL(pneigh_enqueue);

static inline struct neigh_parms *lookup_neigh_parms(struct neigh_table *tbl,
						      struct net *net, int ifindex)
{
	struct neigh_parms *p;

	for (p = &tbl->parms; p; p = p->next) {
		if ((p->dev && p->dev->ifindex == ifindex && net_eq(neigh_parms_net(p), net)) ||
		    (!p->dev && !ifindex))
			return p;
	}

	return NULL;
}

struct neigh_parms *neigh_parms_alloc(struct net_device *dev,
				      struct neigh_table *tbl)
{
	struct neigh_parms *p, *ref;
	struct net *net = dev_net(dev);
	const struct net_device_ops *ops = dev->netdev_ops;

	ref = lookup_neigh_parms(tbl, net, 0);
	if (!ref)
		return NULL;

	p = kmemdup(ref, sizeof(*p), GFP_KERNEL);
	if (p) {
		p->tbl		  = tbl;
		atomic_set(&p->refcnt, 1);
		p->reachable_time =
				neigh_rand_reach_time(p->base_reachable_time);

		if (ops->ndo_neigh_setup && ops->ndo_neigh_setup(dev, p)) {
			kfree(p);
			return NULL;
		}

		dev_hold(dev);
		p->dev = dev;
		write_pnet(&p->net, hold_net(net));
		p->sysctl_table = NULL;
		write_lock_bh(&tbl->lock);
		p->next		= tbl->parms.next;
		tbl->parms.next = p;
		write_unlock_bh(&tbl->lock);
	}
	return p;
}
EXPORT_SYMBOL(neigh_parms_alloc);

static void neigh_rcu_free_parms(struct rcu_head *head)
{
	struct neigh_parms *parms =
		container_of(head, struct neigh_parms, rcu_head);

	neigh_parms_put(parms);
}

void neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms)
{
	struct neigh_parms **p;

	if (!parms || parms == &tbl->parms)
		return;
	write_lock_bh(&tbl->lock);
	for (p = &tbl->parms.next; *p; p = &(*p)->next) {
		if (*p == parms) {
			*p = parms->next;
			parms->dead = 1;
			write_unlock_bh(&tbl->lock);
			if (parms->dev)
				dev_put(parms->dev);
			call_rcu(&parms->rcu_head, neigh_rcu_free_parms);
			return;
		}
	}
	write_unlock_bh(&tbl->lock);
	NEIGH_PRINTK1("neigh_parms_release: not found\n");
}
EXPORT_SYMBOL(neigh_parms_release);

static void neigh_parms_destroy(struct neigh_parms *parms)
{
	release_net(neigh_parms_net(parms));
	kfree(parms);
}

static struct lock_class_key neigh_table_proxy_queue_class;

void neigh_table_init_no_netlink(struct neigh_table *tbl)
{
	unsigned long now = jiffies;
	unsigned long phsize;

	write_pnet(&tbl->parms.net, &init_net);
	atomic_set(&tbl->parms.refcnt, 1);
	tbl->parms.reachable_time =
			  neigh_rand_reach_time(tbl->parms.base_reachable_time);

	if (!tbl->kmem_cachep)
		tbl->kmem_cachep =
			kmem_cache_create(tbl->id, tbl->entry_size, 0,
					  SLAB_HWCACHE_ALIGN|SLAB_PANIC,
					  NULL);
	tbl->stats = alloc_percpu(struct neigh_statistics);
	if (!tbl->stats)
		panic("cannot create neighbour cache statistics");

#ifdef CONFIG_PROC_FS
	if (!proc_create_data(tbl->id, 0, init_net.proc_net_stat,
			      &neigh_stat_seq_fops, tbl))
		panic("cannot create neighbour proc dir entry");
#endif

	tbl->hash_mask = 1;
	tbl->hash_buckets = neigh_hash_alloc(tbl->hash_mask + 1);

	phsize = (PNEIGH_HASHMASK + 1) * sizeof(struct pneigh_entry *);
	tbl->phash_buckets = kzalloc(phsize, GFP_KERNEL);

	if (!tbl->hash_buckets || !tbl->phash_buckets)
		panic("cannot allocate neighbour cache hashes");

	get_random_bytes(&tbl->hash_rnd, sizeof(tbl->hash_rnd));

	rwlock_init(&tbl->lock);
	INIT_DELAYED_WORK_DEFERRABLE(&tbl->gc_work, neigh_periodic_work);
	schedule_delayed_work(&tbl->gc_work, tbl->parms.reachable_time);
	setup_timer(&tbl->proxy_timer, neigh_proxy_process, (unsigned long)tbl);
	skb_queue_head_init_class(&tbl->proxy_queue,
			&neigh_table_proxy_queue_class);

	tbl->last_flush = now;
	tbl->last_rand	= now + tbl->parms.reachable_time * 20;
}
EXPORT_SYMBOL(neigh_table_init_no_netlink);

/*
 * 此函数用于初始化neigh_table结构:主要完成以下工作
 * 1.为neighbour结构分配预备的内存池。
 * 2.分配一个neigh_statistics结构来收集协议的统计信息。
 * 3.分配两个hash表:hash_buckets和phash_buckets。这两个表分别作为解析过的地址关联缓存和代理的地址数据库。
 * 4.在/proc/net中建立一个文件，用于转储缓存的内容。文件名来自neigh_table->id
 * 5.启动gc_timer垃圾回收定时器.
 * 6.初始化(但是不启动)proxy_timer代理定时器和相关的proxy_queue队列。
 * 7.添加neigh_table结构到neigh_tables全局列表中。后者由一个锁保护。
 * 8.初始化其他一些参数。例如reachable_time。
*/
void neigh_table_init(struct neigh_table *tbl)
{
	struct neigh_table *tmp;

	neigh_table_init_no_netlink(tbl);//初始化邻居表
	write_lock(&neigh_tbl_lock);//对neigh_tables操作，进行加锁处理
	for (tmp = neigh_tables; tmp; tmp = tmp->next) {
		if (tmp->family == tbl->family)//查看相同地址族的邻居表
			break;
	}
	//将邻居表插入到队列的前面
	tbl->next	= neigh_tables;
	neigh_tables	= tbl;//放到队列前面
	write_unlock(&neigh_tbl_lock);

	if (unlikely(tmp)) {//如果找到相同地址族邻居表就打印错误信息
		printk(KERN_ERR "NEIGH: Registering multiple tables for "
		       "family %d\n", tbl->family);
		dump_stack();
	}
}
EXPORT_SYMBOL(neigh_table_init);

/*
 * 当一个协议使用模块方式允许，并且模块被卸载时，会调用此函数来撤销neigh_table_int在初始化时所做的工作，
 * 并且会清理在协议生存期内分配给该协议的任何资源，例如，定时器和队列。
 * IPv4是唯一不能编译为模块的协议，因此ARP不需要清理函数.
*/
int neigh_table_clear(struct neigh_table *tbl)
{
	struct neigh_table **tp;

	/* It is not clean... Fix it to unload IPv6 module safely */
	cancel_delayed_work(&tbl->gc_work);
	flush_scheduled_work();
	del_timer_sync(&tbl->proxy_timer);
	pneigh_queue_purge(&tbl->proxy_queue);
	neigh_ifdown(tbl, NULL);
	if (atomic_read(&tbl->entries))
		printk(KERN_CRIT "neighbour leakage\n");
	write_lock(&neigh_tbl_lock);
	for (tp = &neigh_tables; *tp; tp = &(*tp)->next) {
		if (*tp == tbl) {
			*tp = tbl->next;
			break;
		}
	}
	write_unlock(&neigh_tbl_lock);

	neigh_hash_free(tbl->hash_buckets, tbl->hash_mask + 1);
	tbl->hash_buckets = NULL;

	kfree(tbl->phash_buckets);
	tbl->phash_buckets = NULL;

	remove_proc_entry(tbl->id, init_net.proc_net_stat);

	free_percpu(tbl->stats);
	tbl->stats = NULL;

	kmem_cache_destroy(tbl->kmem_cachep);
	tbl->kmem_cachep = NULL;

	return 0;
}
EXPORT_SYMBOL(neigh_table_clear);

static int neigh_delete(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct net *net = sock_net(skb->sk);
	struct ndmsg *ndm;
	struct nlattr *dst_attr;
	struct neigh_table *tbl;
	struct net_device *dev = NULL;
	int err = -EINVAL;

	if (nlmsg_len(nlh) < sizeof(*ndm))
		goto out;

	dst_attr = nlmsg_find_attr(nlh, sizeof(*ndm), NDA_DST);
	if (dst_attr == NULL)
		goto out;

	ndm = nlmsg_data(nlh);
	if (ndm->ndm_ifindex) {
		dev = dev_get_by_index(net, ndm->ndm_ifindex);
		if (dev == NULL) {
			err = -ENODEV;
			goto out;
		}
	}

	read_lock(&neigh_tbl_lock);
	for (tbl = neigh_tables; tbl; tbl = tbl->next) {
		struct neighbour *neigh;

		if (tbl->family != ndm->ndm_family)
			continue;
		read_unlock(&neigh_tbl_lock);

		if (nla_len(dst_attr) < tbl->key_len)
			goto out_dev_put;

		if (ndm->ndm_flags & NTF_PROXY) {
			err = pneigh_delete(tbl, net, nla_data(dst_attr), dev);
			goto out_dev_put;
		}

		if (dev == NULL)
			goto out_dev_put;

		neigh = neigh_lookup(tbl, nla_data(dst_attr), dev);
		if (neigh == NULL) {
			err = -ENOENT;
			goto out_dev_put;
		}

		err = neigh_update(neigh, NULL, NUD_FAILED,
				   NEIGH_UPDATE_F_OVERRIDE |
				   NEIGH_UPDATE_F_ADMIN);
		neigh_release(neigh);
		goto out_dev_put;
	}
	read_unlock(&neigh_tbl_lock);
	err = -EAFNOSUPPORT;

out_dev_put:
	if (dev)
		dev_put(dev);
out:
	return err;
}

static int neigh_add(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct net *net = sock_net(skb->sk);
	struct ndmsg *ndm;
	struct nlattr *tb[NDA_MAX+1];
	struct neigh_table *tbl;
	struct net_device *dev = NULL;
	int err;

	err = nlmsg_parse(nlh, sizeof(*ndm), tb, NDA_MAX, NULL);
	if (err < 0)
		goto out;

	err = -EINVAL;
	if (tb[NDA_DST] == NULL)
		goto out;
	/*
	从消息的后部，即邻居信息之后，获取变长的扩展属性，并校验保存存在NDA_DST类型的扩展属性
	*/
	ndm = nlmsg_data(nlh);
	if (ndm->ndm_ifindex) {
		dev = dev_get_by_index(net, ndm->ndm_ifindex);
		if (dev == NULL) {
			err = -ENODEV;
			goto out;
		}

		if (tb[NDA_LLADDR] && nla_len(tb[NDA_LLADDR]) < dev->addr_len)
			goto out_dev_put;
	}

	/*
	由邻居项的网络设备索引获取对应的网络设备.如果存在二层地址扩展属性，则需校验
	*/
	read_lock(&neigh_tbl_lock);
	//遍历neigh_tables链表中所有的邻居表，获取与消息中给出的地址族相一致的邻居表
	for (tbl = neigh_tables; tbl; tbl = tbl->next) {
		int flags = NEIGH_UPDATE_F_ADMIN | NEIGH_UPDATE_F_OVERRIDE;
		struct neighbour *neigh;
		void *dst, *lladdr;

		if (tbl->family != ndm->ndm_family)
			continue;
		read_unlock(&neigh_tbl_lock);

		//从扩展属性值中获取相关的信息等待处理
		if (nla_len(tb[NDA_DST]) < tbl->key_len)
			goto out_dev_put;
		dst = nla_data(tb[NDA_DST]);
		lladdr = tb[NDA_LLADDR] ? nla_data(tb[NDA_LLADDR]) : NULL;

		if (ndm->ndm_flags & NTF_PROXY) {
			struct pneigh_entry *pn;

			err = -ENOBUFS;
			pn = pneigh_lookup(tbl, net, dst, dev, 1);//添加一个代理项
			if (pn) {
				pn->flags = ndm->ndm_flags;
				err = 0;
			}
			goto out_dev_put;
		}

		//添加邻居项前，确保该邻居的输出网络设备不能为空
		if (dev == NULL)
			goto out_dev_put;

		//调用neigh_lookup()根据邻居项的地址以及输出网络设备，在邻居表的邻居散列表中找到对应的邻居项
		neigh = neigh_lookup(tbl, dst, dev);
		if (neigh == NULL) {
			if (!(nlh->nlmsg_flags & NLM_F_CREATE)) {
				err = -ENOENT;
				goto out_dev_put;
			}

			/* 如果没有在邻居表中找到对应的邻居项，且netlink添加邻居项消息首部的nlmsg_flags域中存在NLM_F_CREATE标志，
			   该标志表示不存在即创建之，则调用neigh_lookup_errno()创建并添加相应的邻居项到散列表中
			*/
			neigh = __neigh_lookup_errno(tbl, dst, dev);
			if (IS_ERR(neigh)) {
				err = PTR_ERR(neigh);
				goto out_dev_put;
			}
		} else {
			if (nlh->nlmsg_flags & NLM_F_EXCL) {
				err = -EEXIST;
				neigh_release(neigh);
				goto out_dev_put;
			}

			if (!(nlh->nlmsg_flags & NLM_F_REPLACE))
				flags &= ~NEIGH_UPDATE_F_OVERRIDE;
		}

		if (ndm->ndm_flags & NTF_USE) {
			neigh_event_send(neigh, NULL);
			err = 0;
		} else
			err = neigh_update(neigh, lladdr, ndm->ndm_state, flags);//更新指定项
		neigh_release(neigh);
		goto out_dev_put;
	}

	read_unlock(&neigh_tbl_lock);
	err = -EAFNOSUPPORT;

out_dev_put:
	if (dev)
		dev_put(dev);
out:
	return err;
}

static int neightbl_fill_parms(struct sk_buff *skb, struct neigh_parms *parms)
{
	struct nlattr *nest;

	nest = nla_nest_start(skb, NDTA_PARMS);
	if (nest == NULL)
		return -ENOBUFS;

	if (parms->dev)
		NLA_PUT_U32(skb, NDTPA_IFINDEX, parms->dev->ifindex);

	NLA_PUT_U32(skb, NDTPA_REFCNT, atomic_read(&parms->refcnt));
	NLA_PUT_U32(skb, NDTPA_QUEUE_LEN, parms->queue_len);
	NLA_PUT_U32(skb, NDTPA_PROXY_QLEN, parms->proxy_qlen);
	NLA_PUT_U32(skb, NDTPA_APP_PROBES, parms->app_probes);
	NLA_PUT_U32(skb, NDTPA_UCAST_PROBES, parms->ucast_probes);
	NLA_PUT_U32(skb, NDTPA_MCAST_PROBES, parms->mcast_probes);
	NLA_PUT_MSECS(skb, NDTPA_REACHABLE_TIME, parms->reachable_time);
	NLA_PUT_MSECS(skb, NDTPA_BASE_REACHABLE_TIME,
		      parms->base_reachable_time);
	NLA_PUT_MSECS(skb, NDTPA_GC_STALETIME, parms->gc_staletime);
	NLA_PUT_MSECS(skb, NDTPA_DELAY_PROBE_TIME, parms->delay_probe_time);
	NLA_PUT_MSECS(skb, NDTPA_RETRANS_TIME, parms->retrans_time);
	NLA_PUT_MSECS(skb, NDTPA_ANYCAST_DELAY, parms->anycast_delay);
	NLA_PUT_MSECS(skb, NDTPA_PROXY_DELAY, parms->proxy_delay);
	NLA_PUT_MSECS(skb, NDTPA_LOCKTIME, parms->locktime);

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

static int neightbl_fill_info(struct sk_buff *skb, struct neigh_table *tbl,
			      u32 pid, u32 seq, int type, int flags)
{
	struct nlmsghdr *nlh;
	struct ndtmsg *ndtmsg;

	nlh = nlmsg_put(skb, pid, seq, type, sizeof(*ndtmsg), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ndtmsg = nlmsg_data(nlh);

	read_lock_bh(&tbl->lock);
	ndtmsg->ndtm_family = tbl->family;
	ndtmsg->ndtm_pad1   = 0;
	ndtmsg->ndtm_pad2   = 0;

	NLA_PUT_STRING(skb, NDTA_NAME, tbl->id);
	NLA_PUT_MSECS(skb, NDTA_GC_INTERVAL, tbl->gc_interval);
	NLA_PUT_U32(skb, NDTA_THRESH1, tbl->gc_thresh1);
	NLA_PUT_U32(skb, NDTA_THRESH2, tbl->gc_thresh2);
	NLA_PUT_U32(skb, NDTA_THRESH3, tbl->gc_thresh3);

	{
		unsigned long now = jiffies;
		unsigned int flush_delta = now - tbl->last_flush;
		unsigned int rand_delta = now - tbl->last_rand;

		struct ndt_config ndc = {
			.ndtc_key_len		= tbl->key_len,
			.ndtc_entry_size	= tbl->entry_size,
			.ndtc_entries		= atomic_read(&tbl->entries),
			.ndtc_last_flush	= jiffies_to_msecs(flush_delta),
			.ndtc_last_rand		= jiffies_to_msecs(rand_delta),
			.ndtc_hash_rnd		= tbl->hash_rnd,
			.ndtc_hash_mask		= tbl->hash_mask,
			.ndtc_proxy_qlen	= tbl->proxy_queue.qlen,
		};

		NLA_PUT(skb, NDTA_CONFIG, sizeof(ndc), &ndc);
	}

	{
		int cpu;
		struct ndt_stats ndst;

		memset(&ndst, 0, sizeof(ndst));

		for_each_possible_cpu(cpu) {
			struct neigh_statistics	*st;

			st = per_cpu_ptr(tbl->stats, cpu);
			ndst.ndts_allocs		+= st->allocs;
			ndst.ndts_destroys		+= st->destroys;
			ndst.ndts_hash_grows		+= st->hash_grows;
			ndst.ndts_res_failed		+= st->res_failed;
			ndst.ndts_lookups		+= st->lookups;
			ndst.ndts_hits			+= st->hits;
			ndst.ndts_rcv_probes_mcast	+= st->rcv_probes_mcast;
			ndst.ndts_rcv_probes_ucast	+= st->rcv_probes_ucast;
			ndst.ndts_periodic_gc_runs	+= st->periodic_gc_runs;
			ndst.ndts_forced_gc_runs	+= st->forced_gc_runs;
		}

		NLA_PUT(skb, NDTA_STATS, sizeof(ndst), &ndst);
	}

	BUG_ON(tbl->parms.dev);
	if (neightbl_fill_parms(skb, &tbl->parms) < 0)
		goto nla_put_failure;

	read_unlock_bh(&tbl->lock);
	return nlmsg_end(skb, nlh);

nla_put_failure:
	read_unlock_bh(&tbl->lock);
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static int neightbl_fill_param_info(struct sk_buff *skb,
				    struct neigh_table *tbl,
				    struct neigh_parms *parms,
				    u32 pid, u32 seq, int type,
				    unsigned int flags)
{
	struct ndtmsg *ndtmsg;
	struct nlmsghdr *nlh;

	nlh = nlmsg_put(skb, pid, seq, type, sizeof(*ndtmsg), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ndtmsg = nlmsg_data(nlh);

	read_lock_bh(&tbl->lock);
	ndtmsg->ndtm_family = tbl->family;
	ndtmsg->ndtm_pad1   = 0;
	ndtmsg->ndtm_pad2   = 0;

	if (nla_put_string(skb, NDTA_NAME, tbl->id) < 0 ||
	    neightbl_fill_parms(skb, parms) < 0)
		goto errout;

	read_unlock_bh(&tbl->lock);
	return nlmsg_end(skb, nlh);
errout:
	read_unlock_bh(&tbl->lock);
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static const struct nla_policy nl_neightbl_policy[NDTA_MAX+1] = {
	[NDTA_NAME]		= { .type = NLA_STRING },
	[NDTA_THRESH1]		= { .type = NLA_U32 },
	[NDTA_THRESH2]		= { .type = NLA_U32 },
	[NDTA_THRESH3]		= { .type = NLA_U32 },
	[NDTA_GC_INTERVAL]	= { .type = NLA_U64 },
	[NDTA_PARMS]		= { .type = NLA_NESTED },
};

static const struct nla_policy nl_ntbl_parm_policy[NDTPA_MAX+1] = {
	[NDTPA_IFINDEX]			= { .type = NLA_U32 },
	[NDTPA_QUEUE_LEN]		= { .type = NLA_U32 },
	[NDTPA_PROXY_QLEN]		= { .type = NLA_U32 },
	[NDTPA_APP_PROBES]		= { .type = NLA_U32 },
	[NDTPA_UCAST_PROBES]		= { .type = NLA_U32 },
	[NDTPA_MCAST_PROBES]		= { .type = NLA_U32 },
	[NDTPA_BASE_REACHABLE_TIME]	= { .type = NLA_U64 },
	[NDTPA_GC_STALETIME]		= { .type = NLA_U64 },
	[NDTPA_DELAY_PROBE_TIME]	= { .type = NLA_U64 },
	[NDTPA_RETRANS_TIME]		= { .type = NLA_U64 },
	[NDTPA_ANYCAST_DELAY]		= { .type = NLA_U64 },
	[NDTPA_PROXY_DELAY]		= { .type = NLA_U64 },
	[NDTPA_LOCKTIME]		= { .type = NLA_U64 },
};

static int neightbl_set(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct net *net = sock_net(skb->sk);
	struct neigh_table *tbl;
	struct ndtmsg *ndtmsg;
	struct nlattr *tb[NDTA_MAX+1];
	int err;

	err = nlmsg_parse(nlh, sizeof(*ndtmsg), tb, NDTA_MAX,
			  nl_neightbl_policy);
	if (err < 0)
		goto errout;

	if (tb[NDTA_NAME] == NULL) {
		err = -EINVAL;
		goto errout;
	}

	ndtmsg = nlmsg_data(nlh);
	read_lock(&neigh_tbl_lock);
	for (tbl = neigh_tables; tbl; tbl = tbl->next) {
		if (ndtmsg->ndtm_family && tbl->family != ndtmsg->ndtm_family)
			continue;

		if (nla_strcmp(tb[NDTA_NAME], tbl->id) == 0)
			break;
	}

	if (tbl == NULL) {
		err = -ENOENT;
		goto errout_locked;
	}

	/*
	 * We acquire tbl->lock to be nice to the periodic timers and
	 * make sure they always see a consistent set of values.
	 */
	write_lock_bh(&tbl->lock);

	if (tb[NDTA_PARMS]) {
		struct nlattr *tbp[NDTPA_MAX+1];
		struct neigh_parms *p;
		int i, ifindex = 0;

		err = nla_parse_nested(tbp, NDTPA_MAX, tb[NDTA_PARMS],
				       nl_ntbl_parm_policy);
		if (err < 0)
			goto errout_tbl_lock;

		if (tbp[NDTPA_IFINDEX])
			ifindex = nla_get_u32(tbp[NDTPA_IFINDEX]);

		p = lookup_neigh_parms(tbl, net, ifindex);
		if (p == NULL) {
			err = -ENOENT;
			goto errout_tbl_lock;
		}

		for (i = 1; i <= NDTPA_MAX; i++) {
			if (tbp[i] == NULL)
				continue;

			switch (i) {
			case NDTPA_QUEUE_LEN:
				p->queue_len = nla_get_u32(tbp[i]);
				break;
			case NDTPA_PROXY_QLEN:
				p->proxy_qlen = nla_get_u32(tbp[i]);
				break;
			case NDTPA_APP_PROBES:
				p->app_probes = nla_get_u32(tbp[i]);
				break;
			case NDTPA_UCAST_PROBES:
				p->ucast_probes = nla_get_u32(tbp[i]);
				break;
			case NDTPA_MCAST_PROBES:
				p->mcast_probes = nla_get_u32(tbp[i]);
				break;
			case NDTPA_BASE_REACHABLE_TIME:
				p->base_reachable_time = nla_get_msecs(tbp[i]);
				break;
			case NDTPA_GC_STALETIME:
				p->gc_staletime = nla_get_msecs(tbp[i]);
				break;
			case NDTPA_DELAY_PROBE_TIME:
				p->delay_probe_time = nla_get_msecs(tbp[i]);
				break;
			case NDTPA_RETRANS_TIME:
				p->retrans_time = nla_get_msecs(tbp[i]);
				break;
			case NDTPA_ANYCAST_DELAY:
				p->anycast_delay = nla_get_msecs(tbp[i]);
				break;
			case NDTPA_PROXY_DELAY:
				p->proxy_delay = nla_get_msecs(tbp[i]);
				break;
			case NDTPA_LOCKTIME:
				p->locktime = nla_get_msecs(tbp[i]);
				break;
			}
		}
	}

	if (tb[NDTA_THRESH1])
		tbl->gc_thresh1 = nla_get_u32(tb[NDTA_THRESH1]);

	if (tb[NDTA_THRESH2])
		tbl->gc_thresh2 = nla_get_u32(tb[NDTA_THRESH2]);

	if (tb[NDTA_THRESH3])
		tbl->gc_thresh3 = nla_get_u32(tb[NDTA_THRESH3]);

	if (tb[NDTA_GC_INTERVAL])
		tbl->gc_interval = nla_get_msecs(tb[NDTA_GC_INTERVAL]);

	err = 0;

errout_tbl_lock:
	write_unlock_bh(&tbl->lock);
errout_locked:
	read_unlock(&neigh_tbl_lock);
errout:
	return err;
}

static int neightbl_dump_info(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	int family, tidx, nidx = 0;
	int tbl_skip = cb->args[0];
	int neigh_skip = cb->args[1];
	struct neigh_table *tbl;

	family = ((struct rtgenmsg *) nlmsg_data(cb->nlh))->rtgen_family;

	read_lock(&neigh_tbl_lock);
	for (tbl = neigh_tables, tidx = 0; tbl; tbl = tbl->next, tidx++) {
		struct neigh_parms *p;

		if (tidx < tbl_skip || (family && tbl->family != family))
			continue;

		if (neightbl_fill_info(skb, tbl, NETLINK_CB(cb->skb).pid,
				       cb->nlh->nlmsg_seq, RTM_NEWNEIGHTBL,
				       NLM_F_MULTI) <= 0)
			break;

		for (nidx = 0, p = tbl->parms.next; p; p = p->next) {
			if (!net_eq(neigh_parms_net(p), net))
				continue;

			if (nidx < neigh_skip)
				goto next;

			if (neightbl_fill_param_info(skb, tbl, p,
						     NETLINK_CB(cb->skb).pid,
						     cb->nlh->nlmsg_seq,
						     RTM_NEWNEIGHTBL,
						     NLM_F_MULTI) <= 0)
				goto out;
		next:
			nidx++;
		}

		neigh_skip = 0;
	}
out:
	read_unlock(&neigh_tbl_lock);
	cb->args[0] = tidx;
	cb->args[1] = nidx;

	return skb->len;
}

static int neigh_fill_info(struct sk_buff *skb, struct neighbour *neigh,
			   u32 pid, u32 seq, int type, unsigned int flags)
{
	unsigned long now = jiffies;
	struct nda_cacheinfo ci;
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;

	nlh = nlmsg_put(skb, pid, seq, type, sizeof(*ndm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ndm = nlmsg_data(nlh);
	ndm->ndm_family	 = neigh->ops->family;
	ndm->ndm_pad1    = 0;
	ndm->ndm_pad2    = 0;
	ndm->ndm_flags	 = neigh->flags;
	ndm->ndm_type	 = neigh->type;
	ndm->ndm_ifindex = neigh->dev->ifindex;

	NLA_PUT(skb, NDA_DST, neigh->tbl->key_len, neigh->primary_key);

	read_lock_bh(&neigh->lock);
	ndm->ndm_state	 = neigh->nud_state;
	if ((neigh->nud_state & NUD_VALID) &&
	    nla_put(skb, NDA_LLADDR, neigh->dev->addr_len, neigh->ha) < 0) {
		read_unlock_bh(&neigh->lock);
		goto nla_put_failure;
	}

	ci.ndm_used	 = jiffies_to_clock_t(now - neigh->used);
	ci.ndm_confirmed = jiffies_to_clock_t(now - neigh->confirmed);
	ci.ndm_updated	 = jiffies_to_clock_t(now - neigh->updated);
	ci.ndm_refcnt	 = atomic_read(&neigh->refcnt) - 1;
	read_unlock_bh(&neigh->lock);

	NLA_PUT_U32(skb, NDA_PROBES, atomic_read(&neigh->probes));
	NLA_PUT(skb, NDA_CACHEINFO, sizeof(ci), &ci);

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static void neigh_update_notify(struct neighbour *neigh)
{
	call_netevent_notifiers(NETEVENT_NEIGH_UPDATE, neigh);
	__neigh_notify(neigh, RTM_NEWNEIGH, 0);
}

static int neigh_dump_table(struct neigh_table *tbl, struct sk_buff *skb,
			    struct netlink_callback *cb)
{
	struct net * net = sock_net(skb->sk);
	struct neighbour *n;
	int rc, h, s_h = cb->args[1];
	int idx, s_idx = idx = cb->args[2];

	read_lock_bh(&tbl->lock);
	for (h = 0; h <= tbl->hash_mask; h++) {
		if (h < s_h)
			continue;
		if (h > s_h)
			s_idx = 0;
		for (n = tbl->hash_buckets[h], idx = 0; n; n = n->next) {
			if (dev_net(n->dev) != net)
				continue;
			if (idx < s_idx)
				goto next;
			if (neigh_fill_info(skb, n, NETLINK_CB(cb->skb).pid,
					    cb->nlh->nlmsg_seq,
					    RTM_NEWNEIGH,
					    NLM_F_MULTI) <= 0) {
				read_unlock_bh(&tbl->lock);
				rc = -1;
				goto out;
			}
		next:
			idx++;
		}
	}
	read_unlock_bh(&tbl->lock);
	rc = skb->len;
out:
	cb->args[1] = h;
	cb->args[2] = idx;
	return rc;
}

static int neigh_dump_info(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct neigh_table *tbl;
	int t, family, s_t;

	read_lock(&neigh_tbl_lock);
	family = ((struct rtgenmsg *) nlmsg_data(cb->nlh))->rtgen_family;
	s_t = cb->args[0];

	for (tbl = neigh_tables, t = 0; tbl; tbl = tbl->next, t++) {
		if (t < s_t || (family && tbl->family != family))
			continue;
		if (t > s_t)
			memset(&cb->args[1], 0, sizeof(cb->args) -
						sizeof(cb->args[0]));
		if (neigh_dump_table(tbl, skb, cb) < 0)
			break;
	}
	read_unlock(&neigh_tbl_lock);

	cb->args[0] = t;
	return skb->len;
}

void neigh_for_each(struct neigh_table *tbl, void (*cb)(struct neighbour *, void *), void *cookie)
{
	int chain;

	read_lock_bh(&tbl->lock);
	for (chain = 0; chain <= tbl->hash_mask; chain++) {
		struct neighbour *n;

		for (n = tbl->hash_buckets[chain]; n; n = n->next)
			cb(n, cookie);
	}
	read_unlock_bh(&tbl->lock);
}
EXPORT_SYMBOL(neigh_for_each);

/* The tbl->lock must be held as a writer and BH disabled. */
void __neigh_for_each_release(struct neigh_table *tbl,
			      int (*cb)(struct neighbour *))
{
	int chain;

	for (chain = 0; chain <= tbl->hash_mask; chain++) {
		struct neighbour *n, **np;

		np = &tbl->hash_buckets[chain];
		while ((n = *np) != NULL) {
			int release;

			write_lock(&n->lock);
			release = cb(n);
			if (release) {
				*np = n->next;
				n->dead = 1;
			} else
				np = &n->next;
			write_unlock(&n->lock);
			if (release)
				neigh_cleanup_and_release(n);
		}
	}
}
EXPORT_SYMBOL(__neigh_for_each_release);

#ifdef CONFIG_PROC_FS

static struct neighbour *neigh_get_first(struct seq_file *seq)
{
	struct neigh_seq_state *state = seq->private;
	struct net *net = seq_file_net(seq);
	struct neigh_table *tbl = state->tbl;
	struct neighbour *n = NULL;
	int bucket = state->bucket;

	state->flags &= ~NEIGH_SEQ_IS_PNEIGH;
	for (bucket = 0; bucket <= tbl->hash_mask; bucket++) {
		n = tbl->hash_buckets[bucket];

		while (n) {
			if (!net_eq(dev_net(n->dev), net))
				goto next;
			if (state->neigh_sub_iter) {
				loff_t fakep = 0;
				void *v;

				v = state->neigh_sub_iter(state, n, &fakep);
				if (!v)
					goto next;
			}
			if (!(state->flags & NEIGH_SEQ_SKIP_NOARP))
				break;
			if (n->nud_state & ~NUD_NOARP)
				break;
		next:
			n = n->next;
		}

		if (n)
			break;
	}
	state->bucket = bucket;

	return n;
}

static struct neighbour *neigh_get_next(struct seq_file *seq,
					struct neighbour *n,
					loff_t *pos)
{
	struct neigh_seq_state *state = seq->private;
	struct net *net = seq_file_net(seq);
	struct neigh_table *tbl = state->tbl;

	if (state->neigh_sub_iter) {
		void *v = state->neigh_sub_iter(state, n, pos);
		if (v)
			return n;
	}
	n = n->next;

	while (1) {
		while (n) {
			if (!net_eq(dev_net(n->dev), net))
				goto next;
			if (state->neigh_sub_iter) {
				void *v = state->neigh_sub_iter(state, n, pos);
				if (v)
					return n;
				goto next;
			}
			if (!(state->flags & NEIGH_SEQ_SKIP_NOARP))
				break;

			if (n->nud_state & ~NUD_NOARP)
				break;
		next:
			n = n->next;
		}

		if (n)
			break;

		if (++state->bucket > tbl->hash_mask)
			break;

		n = tbl->hash_buckets[state->bucket];
	}

	if (n && pos)
		--(*pos);
	return n;
}

static struct neighbour *neigh_get_idx(struct seq_file *seq, loff_t *pos)
{
	struct neighbour *n = neigh_get_first(seq);

	if (n) {
		--(*pos);
		while (*pos) {
			n = neigh_get_next(seq, n, pos);
			if (!n)
				break;
		}
	}
	return *pos ? NULL : n;
}

static struct pneigh_entry *pneigh_get_first(struct seq_file *seq)
{
	struct neigh_seq_state *state = seq->private;
	struct net *net = seq_file_net(seq);
	struct neigh_table *tbl = state->tbl;
	struct pneigh_entry *pn = NULL;
	int bucket = state->bucket;

	state->flags |= NEIGH_SEQ_IS_PNEIGH;
	for (bucket = 0; bucket <= PNEIGH_HASHMASK; bucket++) {
		pn = tbl->phash_buckets[bucket];
		while (pn && !net_eq(pneigh_net(pn), net))
			pn = pn->next;
		if (pn)
			break;
	}
	state->bucket = bucket;

	return pn;
}

static struct pneigh_entry *pneigh_get_next(struct seq_file *seq,
					    struct pneigh_entry *pn,
					    loff_t *pos)
{
	struct neigh_seq_state *state = seq->private;
	struct net *net = seq_file_net(seq);
	struct neigh_table *tbl = state->tbl;

	pn = pn->next;
	while (!pn) {
		if (++state->bucket > PNEIGH_HASHMASK)
			break;
		pn = tbl->phash_buckets[state->bucket];
		while (pn && !net_eq(pneigh_net(pn), net))
			pn = pn->next;
		if (pn)
			break;
	}

	if (pn && pos)
		--(*pos);

	return pn;
}

static struct pneigh_entry *pneigh_get_idx(struct seq_file *seq, loff_t *pos)
{
	struct pneigh_entry *pn = pneigh_get_first(seq);

	if (pn) {
		--(*pos);
		while (*pos) {
			pn = pneigh_get_next(seq, pn, pos);
			if (!pn)
				break;
		}
	}
	return *pos ? NULL : pn;
}

static void *neigh_get_idx_any(struct seq_file *seq, loff_t *pos)
{
	struct neigh_seq_state *state = seq->private;
	void *rc;
	loff_t idxpos = *pos;

	rc = neigh_get_idx(seq, &idxpos);
	if (!rc && !(state->flags & NEIGH_SEQ_NEIGH_ONLY))
		rc = pneigh_get_idx(seq, &idxpos);

	return rc;
}

void *neigh_seq_start(struct seq_file *seq, loff_t *pos, struct neigh_table *tbl, unsigned int neigh_seq_flags)
	__acquires(tbl->lock)
{
	struct neigh_seq_state *state = seq->private;

	state->tbl = tbl;
	state->bucket = 0;
	state->flags = (neigh_seq_flags & ~NEIGH_SEQ_IS_PNEIGH);

	read_lock_bh(&tbl->lock);

	return *pos ? neigh_get_idx_any(seq, pos) : SEQ_START_TOKEN;
}
EXPORT_SYMBOL(neigh_seq_start);

void *neigh_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct neigh_seq_state *state;
	void *rc;

	if (v == SEQ_START_TOKEN) {
		rc = neigh_get_first(seq);
		goto out;
	}

	state = seq->private;
	if (!(state->flags & NEIGH_SEQ_IS_PNEIGH)) {
		rc = neigh_get_next(seq, v, NULL);
		if (rc)
			goto out;
		if (!(state->flags & NEIGH_SEQ_NEIGH_ONLY))
			rc = pneigh_get_first(seq);
	} else {
		BUG_ON(state->flags & NEIGH_SEQ_NEIGH_ONLY);
		rc = pneigh_get_next(seq, v, NULL);
	}
out:
	++(*pos);
	return rc;
}
EXPORT_SYMBOL(neigh_seq_next);

void neigh_seq_stop(struct seq_file *seq, void *v)
	__releases(tbl->lock)
{
	struct neigh_seq_state *state = seq->private;
	struct neigh_table *tbl = state->tbl;

	read_unlock_bh(&tbl->lock);
}
EXPORT_SYMBOL(neigh_seq_stop);

/* statistics via seq_file */

static void *neigh_stat_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct proc_dir_entry *pde = seq->private;
	struct neigh_table *tbl = pde->data;
	int cpu;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	for (cpu = *pos-1; cpu < nr_cpu_ids; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return per_cpu_ptr(tbl->stats, cpu);
	}
	return NULL;
}

static void *neigh_stat_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct proc_dir_entry *pde = seq->private;
	struct neigh_table *tbl = pde->data;
	int cpu;

	for (cpu = *pos; cpu < nr_cpu_ids; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return per_cpu_ptr(tbl->stats, cpu);
	}
	return NULL;
}

static void neigh_stat_seq_stop(struct seq_file *seq, void *v)
{

}

static int neigh_stat_seq_show(struct seq_file *seq, void *v)
{
	struct proc_dir_entry *pde = seq->private;
	struct neigh_table *tbl = pde->data;
	struct neigh_statistics *st = v;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "entries  allocs destroys hash_grows  lookups hits  res_failed  rcv_probes_mcast rcv_probes_ucast  periodic_gc_runs forced_gc_runs unresolved_discards\n");
		return 0;
	}

	seq_printf(seq, "%08x  %08lx %08lx %08lx  %08lx %08lx  %08lx  "
			"%08lx %08lx  %08lx %08lx %08lx\n",
		   atomic_read(&tbl->entries),

		   st->allocs,
		   st->destroys,
		   st->hash_grows,

		   st->lookups,
		   st->hits,

		   st->res_failed,

		   st->rcv_probes_mcast,
		   st->rcv_probes_ucast,

		   st->periodic_gc_runs,
		   st->forced_gc_runs,
		   st->unres_discards
		   );

	return 0;
}

static const struct seq_operations neigh_stat_seq_ops = {
	.start	= neigh_stat_seq_start,
	.next	= neigh_stat_seq_next,
	.stop	= neigh_stat_seq_stop,
	.show	= neigh_stat_seq_show,
};

static int neigh_stat_seq_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &neigh_stat_seq_ops);

	if (!ret) {
		struct seq_file *sf = file->private_data;
		sf->private = PDE(inode);
	}
	return ret;
};

static const struct file_operations neigh_stat_seq_fops = {
	.owner	 = THIS_MODULE,
	.open 	 = neigh_stat_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

#endif /* CONFIG_PROC_FS */

static inline size_t neigh_nlmsg_size(void)
{
	return NLMSG_ALIGN(sizeof(struct ndmsg))
	       + nla_total_size(MAX_ADDR_LEN) /* NDA_DST */
	       + nla_total_size(MAX_ADDR_LEN) /* NDA_LLADDR */
	       + nla_total_size(sizeof(struct nda_cacheinfo))
	       + nla_total_size(4); /* NDA_PROBES */
}

static void __neigh_notify(struct neighbour *n, int type, int flags)
{
	struct net *net = dev_net(n->dev);
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(neigh_nlmsg_size(), GFP_ATOMIC);
	if (skb == NULL)
		goto errout;

	err = neigh_fill_info(skb, n, 0, 0, type, flags);
	if (err < 0) {
		/* -EMSGSIZE implies BUG in neigh_nlmsg_size() */
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}
	rtnl_notify(skb, net, 0, RTNLGRP_NEIGH, NULL, GFP_ATOMIC);
	return;
errout:
	if (err < 0)
		rtnl_set_sk_err(net, RTNLGRP_NEIGH, err);
}

#ifdef CONFIG_ARPD
void neigh_app_ns(struct neighbour *n)
{
	__neigh_notify(n, RTM_GETNEIGH, NLM_F_REQUEST);
}
EXPORT_SYMBOL(neigh_app_ns);
#endif /* CONFIG_ARPD */

#ifdef CONFIG_SYSCTL

static struct neigh_sysctl_table {
	struct ctl_table_header *sysctl_header;
	struct ctl_table neigh_vars[__NET_NEIGH_MAX];
	char *dev_name;
} neigh_sysctl_template __read_mostly = {
	.neigh_vars = {
		{
			.ctl_name	= NET_NEIGH_MCAST_SOLICIT,
			.procname	= "mcast_solicit",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_UCAST_SOLICIT,
			.procname	= "ucast_solicit",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_APP_SOLICIT,
			.procname	= "app_solicit",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		{
			.procname	= "retrans_time",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_userhz_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_REACHABLE_TIME,
			.procname	= "base_reachable_time",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_jiffies,
			.strategy	= sysctl_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_DELAY_PROBE_TIME,
			.procname	= "delay_first_probe_time",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_jiffies,
			.strategy	= sysctl_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_GC_STALE_TIME,
			.procname	= "gc_stale_time",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_jiffies,
			.strategy	= sysctl_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_UNRES_QLEN,
			.procname	= "unres_qlen",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_PROXY_QLEN,
			.procname	= "proxy_qlen",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		{
			.procname	= "anycast_delay",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_userhz_jiffies,
		},
		{
			.procname	= "proxy_delay",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_userhz_jiffies,
		},
		{
			.procname	= "locktime",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_userhz_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_RETRANS_TIME_MS,
			.procname	= "retrans_time_ms",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_ms_jiffies,
			.strategy	= sysctl_ms_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_REACHABLE_TIME_MS,
			.procname	= "base_reachable_time_ms",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_ms_jiffies,
			.strategy	= sysctl_ms_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_GC_INTERVAL,
			.procname	= "gc_interval",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_jiffies,
			.strategy	= sysctl_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_GC_THRESH1,
			.procname	= "gc_thresh1",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_GC_THRESH2,
			.procname	= "gc_thresh2",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_GC_THRESH3,
			.procname	= "gc_thresh3",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		{},
	},
};

int neigh_sysctl_register(struct net_device *dev, struct neigh_parms *p,
			  int p_id, int pdev_id, char *p_name,
			  proc_handler *handler, ctl_handler *strategy)
{
	struct neigh_sysctl_table *t;
	const char *dev_name_source = NULL;

#define NEIGH_CTL_PATH_ROOT	0
#define NEIGH_CTL_PATH_PROTO	1
#define NEIGH_CTL_PATH_NEIGH	2
#define NEIGH_CTL_PATH_DEV	3

	struct ctl_path neigh_path[] = {
		{ .procname = "net",	 .ctl_name = CTL_NET, },
		{ .procname = "proto",	 .ctl_name = 0, },
		{ .procname = "neigh",	 .ctl_name = 0, },
		{ .procname = "default", .ctl_name = NET_PROTO_CONF_DEFAULT, },
		{ },
	};

	t = kmemdup(&neigh_sysctl_template, sizeof(*t), GFP_KERNEL);
	if (!t)
		goto err;

	t->neigh_vars[0].data  = &p->mcast_probes;
	t->neigh_vars[1].data  = &p->ucast_probes;
	t->neigh_vars[2].data  = &p->app_probes;
	t->neigh_vars[3].data  = &p->retrans_time;
	t->neigh_vars[4].data  = &p->base_reachable_time;
	t->neigh_vars[5].data  = &p->delay_probe_time;
	t->neigh_vars[6].data  = &p->gc_staletime;
	t->neigh_vars[7].data  = &p->queue_len;
	t->neigh_vars[8].data  = &p->proxy_qlen;
	t->neigh_vars[9].data  = &p->anycast_delay;
	t->neigh_vars[10].data = &p->proxy_delay;
	t->neigh_vars[11].data = &p->locktime;
	t->neigh_vars[12].data  = &p->retrans_time;
	t->neigh_vars[13].data  = &p->base_reachable_time;

	if (dev) {
		dev_name_source = dev->name;
		neigh_path[NEIGH_CTL_PATH_DEV].ctl_name = dev->ifindex;
		/* Terminate the table early */
		memset(&t->neigh_vars[14], 0, sizeof(t->neigh_vars[14]));
	} else {
		dev_name_source = neigh_path[NEIGH_CTL_PATH_DEV].procname;
		t->neigh_vars[14].data = (int *)(p + 1);
		t->neigh_vars[15].data = (int *)(p + 1) + 1;
		t->neigh_vars[16].data = (int *)(p + 1) + 2;
		t->neigh_vars[17].data = (int *)(p + 1) + 3;
	}


	if (handler || strategy) {
		/* RetransTime */
		t->neigh_vars[3].proc_handler = handler;
		t->neigh_vars[3].strategy = strategy;
		t->neigh_vars[3].extra1 = dev;
		if (!strategy)
			t->neigh_vars[3].ctl_name = CTL_UNNUMBERED;
		/* ReachableTime */
		t->neigh_vars[4].proc_handler = handler;
		t->neigh_vars[4].strategy = strategy;
		t->neigh_vars[4].extra1 = dev;
		if (!strategy)
			t->neigh_vars[4].ctl_name = CTL_UNNUMBERED;
		/* RetransTime (in milliseconds)*/
		t->neigh_vars[12].proc_handler = handler;
		t->neigh_vars[12].strategy = strategy;
		t->neigh_vars[12].extra1 = dev;
		if (!strategy)
			t->neigh_vars[12].ctl_name = CTL_UNNUMBERED;
		/* ReachableTime (in milliseconds) */
		t->neigh_vars[13].proc_handler = handler;
		t->neigh_vars[13].strategy = strategy;
		t->neigh_vars[13].extra1 = dev;
		if (!strategy)
			t->neigh_vars[13].ctl_name = CTL_UNNUMBERED;
	}

	t->dev_name = kstrdup(dev_name_source, GFP_KERNEL);
	if (!t->dev_name)
		goto free;

	neigh_path[NEIGH_CTL_PATH_DEV].procname = t->dev_name;
	neigh_path[NEIGH_CTL_PATH_NEIGH].ctl_name = pdev_id;
	neigh_path[NEIGH_CTL_PATH_PROTO].procname = p_name;
	neigh_path[NEIGH_CTL_PATH_PROTO].ctl_name = p_id;

	t->sysctl_header =
		register_net_sysctl_table(neigh_parms_net(p), neigh_path, t->neigh_vars);
	if (!t->sysctl_header)
		goto free_procname;

	p->sysctl_table = t;
	return 0;

free_procname:
	kfree(t->dev_name);
free:
	kfree(t);
err:
	return -ENOBUFS;
}
EXPORT_SYMBOL(neigh_sysctl_register);

void neigh_sysctl_unregister(struct neigh_parms *p)
{
	if (p->sysctl_table) {
		struct neigh_sysctl_table *t = p->sysctl_table;
		p->sysctl_table = NULL;
		unregister_sysctl_table(t->sysctl_header);
		kfree(t->dev_name);
		kfree(t);
	}
}
EXPORT_SYMBOL(neigh_sysctl_unregister);

#endif	/* CONFIG_SYSCTL */

static int __init neigh_init(void)
{
	rtnl_register(PF_UNSPEC, RTM_NEWNEIGH, neigh_add, NULL);
	rtnl_register(PF_UNSPEC, RTM_DELNEIGH, neigh_delete, NULL);
	rtnl_register(PF_UNSPEC, RTM_GETNEIGH, NULL, neigh_dump_info);

	rtnl_register(PF_UNSPEC, RTM_GETNEIGHTBL, NULL, neightbl_dump_info);
	rtnl_register(PF_UNSPEC, RTM_SETNEIGHTBL, neightbl_set, NULL);

	return 0;
}

subsys_initcall(neigh_init);

