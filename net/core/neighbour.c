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
 * �ú������ڴ���neighbour�ṹ����ɾ������ʱ�������Ϊ������ȻҪ�������neighbour�ṹ������neigh_blackhole�ᶪ��������ӿ�
 * �Ͻ��յ��κη����Ϊ��ȷ���κ���ͼ���ھӴ��ͷ������Ϊ���ᷢ��,���������Ǳ���ġ���Ϊ�ھӵ����ݽṹ��Ҫ��ɾ����
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
 * �����ڼ����1/2��* base ...��3/2��* base�е�����ֲ��� ����Ӧ��Ĭ�ϵ�IPv6���ã������ǿ��Ը��ǵģ���Ϊ�������������ѡ��
 */

unsigned long neigh_rand_reach_time(unsigned long base)
{
	return (base ? (net_random() % base) + (base >> 1) : 0);
}
EXPORT_SYMBOL(neigh_rand_reach_time);

/*
 * �ú�����ɾ������hash�������еķ���������Ԫ�ء�ͬʱ����һ����������:
 * 1.���ü���ֵΪ1����ʾû�к�����ṹʹ�ø�Ԫ�أ�����ɾ����Ԫ�ز�Ӱ�챣��ʣ�����õ���ϵͳ��
 * 2.��Ԫ�ز���NUD_PERMANENT̬���ڸ�״̬��Ԫ���Ǿ�̬���õģ���˲�����ڡ�
*/
static int neigh_forced_gc(struct neigh_table *tbl)
{
	int shrunk = 0;
	int i;

	NEIGH_CACHE_STAT_INC(tbl, forced_gc_runs);

	/* ��ͬ������ʱ����������е��ھ���(�������첽����ʱ��ֻ����ɢ�б��һ��Ͱ)�������ü���Ϊ1�ҷǾ�̬���ھ���ȫ�������
	   ��󷵻��Ƿ�ִ��������ı�־��������ֵΪ1��ʾִ��������0��ʾû�������ھ��
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
	neigh_hold(n);//�����ھӽṹ��ʹ�ü���
	/*
	 * ��ʱ��������л�����ִ�ж�ʱ�����������ʱ������ǰ��neigh_alloc()�������õ�,�䶨ʱִ�к���Ϊneigh_timer_handler()
	 * ���������Ǽ���ھӽṹ��ʱ�䣬����������״̬��
	*/
	if (unlikely(mod_timer(&n->timer, when))) {//���ö�ʱ���Ķ�ʱִ��ʱ�����붨ʱ����
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
 * �����Ƶ�ip link set eth0 lladdr 01:02:03:04:05:06�������neigh_changeaddr�����ı��ַʱ�����������ɨ��Э�黺����
 * �������������Ҫ�ı��ַ���豸��ص�����Ϊͣ��(dead)���������ս��̸�������Щͣ���
*/
void neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev)
{
	write_lock_bh(&tbl->lock);
	neigh_flush_dev(tbl, dev);
	write_unlock_bh(&tbl->lock);
}
EXPORT_SYMBOL(neigh_changeaddr);

/* һ������:
 * �ھ���ϵͳά�����ھ����У�����ʲôʱ��ֻҪ�ھ�������һ����ҪԪ��(L3��ַ��L2��ַ��ӿ��豸)�仯�ˣ���ô����Ҳ��ʧЧ�ˡ�
 * ��ʱ���ں˱���ȷ���ھ�Э���ܹ�ָ����Щ��Ϣ�Ƿ����仯��
 * �������ں���ϵͳҪ���øú�������֪ͨ�ھ���ϵͳ�й��豸��L3��ַ�ı仯��
 * L3��ַ�ı��֪ͨ��L3Э���ͳ���
 * �����������ھ�ϴ�¸���Ȥ���ⲿ�������Ϊ�ͺ���������ʾ:
 * 1.�豸�ر�:ÿ���ھ����һ���豸���������ˣ�������豸ֹͣ�����ˣ���ô������֮��ص��ھ��Ҫ��ɾ����
 * 2.L3��ַ�ı�:�������Ա�ı��˽ӿ����ã���ǰͨ���ýӿڿɵ���������п���ͨ�������޷�����ı�ӿڵ�L3��ַ����neigh_ifdown������
 * 3.Э��ر�:�����Ϊģ�鰲װ��L3Э����ں���ж���ˣ���ô������ص���������������ã�����Ҫɾ����
 * ����������neighbour�ṹ��Ҫִ�еĶ���:
 *     ����������е�neighbour�ṹ���ҵ��봥���¼����豸��صĽṹ��Ȼ��ʹ�䲻�ٿ��ã���������ɾ������Ϊ�ھ���ϵͳ�ڿ��������á�
 *     ��neigh_ifdown�ѻ����е�����������豸��ص��������֮�󣬾͵���pneigh_ifdown���������ʹ����������proxy_queue�����е������.
 * 1.ֹͣ����δ���Ķ�ʱ����
 * 2.������ھ����״̬��ΪNUD_NOARP̬��������ͼʹ�ø��ھ�����κ��������ٻᴥ��solicitation����
 * 3.ʹ��neigh->outputָ��neigh_blackhole���Ա㶪���͵����ھӵķ�������ǽ����ύ��
 * 4.����skb_queue_purge,��������arp_queue�����д�����ķ��������
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
 * �ú������ڷ����µ�neighbour���ݴ洢�ռ�,�ú���Ҳ���ڳ�ʼ��һЩ���������磬Ƕ��Ķ�ʱ�������ü�������ָ�������neigh_table(�ھ�Э��)
 * �ṹ��ָ��ͶԷ����neighbour�ṹ��Ŀ������ͳ�ơ��˺���ʹ���ھ���ϵͳ��ʼ��ʱ�������ڴ�ء������ǰ������ھӽṹ��Ŀ�������õ���ֵ��
 * ���ҽ�������������������ͼ�ͷ�ĳ���ڴ�ʧ���ˣ��ú������޷���ɷ��䡣
 * ����Ϊtbl:�������ھ������ڵ��ھӱ�
*/
static struct neighbour *neigh_alloc(struct neigh_table *tbl)
{
	struct neighbour *n = NULL;
	unsigned long now = jiffies;
	int entries;

	/* time_after()����������һ�λ��յ����ڵ�ʵ�ʼ���������Ҫ���վ�����neigh_forced_gc()������
	 * �����ھӽṹ��ʹ�ü�����״̬���л���
	*/
	entries = atomic_inc_return(&tbl->entries) - 1;//��ȡ�ھӽṹ����
	if (entries >= tbl->gc_thresh3 ||
	    (entries >= tbl->gc_thresh2 &&
	     time_after(now, tbl->last_flush + 5 * HZ))) {//����Ƿ���Ҫ����:ǰ�ߵ�ʱ������ں��ߵ�ʱ��� b-a<0
		if (!neigh_forced_gc(tbl) &&//����ͬ����������
		    entries >= tbl->gc_thresh3)//���պ�������Ȼ���������ֵ
			goto out_entries;
	}

    //���ھӱ�ָ���ĸ��ٻ����з���ṹ�ռ�
	n = kmem_cache_zalloc(tbl->kmem_cachep, GFP_ATOMIC);
	if (!n)
		goto out_entries;

	__skb_queue_head_init(&n->arp_queue);//��ʼ���ھӽṹ�Ķ���ͷ(�洢��Ҫ����ķ��)
	rwlock_init(&n->lock);
	n->updated	  = n->used = now;//��¼��ǰʱ��
	n->nud_state	  = NUD_NONE;//����״̬
	n->output	  = neigh_blackhole;//���÷��ͺ���
	n->parms	  = neigh_parms_clone(&tbl->parms);//��¼�ھӲ����ṹ
	setup_timer(&n->timer, neigh_timer_handler, (unsigned long)n);//��ʼ����ʱ������ʱ������Ϊneigh_timer_handler
	/*
	setup_timer ����/include/linux/time.h�к���
	static inline void setup_timer_key(struct timer_list * timer,
				const char *name,
				struct lock_class_key *key,
				void (*function)(unsigned long),
				unsigned long data)
{
	timer->function = function;        //��¼�ھӽṹ�Ķ�ʱִ�к���neigh_timer_handler()
	timer->data = data;                //��¼�ھӽṹ�ĵ�ַ
	init_timer_key(timer, name, key);  //��ʼ����ʱ��
}
    ����ֻ�ǳ�ʼ���˶�ʱ������û�н��������ں˵Ķ�ʱ��ִ�ж��У���˳�ʼ���󻹻�ִ�ж�ʱ����neigh_timer_handler(),
    �ں���__neigh_event_send()�����Ĺ����п��������ʱ��������
	*/

	NEIGH_CACHE_STAT_INC(tbl, allocs);//�������������
	n->tbl		  = tbl;//��¼�ھӱ�
	atomic_set(&n->refcnt, 1);//����ʹ�ü���
	n->dead		  = 1;//��ʼɾ����־
out:
	return n;

out_entries:
	atomic_dec(&tbl->entries);//�ݼ��ھӽṹ������
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
����ԭ�ͣ�
static void neigh_hash_grow(struct neigh_table *tbl, unsigned long new_entries)
���ã�
�ڴ����ھ���ʱ������ڼ���Ҫ�������ھ�����ھӱ��ھ���ļ����������ھ�ɢ�б���������ͻ����neigh_hash_grow()�����ھ�ɢ�б�
������
tbl,�������ھ���ɢ�б��������ھӱ�ARP�е�arp_tbl
new_entries,���ݺ��ھ�ɢ�б������

*/
static void neigh_hash_grow(struct neigh_table *tbl, unsigned long new_entries)
{
	struct neighbour **new_hash, **old_hash;
	unsigned int i, new_hash_mask, old_entries;

	NEIGH_CACHE_STAT_INC(tbl, hash_grows);

	BUG_ON(!is_power_of_2(new_entries));
	/*
	����neigh_hash_alloc()Ϊ�ھ���ɢ�б����·����ڴ棬�ڸú����У����ݴ�������ڴ�������PAGE_SIZE�����ȷ��ʹ��
	kzalloc()����get_free_pages()�����ڴ�
	*/
	new_hash = neigh_hash_alloc(new_entries);
	if (!new_hash)
		return;

	old_entries = tbl->hash_mask + 1;
	new_hash_mask = new_entries - 1;
	old_hash = tbl->hash_buckets;

	get_random_bytes(&tbl->hash_rnd, sizeof(tbl->hash_rnd));//���¼������ֵhash_rand
	/*
	�Ƚ�ԭ���ھ���ɢ�б��е��ھ����ƶ������ݺ���ھ���ɢ�б��У�Ȼ����ɢ�����б���hash_mask���浽�ھӱ���
	*/
	for (i = 0; i < old_entries; i++) {
		struct neighbour *n, *next;

		for (n = old_hash[i]; n; n = next) {
			unsigned int hash_val = tbl->hash(n->primary_key, n->dev);

			hash_val &= new_hash_mask;
			next = n->next;

			n->next = new_hash[hash_val];//����Ӧ��ɢ��Ͱ�еĶ����ײ����
			new_hash[hash_val] = n;
		}
	}
	tbl->hash_buckets = new_hash;
	tbl->hash_mask = new_hash_mask;

	neigh_hash_free(old_hash, old_entries);//����neigh_hash_free()�ͷž��ھ�ɢ�б���ռ�õ��ڴ�
}
/*
 * �ú�������arp_tbl�м��Ҫ���ҵ�Ԫ��(���غ��豸)�Ƿ���ڣ������ڲ��ҳɹ�ʱ����ָ���Ԫ�ص�ָ�롣
���ã�
�ھ���Ĳ��ҷǳ�Ƶ��������ھ���ʱ��Ҫ�����ھ����Ƿ��Ѵ��ڣ�ɾ���ھ���ʱ��Ҫ���Ҵ�ɾ�����ھ����Ƿ���ڡ�
������
tbl��Ϊ�����ҵ��ھӱ�
pkey��dev,�ǲ���������������Э���ַ���ھ��������豸
*/
struct neighbour *neigh_lookup(struct neigh_table *tbl, const void *pkey,
			       struct net_device *dev)
{
	struct neighbour *n;
	int key_len = tbl->key_len;//ȡ�õ�ַ����
	u32 hash_val;

	NEIGH_CACHE_STAT_INC(tbl, lookups);//���������ھӱ������

	read_lock_bh(&tbl->lock);
	hash_val = tbl->hash(pkey, dev);//�����ھӱ��еĹ�ϣ���㺯��ȷ����ϣֵ
	//�ڹ�ϣͰ�в���ָ���豸��ָ�����ص��ھӽṹ
	for (n = tbl->hash_buckets[hash_val & tbl->hash_mask]; n; n = n->next) {
		if (dev == n->dev && !memcmp(n->primary_key, pkey, key_len)) {
			neigh_hold(n);//�����ھӽṹ�ļ�����
			NEIGH_CACHE_STAT_INC(tbl, hits);//�����ھӱ�����м�����
			break;
		}
	}
	read_unlock_bh(&tbl->lock);
	return n;//�����ҵ����ھӽṹ
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
*����:���������ش���һ���ھ����������ӵ�ɢ�б��ϣ���󷵻�ָ����ھ����ָ��
*tbl: �������ھӱ����������ھӱ�,��ARP��Ϊarp_tbl
*pkey: ��һ������Э���ַ����Ϊ�ھӱ���Ĺؼ���
*dev: ���ھӱ��������豸,��Ҫ�������ھ�����ص��豸����Ϊÿ��neighbour���һ��L3��ַ����������Һ���������һ���豸�������
*     ����neighbourʵ������һ���豸�������
**/
struct neighbour *neigh_create(struct neigh_table *tbl, const void *pkey,
			       struct net_device *dev)
{
	u32 hash_val;
	int key_len = tbl->key_len;//ȡ��IP��ַ������Ϊ��ֵ
	int error;
	/*
	����Ϊ�µ��ھӱ���struct neighbour����ռ䣬����һЩ��ʼ����
	����Ĳ���tbl����ȫ����arp_tbl������ռ�Ĵ�С��tbl->entry_size��
	�����ֵ������arp_tblʱ��ʼ��Ϊsizeof(struct neighbour) + 4�������4���ֽھ���keyֵ��ŵĵط���
	*/
	struct neighbour *n1, *rc, *n = neigh_alloc(tbl);/*����һ���ھӽṹʵ��*/

	if (!n) {//����ʧ�ܷ���
		rc = ERR_PTR(-ENOBUFS);
		goto out;
	}

	/*�������ַ������豸���õ��ھӱ�����*/
	memcpy(n->primary_key, pkey, key_len);//key_len��Ҫ�ģ���Ϊneighbour�ṹ�Ǳ���Э���޹صĻ�����Һ���ʹ�ã����Ҹ����ھ�Э���ʾ��ַ���ֽڳ��Ȳ�ͬ��
	n->dev = dev;//����neighbour���а����˶�net_device�ṹ��dev�����ã��ں˻�ʹ��dev_hold���Ժ��ߵ����ü�������1���Դ�����֤���豸��neighbour�ṹ�����ǲ��ᱻɾ����
	dev_hold(dev);//�����豸�ļ�����

	/* Protocol specific setup. ִ�����ھ�Э����صĳ�ʼ�����������arp_tbl�ṹ�����ݣ�ʵ��ִ��ARP��Ϊarp_constructor*/
	if (tbl->constructor &&	(error = tbl->constructor(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}

	/* Device specific setup. �豸ִ�еĳ�ʼ��������neigh_setup�麯�����*/
	if (n->parms->neigh_setup &&//���ָ���˰�װ������ִ����
	    (error = n->parms->neigh_setup(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}
	
	/*���������ھӱ�������ھӱ���hash����*/
	//confirmed�ֶΣ���ʾ���ھ��ǿɵ����,��������£����ֶ��ɿɵ�����֤�������£�������ֵ����Ϊjiffies��ʾ�ĵ�ǰʱ�䣬
	//����������½��ĽǶ���˵��neigh_create�������confirmedֵ��ȥһС��ʱ��(reachable_timeֵ��һ��)��������ʹ���ھ�
	//״̬�ܱ�ƽ����Ҫ���пɵ�����֤��ʱ���Կ��ת�Ƶ�NUD_STALE̬
	n->confirmed = jiffies - (n->parms->base_reachable_time << 1);//ȷ��ʱ�䣬����jiffiesΪ��ǰʱ��

	write_lock_bh(&tbl->lock);

    //����ھӽṹ���������˹�ϣͰ�ĳ���
	if (atomic_read(&tbl->entries) > (tbl->hash_mask + 1))
		neigh_hash_grow(tbl, (tbl->hash_mask + 1) << 1);//������ϣͰ,����1��

	hash_val = tbl->hash(pkey, dev) & tbl->hash_mask;//�����ϣֵ

	if (n->parms->dead) {//�ھ����ò������ڱ�ɾ����������ʹ�ã����Ҳ�Ͳ����ټ��������ھ�����
		rc = ERR_PTR(-EINVAL);
		goto out_tbl_unlock;
	}

	//�ڹ�ϣͰ�в���Ҫ����Ķ���
	for (n1 = tbl->hash_buckets[hash_val]; n1; n1 = n1->next) {
		if (dev == n1->dev && !memcmp(n1->primary_key, pkey, key_len)) {
			neigh_hold(n1);
			rc = n1;//��¼��ͬ��ַ���豸���ھӽṹ��ֱ�ӷ����ҵ����ھӽṹ
			goto out_tbl_unlock;
		}
	}

	n->next = tbl->hash_buckets[hash_val];//ָ���������һ���ھӽṹ
	tbl->hash_buckets[hash_val] = n;//�����ϣͰ
	n->dead = 0;//���ɾ����־
	neigh_hold(n);//����ʹ�ü���
	write_unlock_bh(&tbl->lock);
	NEIGH_PRINTK2("neigh %p is created.\n", n);
	rc = n;//��¼�´������ھӽṹ
out:
	return rc;//�����ھӽṹ
out_tbl_unlock:
	write_unlock_bh(&tbl->lock);
out_neigh_release:
	neigh_release(n);//�ҵ�����ͬ���ھӽṹ���ͷ��½���
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
 *  ɾ���ھӽṹ�ĺ�����Ҫ������������:
 *  1.ֹͣ����δ���Ķ�ʱ����
 *  2.�ͷ����ж��ⲿ���ݽṹ�����ã�����������豸�������L2֡ͷ.
 *  3.���һ���ھ�Э���ṩ��destructor���������ھ�Э��ͻ�ִ����������Լ������ھ��
 *  4.���arp_queue���зǿգ���Ҫ�������(ɾ��������Ԫ��)��
 *  5.����ʾ����ʹ�õ�neighbour��������ȫ�ּ�������1.
 *  6.�Ƿ��neighbour�ṹ(����ռ�õ��ڴ�ռ䷵�����ڴ��)��
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

	neigh->output = neigh->ops->connected_output;//���Կ���neigh->output����ʼ��Ϊconnected_output����ARP����neigh_connected_output

	for (hh = neigh->hh; hh; hh = hh->hh_next)
		hh->hh_output = neigh->ops->hh_output;
}

 /*
 �������л��첽�ĸ���NUD״̬,neigh_periodic_work����NUD_STALE
 ע��neigh_timer_handler��ÿ������һ���ģ���neigh_periodic_work��Ψһ��
 ��neigh����NUD_STALE״̬ʱ����ʱ���ȴ�һ��ʱ�䣬�������õ������Ӷ�ת��NUD_DELAY״̬��
 û�����ã���ת��NUD_FAIL�����ͷš���ͬ��NUD_INCOMPLETE��NUD_DELAY��NUD_PROBE��NUD_REACHABLE״̬ʱ�Ķ�ʱ����
 ����ʹ�õ��첽���ƣ�ͨ�����ڴ���neigh_periodic_work()�����NUD_STALE״̬��
*/
static void neigh_periodic_work(struct work_struct *work)
{
	/*
	neigh_periodic_work����ִ�У���Ҫ��֤��������Ӿͱ�neigh_periodic_work�������
	����Ĳ����ǣ�gc_staletime����1/2 base_reachable_time��Ĭ�ϵģ�gc_staletime = 30��
	base_reachable_time = 30��Ҳ����˵��neigh_periodic_work��ÿ15HZִ��һ�Σ�
	��������NUD_STALE�Ĵ��ʱ����30HZ����������֤��ÿ������������Ҳ��(30 - 15)HZ���������ڡ�
	*/
	struct neigh_table *tbl = container_of(work, struct neigh_table, gc_work.work);
	struct neighbour *n, **np;
	unsigned int i;

	NEIGH_CACHE_STAT_INC(tbl, periodic_gc_runs);

	write_lock_bh(&tbl->lock);

	/*
	 *	periodically recompute ReachableTime from random function ����������������¼���ReachableTime
	 */
	//ÿ300s���ھӱ�����neigh_parms�ṹʵ����NUD_REACHABLE״̬��ʱʱ��reachable_time����Ϊһ���µ����ֵ��
	if (time_after(jiffies, tbl->last_rand + 300 * HZ)) {
		struct neigh_parms *p;
		tbl->last_rand = jiffies;
		for (p = &tbl->parms; p; p = p->next)
			p->reachable_time =
				neigh_rand_reach_time(p->base_reachable_time);
	}

    //���������ھӱ�ÿ��hash_buckets��ÿ����������gc_staletime����δ�����ù��������ھӱ��������
	for (i = 0 ; i <= tbl->hash_mask; i++) {
		np = &tbl->hash_buckets[i];

		while ((n = *np) != NULL) {
			unsigned int state;

			write_lock(&n->lock);

			//���ھ�̬�ھ�����ڶ�ʱ��״̬���ھ������ֱ������
			state = n->nud_state;
			if (state & (NUD_PERMANENT | NUD_IN_TIMER)) {
				write_unlock(&n->lock);
				goto next_elt;
			}

			//����ھ�������ʹ��ʱ�������ȷ��ʱ��֮ǰ����������ʹ��ʱ��Ϊ���ȷ��ʱ��
			if (time_before(n->used, n->confirmed))
				n->used = n->confirmed;
			/*
				����neigh_release()ɾ���ͷŷ��������������ھ���:
				1.Ӧ�ü���Ϊ1��״̬ΪNUD_FAILED
				2.���ü���Ϊ1������ʱ�䳬����ָ������gc_staletime
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
		 * �������ͷ���������ȷ�ģ���ʹ��ϣ�������Ǳ���ռ��ʱ��������
		 */
		write_unlock_bh(&tbl->lock);
		cond_resched();
		write_lock_bh(&tbl->lock);
	}
	/* Cycle through all hash buckets every base_reachable_time/2 ticks.
	 * ARP entry timeouts range from 1/2 base_reachable_time to 3/2
	 * base_reachable_time.
	 */
	// �ڹ�������ٴ���Ӹù����������У�����ʱ1/2 base_reachable_time��ʼִ�У�
	// �����������neigh_periodic_work����ÿ��1/2 base_reachable_timeִ��һ�Ρ�
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
 * ����neigh_timer_handler��ʱ����neigh_periodic_work�������л��첽�ĸ���NUD״̬��
 * neigh_timer_handler����NUD_INCOMPLETE, NUD_DELAY, NUD_PROBE, NUD_REACHABLE״̬��
 * neigh_periodic_work����NUD_STALE��ע��neigh_timer_handler��ÿ������һ���ģ�
 * ��neigh_periodic_work��Ψһ�ģ�NUD_STALE״̬�ı���û��Ҫ����ʹ�ö�ʱ����
 * ���ڼ����ھͿ����ˣ���������ʡ����Դ
 *
 �ھ������״̬�У���Щ���ڶ�ʱ״̬��������Щ״̬��ת���ɶ�ʱ��������������
 ÿ���ھ����һ����ʱ�����ö�ʱ���ڴ����ھ���ʱ����ʼ�������Ĵ�����Ϊneigh_timer_handler()��
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

	//��������Щ�����ڶ�ʱ״̬���ھ���
	if (!(state & NUD_IN_TIMER)) {//��ʱ��״̬���붨ʱ���йص�״̬:NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE
#ifndef CONFIG_SMP
		printk(KERN_WARNING "neigh: timer & !nud_in_timer\n");
#endif
		goto out;
	}

	if (state & NUD_REACHABLE) {
		if (time_before_eq(now,
				   neigh->confirmed + neigh->parms->reachable_time)) {
			//�����ʱ�����ڼ��յ��Է��ı��ģ�������״̬�������ó�ʱʱ��Ϊneigh->confirmed+reachable_time
			NEIGH_PRINTK2("neigh %p is still alive.\n", neigh);
			next = neigh->confirmed + neigh->parms->reachable_time;
		} else if (time_before_eq(now,
					  neigh->used + neigh->parms->delay_probe_time)) {
		    //�����ʱ���ڼ�δ�յ��Է����ģ�������ʹ�ù������Ǩ����NUD_DELAY״̬��
		    //�����ó�ʱʱ��Ϊneigh->used+delay_probe_time
			NEIGH_PRINTK2("neigh %p is delayed.\n", neigh);
			neigh->nud_state = NUD_DELAY;
			neigh->updated = jiffies;
			neigh_suspect(neigh);
			next = now + neigh->parms->delay_probe_time;
		} else {
		    //�����ʱ���Ҽ�δ�յ��Է����ģ�Ҳδʹ�ù�������ɸ�����ܲ������ˣ�
		    //Ǩ����NUD_STALE״̬������������ɾ����neigh_periodic_work()�ᶨʱ�����NUD_STALE״̬�ı��
			NEIGH_PRINTK2("neigh %p is suspected.\n", neigh);
			neigh->nud_state = NUD_STALE;
			neigh->updated = jiffies;
			neigh_suspect(neigh);
			notify = 1;
		}
	} else if (state & NUD_DELAY) {
		if (time_before_eq(now,
				   neigh->confirmed + neigh->parms->delay_probe_time)) {
		    //�����ʱ���ڼ��յ��Է����ģ�Ǩ����NUD_REACHABLE����¼�´μ��ʱ�䵽next
		    //NUD_DELAY -> NUD_REACHABLE��״̬ת�ƣ���arp_process��Ҳ�ᵽ�����յ�arp replyʱ���б���״̬
		    //NUD_DELAY -> NUD_REACHABLE���������ߵ���������arp_process�������arp��ȷ�ϱ��ģ�
		    //��neigh_timer_handler�������4���ȷ�ϱ��ġ�
			NEIGH_PRINTK2("neigh %p is now reachable.\n", neigh);
			neigh->nud_state = NUD_REACHABLE;
			neigh->updated = jiffies;
			neigh_connect(neigh);
			notify = 1;
			next = neigh->confirmed + neigh->parms->reachable_time;
		} else {
			//�����ʱ���ڼ�δ�յ��Է��ı��ģ�Ǩ����NUD_PROBE����¼�´μ��ʱ�䵽next
			NEIGH_PRINTK2("neigh %p is probed.\n", neigh);
			neigh->nud_state = NUD_PROBE;
			neigh->updated = jiffies;
			atomic_set(&neigh->probes, 0);
			next = now + neigh->parms->retrans_time;
		}
	} else {
		/* NUD_PROBE|NUD_INCOMPLETE */
		//��neigh����NUD_PROBE��NUD_INCOMPLETE״̬ʱ����¼�´μ��ʱ�䵽next����Ϊ������״̬��Ҫ����ARP�������ģ�
		//���ǹ��̵�Ǩ��������ARP�����Ľ��̡�
		next = now + neigh->parms->retrans_time;
	}

	/*
	 * ������ʱ����ʱ���״̬ת�ƣ����neigh����NUD_PROBE��NUD_INCOMPLETE����ᷢ��ARP���ģ�
	 * �Ȼ��鱨�ķ��͵Ĵ���������������޶ȣ������Է�����û�л�Ӧ����neigh����NUD_FAILED�����ͷŵ���
	*/
	if ((neigh->nud_state & (NUD_INCOMPLETE | NUD_PROBE)) &&
	    atomic_read(&neigh->probes) >= neigh_max_probes(neigh)) {
		neigh->nud_state = NUD_FAILED;
		notify = 1;
		neigh_invalidate(neigh);
	}

	// ���ö�ʱ���´ε���ʱ��
	if (neigh->nud_state & NUD_IN_TIMER) {
		if (time_before(next, jiffies + HZ/2))
			next = jiffies + HZ/2;
		if (!mod_timer(&neigh->timer, next))
			neigh_hold(neigh);
	}
	/*
	 * ����ھӱ���״̬����NUD_INCOMPLETE ��NUD_PROBE���ҷ���ARP�������δ�ﵽ���ޣ������ھӷ���ARP���� 
     * neigh->ops->solicit�ڴ�������neighʱ����ֵ��һ����arp_solicit����������̽�����neigh->probes
	*/
	if (neigh->nud_state & (NUD_INCOMPLETE | NUD_PROBE)) {
		/*���ݻ�������еĵ�һ���*/
		struct sk_buff *skb = skb_peek(&neigh->arp_queue);
		/* keep skb alive even if arp_queue overflows ��ʹarp_queue�������Ȼ���ֻ */
		if (skb)
			skb = skb_copy(skb, GFP_ATOMIC);
		write_unlock(&neigh->lock);
		neigh->ops->solicit(neigh, skb);/*����ARP����*///neigh->ops->solicit����ʼ��Ϊarp_solicit()����������ͷ���ARP���󡣵��Ƿ�����������أ�
		atomic_inc(&neigh->probes);     //��Ȼ�ǵȴ�ARPӦ���ˣ����յ�ARPӦ������ջ����arp_process()��������
		kfree_skb(skb);
	} else {
out:
		write_unlock(&neigh->lock);
	}

	//�����Ȥ��ģ��֪ͨNETEVENT_NEIGH_UPDATE�¼����������ʱ֧��ARPD,����֪ͨarpd����
	if (notify)
		neigh_update_notify(neigh);

	neigh_release(neigh);
}

/*
 *����neigh_resolve_output��ִ�н��������1�����ھӱ�����ΪNUD_INCOMPLETE��
 *2���������͵ı��Ĵ����ھӱ���Ļ�����С���������ͺ�����ˣ��ھӱ����е�mac��ַ����û���ҵ�����
 *��˵���ݰ��������ھӱ��������ȥ�Ժ���˭�������أ�
 *ע��ǰ��neigh_add_timer���������ھӱ����״̬��ʱ�������״̬��ʱ���Ĵ�����Ϊneigh_timer_handler��
*/
int __neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	int rc;
	unsigned long now;

	write_lock_bh(&neigh->lock);

	rc = 0;
	/*�ھ�״̬����NUD_CONNECTED��NUD_DELAY��NUD_PROBE��ֱ�ӷ��� */
	if (neigh->nud_state & (NUD_CONNECTED | NUD_DELAY | NUD_PROBE))
		goto out_unlock_bh;//������ӣ��ӳ٣�̽��״̬���˳�

	now = jiffies;//��¼��ǰʱ�䣬��������״̬ǰ��ʵ��

	/* ��ʱʣ�µ�δ����״̬ΪNUD_STALE �� NUD_INCOMPLETE��UND_NONE��
	��������ǰ״̬��ΪNUD_STALE��NUD_INCOMPLETE ���ΪUND_NONE */
	if (!(neigh->nud_state & (NUD_STALE | NUD_INCOMPLETE))) {//������ǹ���״̬��δ���״̬
		/*���������arp�㲥�����Ļ�������Ӧ�ó������������������ھӵ�ַ��
		���ھ���״̬����ΪNUD_INCOMPLETE���������ھ�״̬����ʱ��*/
		/*
		 �ڷ���ARP����ʱ��3������- ucast_probes, mcast_probes, app_probes���ֱ������������
		 �㲥������app_probes�Ƚ����⣬һ�������Ϊ0����ʹ����arpd�ػ�����ʱ�Ż���������ֵ��
		 ����Ѿ��յ����Է��ı��ģ���֪���˶Է���MAC-IP��ARP������ʹ�õ�����ʽ��������ucast_probes������
		 ���δ�յ����Է����ģ���ʱARP����ֻ��ʹ�ù㲥��ʽ��������mcasat_probes������
		*/
		if (neigh->parms->mcast_probes + neigh->parms->app_probes) {//����ھӲ����ṹ��̽��ֵ
			atomic_set(&neigh->probes, neigh->parms->ucast_probes);//��¼̽��ֵ
			neigh->nud_state     = NUD_INCOMPLETE;//�޸�Ϊδ���״̬
			neigh->updated = jiffies;//��¼��ǰʱ�䣬��������״̬���ʱ��
			neigh_add_timer(neigh, now + 1);//���ö�ʱ��
		} else {//û���趨̽��ֵ
		/*�����ھ���ֻ��ת��ΪNUD_FAILED ״̬�����ͷŴ�������ģ�ͬʱ����1����ʾ�ھ�����Ч���������*/
			neigh->nud_state = NUD_FAILED;//�޸�Ϊʧ��״̬
			neigh->updated = jiffies;//��¼��ǰʱ�䣬��������״̬���ʱ��
			write_unlock_bh(&neigh->lock);

			kfree_skb(skb);//�ͷŷ��͵����ݰ�
			return 1;
		}
	} else if (neigh->nud_state & NUD_STALE) {//����ǹ���״̬
		/*
		����ھ��ǰ״̬ΪNUD_STALE,�����б�������ˣ����״̬ת��ΪNUD_DELAY,�������ھ�״̬����ʱ����
		״̬NUD_DELAY��ʾ������������Ҳ����0
		*/
		NEIGH_PRINTK2("neigh %p is delayed.\n", neigh);
		neigh->nud_state = NUD_DELAY;//�޸�Ϊ�ӳ�״̬
		neigh->updated = jiffies;//��¼��ǰʱ�䣬��������״̬���ʱ��
		neigh_add_timer(neigh,
				jiffies + neigh->parms->delay_probe_time);//���ö�ʱ��
	}

    /* 
    ����ھ��ǰ״̬ΪNUD_INCOMPLETE��˵���������Ѿ����ͣ�����δ�յ�Ӧ�𡣴�ʱ������󻺴���г��Ȼ�δ�ﵽ���ޣ�
	�򽫴�������Ļ��浽�ö����У�����ֻ�ܶ����ñ��ġ��������������������1����ʾ�����ܷ��ͱ���	
    */
	if (neigh->nud_state == NUD_INCOMPLETE) {//�����δ���״̬
		if (skb) {//��Ҫ�������ݰ�
			/*������󻺴�����г��Ȼ�δ�ﵽ���ޣ��򽫴�������Ļ��浽�����У�����ֻ�ܶ����ñ��ġ�
			  �����������������1����ʾ�����ܷ��ͱ���*/
			if (skb_queue_len(&neigh->arp_queue) >=
			    neigh->parms->queue_len) {//�����г��ȣ��Ƿ��������ֵ
				struct sk_buff *buff;
				buff = __skb_dequeue(&neigh->arp_queue);//ȡ��������ɵ����ݰ����Ӷ���������
				kfree_skb(buff);//�ͷ����ݰ�
				NEIGH_CACHE_STAT_INC(neigh->tbl, unres_discards);
			}
			__skb_queue_tail(&neigh->arp_queue, skb);//ÿһ��neighbour������Լ���һ��С�ġ�˽�е�arp_queue���С����������ݰ��������
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
  * ���ڸ���neighbour�ṹ��·���ַ���ھӽṹ״̬��ͨ�ú����������ǰ����뵽���л��ܵ����ݰ���
  * neigh----ָ��Ҫ���µ�neighbour�ṹ
  * lladdr---�µ���·��(L2)��ַ��lladdr�������ǳ�ʼ��Ϊһ����ֵ����Ȼ����ָ����Ӳ����ַ�����ڴ����и���״̬�����������ܻ���е���
             ����,������neigh_update��ɾ��һ��neighbour�ṹʱ(������״̬ΪNUD_FAILED,"ɾ���ھ�")
  *          ���lladdr����һ��NULLֵ��
  * new------�µ�NUD״̬��
  * flags----���ڴ�����Ϣ�����磬�Ƿ�Ҫ����һ�����е���·���ַ�ȡ�
*/
int neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new,
		 u32 flags)
{
	u8 old;
	int err;
	int notify = 0;
	struct net_device *dev;
	int update_isrouter = 0;

	write_lock_bh(&neigh->lock);//����neighbour

	dev    = neigh->dev;//��ȡ�����豸�ṹ
	old    = neigh->nud_state;//��ȡ�ھӽṹ��ԭ��״̬
	err    = -EPERM;

	/*�ھӱ���mac��ַ�����*/
	/*
     *ֻ�й�������(NEIGH_UPDATE_F_ADMIN)���Ըı䵱ǰ״̬��NUD_NOARP̬��NUD_PERMANENT̬���ھӵ�״̬��
	*/
	if (!(flags & NEIGH_UPDATE_F_ADMIN) &&
	    (old & (NUD_NOARP | NUD_PERMANENT)))
		goto out;//Լ�����������㣬����ͻ��˳�

	if (!(new & NUD_VALID)) {//����״̬new����һ���Ϸ�״̬ʱ���������NUD_NONE̬��NUD_INCOMPLETE̬����Ҫֹͣ�����˵��ھӶ�ʱ��
		neigh_del_timer(neigh);//is the new state NUD_VALID,not ֹͣ��ʱ��
		if (old & NUD_CONNECTED)
			neigh_suspect(neigh);//����״̬��NUD_CONNECTED�����ú������ھ��ȱ��Ϊ���ɵ�(Ҫ����пɵ�������֤)��
		neigh->nud_state = new;//������״̬
		err = 0;
		notify = old & NUD_VALID;//֪ͨAPRD
		//��ԭ��״̬��NUD_INCOMPLETE��NUD_PROBE״̬ʱ����������ʱ��Ϊ��ַû�н������ݴ���neigh->arp_queue�еı��ģ�
		//�����ڱ�����µ�NUD_FAILED���������޷��ɹ�����ô��ô�ݴ�ı���Ҳֻ�ܱ�����neigh_invalidate��
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
	�����״̬ΪNUD_CONNECTED��˵���ھӴ�������״̬������ֱ�Ӹ��ݸ��ھ�������ݰ��������Ҫ����ȷ��ʱ�䡣
	���ø���ʱ��
	*/
	if (new & NUD_CONNECTED)
		neigh->confirmed = jiffies;
	neigh->updated = jiffies;//��¼��ǰʱ��

	/* If entry was valid and address is not changed,
	   do not change entry state, if new one is STALE.
	   �����Ŀ��Ч���ҵ�ַδ���ģ���Ҫ������Ŀ״̬������µ���STALE��
	 */
	err = 0;
	update_isrouter = flags & NEIGH_UPDATE_F_OVERRIDE_ISROUTER;//NEIGH_UPDATE_F_OVERRIDE_ISROUTER,ֻ��IPV6�д���
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
			// NUD_REACHABLE״̬ʱ����״̬ΪNUD_STALE����������δ��������ȥ�ˣ�
			// ��ΪNUD_REACHABLE״̬���ã���Ӧ�û��˵�NUD_STALE״̬��
			if (lladdr == neigh->ha && new == NUD_STALE &&
			    ((flags & NEIGH_UPDATE_F_WEAK_OVERRIDE) ||
			     (old & NUD_CONNECTED))
			    )
				new = old;
		}
	}

	//�¾�״̬��ͬʱ������ɾ����ʱ���������״̬��Ҫ��ʱ�������������ö�ʱ����������ñ���neighΪ��״̬new��
	if (new != old) {
		neigh_del_timer(neigh);//ժ����ʱ��
		if (new & NUD_IN_TIMER)//ÿ���ھӵĶ�ʱ����ÿ���������ᵼ�¸��ھӵ����ü�����1
			neigh_add_timer(neigh, (jiffies +
						((new & NUD_REACHABLE) ?
						 neigh->parms->reachable_time :
						 0)));//�������ö�ʱ��
		neigh->nud_state = new;//�޸��ھӽṹ��״̬
	}

    //����ھӱ����еĵ�ַ�����˸��£������µĵ�ֵַlladdr����ô���±����ַneigh->ha��
    //��������˱�����ص����л������neigh_update_hhs��
	if (lladdr != neigh->ha) {//���������MAC��ַ��ԭ����¼�Ĳ�ͬ
		memcpy(&neigh->ha, lladdr, dev->addr_len);//��¼������MAC��ַ
		neigh_update_hhs(neigh);
		if (!(new & NUD_CONNECTED))
			neigh->confirmed = jiffies -
				      (neigh->parms->base_reachable_time << 1);//����ȷ��ʱ��
		notify = 1;
	}
	if (new == old)//����޸�״̬��ԭʼ״̬��ͬ��ֱ�ӷ���
		goto out;
	if (new & NUD_CONNECTED)//����Ƿ�Ϊ����״̬
		neigh_connect(neigh); //����neigh->output�����������ھӽṹ�ķ��ͺ���
	else
		neigh_suspect(neigh); //�����ھӽṹ�ķ��ͺ���
	/* ����ھӱ�������Ч״̬��Ϊ��Ч״̬(ע:֮ǰ״̬ΪNUD_INCOMPLETE��������Ч״̬����������ΪNUD_REACHABLEΪ��Ч״̬��һ��) */
	if (!(old & NUD_VALID)) {
		struct sk_buff *skb;

		/* Again: avoid dead loop if something went wrong */
		/*�����ھӱ���Ļ������arp_queue���������ڶ����еı���������*/
		while (neigh->nud_state & NUD_VALID &&
		       (skb = __skb_dequeue(&neigh->arp_queue)) != NULL) {
			struct neighbour *n1 = neigh;
			write_unlock_bh(&neigh->lock);
			/* On shaper/eql skb->dst->neighbour != neigh :( */
			if (skb_dst(skb) && skb_dst(skb)->neighbour)
				n1 = skb_dst(skb)->neighbour;
			//���ڽ��ھӱ����е�mac����ˣ����������������ھӱ��Ҳ���ڽ����ݰ����ͳ�ȥ��
			//����ʹ�õķ��ͺ���Ϊneigh->output��neigh_connect�б����á� 
			//���������ھӽṹ�ķ��ͺ�����������Ȼ��neigh_resolve_output()������
			//���������øú�������ǰ��__neigh_event_send()�������뵽ARP���е����ݰ�����һ���͸�������
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
	write_unlock_bh(&neigh->lock);//����neighbour

	//����֪ͨ,ͨ���ں˵�֪ͨ����netlink�����ھӽṹ���µ���Ϣ��ǰ���arp_init()�����Ѿ����ں˵Ǽ���ARP��֪ͨ�ڵ�
	//arp_notifier��netlink��IPROUTER2���������ھ���ϵͳ��
	if (notify)//aprd��Ҫһ��֪ͨ��?�������ʱ֧��ARPD,����Ҫ֪ͨARPD����
		neigh_update_notify(neigh);

	return err;
}
EXPORT_SYMBOL(neigh_update);

struct neighbour *neigh_event_ns(struct neigh_table *tbl,
				 u8 *lladdr, void *saddr,
				 struct net_device *dev)
{
	struct neighbour *neigh = __neigh_lookup(tbl, saddr, dev,
						 lladdr || !dev->addr_len);//�����ھӽṹ
	if (neigh)
		neigh_update(neigh, lladdr, NUD_STALE,
			     NEIGH_UPDATE_F_OVERRIDE);
	return neigh;
}
EXPORT_SYMBOL(neigh_event_ns);

/*
 * �˺���ʵ��ͨ���ھ���Ϊָ��·�ɻ������Ӳ���ײ�����
*/
static void neigh_hh_init(struct neighbour *n, struct dst_entry *dst,
			  __be16 protocol)
{
	struct hh_cache	*hh;
	struct net_device *dev = dst->dev;

	/*����Э�����ھ����Ӳ�������б��в��Ҷ�Ӧ��Ӳ���ײ����档����������У�
	��ʹ�ø�Ӳ���ײ�����Ϊ·�ɻ��潨��Ӳ���ײ����档
	*/
	for (hh = n->hh; hh; hh = hh->hh_next)
		if (hh->hh_type == protocol)
			break;

	/*�������δ�����򴴽��µ�Ӳ���ײ����棬��������ӵ��ھ����Ӳ�������б��У�ͬʱ����״̬���ú��ʵ�hh_output����ָ��
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
	/* ���������еĻ����´�����Ӳ���ײ��������õ�·�ɻ������� */
	if (hh)	{
		atomic_inc(&hh->hh_refcnt);
		dst->hh = hh;
	}
}

/* This function can be used in contexts, where only old dev_queue_xmit
   worked, f.e. if you want to override normal output path (eql, shaper),
   but resolution is not made yet.
   �ú�����Ϊ�˱�֤���¼��ݡ��������ھӻ����ṹ��ǰ�������������dev_queue_xmit��������ʹL2��ַ��û��׼���á�
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
/*����:
 *���ھ������NUD_CONNECTED״̬ʱ�����������·�����ͱ��ġ�����neigh_resolve_output()�������ٶ���ȫ�������
 *ͨ��������ʼ��neigh_ops�ṹʵ����output����ָ�룬���ھ����NUD_CONNECTEDת����NUD_CONNECTED״̬��������
 *neigh_suspect���ھ����output����Ϊneigh_resolve_output()
 *ע��:
 * �ú��������ݴ���ǰ��L3��ַ����ΪL2��ַ����ˣ���L3��ַ��L2��ַ�Ķ�Ӧ��ϵ��û�н���������Ҫ����ȷ��ʱ��
 * �ͻ��õ��ú������������һ��
 * neighbour�½ṹ������Ҫ����L3��ַ���н���ʱ������"�������"�⣬neigh_resolve_output����ΪĬ�Ϻ���ʹ�õġ�
 * ��������Ҫ������ַ�������neigh_resolve_output���������ñ������Ի��漰�������NUD״̬Ǩ�ƣ�
 * NUD_NONE->NUD_INCOMPLETE��NUD_STALE->NUD_DELAY��
*/
int neigh_resolve_output(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);/*ȡ�ö�Ӧ��·�ɻ���*/
	struct neighbour *neigh;
	int rc = 0;

	if (!dst || !(neigh = dst->neighbour))//���·����������ھӽṹ��û�д��ھͷ���
		goto discard;

	/*ָ�����㣨ip��ͷ��*/
	__skb_pull(skb, skb_network_offset(skb));

	/*ȷ������������ھ���״̬��Ч���ܷ������ݰ�*/
	if (!neigh_event_send(neigh, skb)) {//����ھӽṹ�Ƿ���ã�������ü������ͣ�����0Ϊ����
		int err;
		struct net_device *dev = neigh->dev;
		/*����ھ��������豸֧��hard_header_cache��ͬʱ·�ɻ������еĶ����ײ�������δ������
		����Ϊ��·�ɻ��潨��Ӳ���ײ�����(struce hh_cache)��
		Ȼ��������ı���ǰ��Ӹ�Ӳ���ײ�������ֱ���ڱ���ǰ���Ӳ���ײ�*/
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
		
		/*������Ӳ���ײ��ɹ��������queue_xmit()����������������豸*/
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
   �˺�����ʼ��neigh_ops�ṹʵ����connected_output����ָ�롣
   ���ھ���ӷ�NUD_CONNECTEDת��NUD_CONNECTED״̬��
   �����neigh_connect()���ھ����output����Ϊneigh_connected_output()��

 * �ú���ֻ�����L2��ͷ��Ȼ�����neigh_ops->queue_xmit����ˣ���ϣ��L2��ַ��������neighbour�ṹ��NUD_CONNECTED״̬���õ����������
*/
int neigh_connected_output(struct sk_buff *skb)
{
	int err;
	struct dst_entry *dst = skb_dst(skb);
	struct neighbour *neigh = dst->neighbour;
	struct net_device *dev = neigh->dev;

	__skb_pull(skb, skb_network_offset(skb));

	read_lock_bh(&neigh->lock);
	/*�������Ķ���macͷ��,�ڴ�����ı������Ӳ���ײ�����̫���ϣ��������̫��֡�ײ� */
	err = dev_hard_header(skb, dev, ntohs(skb->protocol),
			      neigh->ha, NULL, skb->len);
	read_unlock_bh(&neigh->lock);
	//������Ӳ���ײ��ɹ��������queue_xmit()����������������豸��
	if (err >= 0)
		err = neigh->ops->queue_xmit(skb);/*����skb*/
	else {
		err = -EINVAL;
		kfree_skb(skb);
	}
	return err;
}
EXPORT_SYMBOL(neigh_connected_output);

/*
  proxy_timer��ʱ������neigh_table_init_no_netlink()�г�ʼ���ģ��䴦����Ϊneigh_proxy_process()��ÿ��proxy_timer����ʱ��
  �ú����ͻ�ӻ�����������ȡ���������ģ�ֱ��ȫ��������ϡ�
*/
static void neigh_proxy_process(unsigned long arg)
{
	struct neigh_table *tbl = (struct neigh_table *)arg;
	long sched_next = 0;
	unsigned long now = jiffies;
	struct sk_buff *skb, *n;

	spin_lock(&tbl->proxy_queue.lock);

	skb_queue_walk_safe(&tbl->proxy_queue, skb, n) {//����proxy_queue����
		long tdif = NEIGH_CB(skb)->sched_next - now;

		//�����ʱ��ʱ���Ѿ�������ǰ�����ĵ���ʱʱ�䣬�򽫸������ĴӶ�����ȡ�£�Ȼ������ھӱ�proxy_redo�ӿڵ���Ч����
		//�Լ�����豸�Ƿ������������ǵ���proxy_redo()����֮���Ƕ���֮��
		if (tdif <= 0) {
			struct net_device *dev = skb->dev;
			__skb_unlink(skb, &tbl->proxy_queue);
			if (tbl->proxy_redo && netif_running(dev))
				tbl->proxy_redo(skb);
			else
				kfree_skb(skb);

			dev_put(dev);
		} else if (!sched_next || tdif < sched_next)//���¼��㲢����proxy_timer��ʱ���´ε���ʱ�䡣
			sched_next = tdif;
	}
	del_timer(&tbl->proxy_timer);
	if (sched_next)
		mod_timer(&tbl->proxy_timer, jiffies + sched_next);
	spin_unlock(&tbl->proxy_queue.lock);
}

/*
 * ������ʱ����Ĵ���������ʱ�������pneigh_enqueue()�������Ļ��浽proxy_queue�����У�
 * Ȼ������proxy_timer��ʱ��������ʱ������ʱ�ٴ���������ġ�
*/
void pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
		    struct sk_buff *skb)
{
	//�е�ǰʱ�䣬�������proxy_dely���������ĵ���ʱʱ�䡣
	unsigned long now = jiffies;
	unsigned long sched_next = now + (net_random() % p->proxy_delay);

	//����ھӱ�Ĵ����Ļ�����г����Ѵﵽ���ޣ��򽫱��Ķ���
	if (tbl->proxy_queue.qlen > p->proxy_qlen) {
		kfree_skb(skb);
		return;
	}

	//��֮ǰ����õ�����ʱʱ���LOCALLY_ENQUEUED��־���浽�������ĵĿ��ƿ��С�
	NEIGH_CB(skb)->sched_next = sched_next;
	NEIGH_CB(skb)->flags |= LOCALLY_ENQUEUED;

	//��ȥ��proxy_timer��ʱ����Ȼ����ԭ����ʱ��ͼ���õ�������ʱ��֮��ȡ����Ϊ�µ���ʱ�䡣
	spin_lock(&tbl->proxy_queue.lock);
	if (del_timer(&tbl->proxy_timer)) {
		if (time_before(tbl->proxy_timer.expires, sched_next))
			sched_next = tbl->proxy_timer.expires;
	}
	//��skb��·�ɻ������ÿպ�����ӵ�proxy_queue����
	skb_dst_drop(skb);
	dev_hold(skb->dev);
	__skb_queue_tail(&tbl->proxy_queue, skb);
	mod_timer(&tbl->proxy_timer, sched_next);//��������proxy_timer��ʱ���´ε���ʱ��
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
 * �˺������ڳ�ʼ��neigh_table�ṹ:��Ҫ������¹���
 * 1.Ϊneighbour�ṹ����Ԥ�����ڴ�ء�
 * 2.����һ��neigh_statistics�ṹ���ռ�Э���ͳ����Ϣ��
 * 3.��������hash��:hash_buckets��phash_buckets����������ֱ���Ϊ�������ĵ�ַ��������ʹ���ĵ�ַ���ݿ⡣
 * 4.��/proc/net�н���һ���ļ�������ת����������ݡ��ļ�������neigh_table->id
 * 5.����gc_timer�������ն�ʱ��.
 * 6.��ʼ��(���ǲ�����)proxy_timer����ʱ������ص�proxy_queue���С�
 * 7.���neigh_table�ṹ��neigh_tablesȫ���б��С�������һ����������
 * 8.��ʼ������һЩ����������reachable_time��
*/
void neigh_table_init(struct neigh_table *tbl)
{
	struct neigh_table *tmp;

	neigh_table_init_no_netlink(tbl);//��ʼ���ھӱ�
	write_lock(&neigh_tbl_lock);//��neigh_tables���������м�������
	for (tmp = neigh_tables; tmp; tmp = tmp->next) {
		if (tmp->family == tbl->family)//�鿴��ͬ��ַ����ھӱ�
			break;
	}
	//���ھӱ���뵽���е�ǰ��
	tbl->next	= neigh_tables;
	neigh_tables	= tbl;//�ŵ�����ǰ��
	write_unlock(&neigh_tbl_lock);

	if (unlikely(tmp)) {//����ҵ���ͬ��ַ���ھӱ�ʹ�ӡ������Ϣ
		printk(KERN_ERR "NEIGH: Registering multiple tables for "
		       "family %d\n", tbl->family);
		dump_stack();
	}
}
EXPORT_SYMBOL(neigh_table_init);

/*
 * ��һ��Э��ʹ��ģ�鷽ʽ��������ģ�鱻ж��ʱ������ô˺���������neigh_table_int�ڳ�ʼ��ʱ�����Ĺ�����
 * ���һ�������Э���������ڷ������Э����κ���Դ�����磬��ʱ���Ͷ��С�
 * IPv4��Ψһ���ܱ���Ϊģ���Э�飬���ARP����Ҫ������.
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
	����Ϣ�ĺ󲿣����ھ���Ϣ֮�󣬻�ȡ�䳤����չ���ԣ���У�鱣�����NDA_DST���͵���չ����
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
	���ھ���������豸������ȡ��Ӧ�������豸.������ڶ����ַ��չ���ԣ�����У��
	*/
	read_lock(&neigh_tbl_lock);
	//����neigh_tables���������е��ھӱ���ȡ����Ϣ�и����ĵ�ַ����һ�µ��ھӱ�
	for (tbl = neigh_tables; tbl; tbl = tbl->next) {
		int flags = NEIGH_UPDATE_F_ADMIN | NEIGH_UPDATE_F_OVERRIDE;
		struct neighbour *neigh;
		void *dst, *lladdr;

		if (tbl->family != ndm->ndm_family)
			continue;
		read_unlock(&neigh_tbl_lock);

		//����չ����ֵ�л�ȡ��ص���Ϣ�ȴ�����
		if (nla_len(tb[NDA_DST]) < tbl->key_len)
			goto out_dev_put;
		dst = nla_data(tb[NDA_DST]);
		lladdr = tb[NDA_LLADDR] ? nla_data(tb[NDA_LLADDR]) : NULL;

		if (ndm->ndm_flags & NTF_PROXY) {
			struct pneigh_entry *pn;

			err = -ENOBUFS;
			pn = pneigh_lookup(tbl, net, dst, dev, 1);//���һ��������
			if (pn) {
				pn->flags = ndm->ndm_flags;
				err = 0;
			}
			goto out_dev_put;
		}

		//����ھ���ǰ��ȷ�����ھӵ���������豸����Ϊ��
		if (dev == NULL)
			goto out_dev_put;

		//����neigh_lookup()�����ھ���ĵ�ַ�Լ���������豸�����ھӱ���ھ�ɢ�б����ҵ���Ӧ���ھ���
		neigh = neigh_lookup(tbl, dst, dev);
		if (neigh == NULL) {
			if (!(nlh->nlmsg_flags & NLM_F_CREATE)) {
				err = -ENOENT;
				goto out_dev_put;
			}

			/* ���û�����ھӱ����ҵ���Ӧ���ھ����netlink����ھ�����Ϣ�ײ���nlmsg_flags���д���NLM_F_CREATE��־��
			   �ñ�־��ʾ�����ڼ�����֮�������neigh_lookup_errno()�����������Ӧ���ھ��ɢ�б���
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
			err = neigh_update(neigh, lladdr, ndm->ndm_state, flags);//����ָ����
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

