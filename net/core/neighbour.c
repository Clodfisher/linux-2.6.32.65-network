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
 * ¸Ãº¯ÊıÓÃÓÚ´¦Àíneighbour½á¹¹²»ÄÜÉ¾³ıµÄÁÙÊ±Çé¿ö£¬ÒòÎªÓĞÈËÈÔÈ»Òªµ÷ÓÃÕâ¸öneighbour½á¹¹¡£º¯Êıneigh_blackhole»á¶ªÆúÔÚÊäÈë½Ó¿Ú
 * ÉÏ½ÓÊÕµÄÈÎºÎ·â°ü¡£ÎªÁËÈ·±£ÈÎºÎÊÔÍ¼¸øÁÚ¾Ó´«ËÍ·â°üµÄĞĞÎª²»»á·¢Éú,ÕâÑù´¦ÀíÊÇ±ØĞèµÄ¡£ÒòÎªÁÚ¾ÓµÄÊı¾İ½á¹¹¼şÒª±»É¾³ı¡£
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
 * ËüÊÇÔÚ¼ä¸ô£¨1/2£©* base ...£¨3/2£©* baseÖĞµÄËæ»ú·Ö²¼¡£ Ëü¶ÔÓ¦ÓÚÄ¬ÈÏµÄIPv6ÉèÖÃ£¬²¢²»ÊÇ¿ÉÒÔ¸²¸ÇµÄ£¬ÒòÎªËüÊÇÕæÕıºÏÀíµÄÑ¡Ôñ¡£
 */

unsigned long neigh_rand_reach_time(unsigned long base)
{
	return (base ? (net_random() % base) + (base >> 1) : 0);
}
EXPORT_SYMBOL(neigh_rand_reach_time);

/*
 * ¸Ãº¯Êı»áÉ¾³ı»º´æhash±íÖĞËùÓĞµÄ·ûºÏÌõ¼şµÄÔªËØ¡£Í¬Ê±Âú×ãÒ»ÏÂÁ½¸öÌõ¼ş:
 * 1.ÒıÓÃ¼ÆÊıÖµÎª1£¬±íÊ¾Ã»ÓĞº¯Êı»ò½á¹¹Ê¹ÓÃ¸ÃÔªËØ£¬¶øÇÒÉ¾³ı¸ÃÔªËØ²»Ó°Ïì±£³ÖÊ£ÓàÒıÓÃµÄ×ÓÏµÍ³¡£
 * 2.¸ÃÔªËØ²»ÊÇNUD_PERMANENTÌ¬¡£ÔÚ¸Ã×´Ì¬µÄÔªËØÊÇ¾²Ì¬ÅäÖÃµÄ£¬Òò´Ë²»»á¹ıÆÚ¡£
*/
static int neigh_forced_gc(struct neigh_table *tbl)
{
	int shrunk = 0;
	int i;

	NEIGH_CACHE_STAT_INC(tbl, forced_gc_runs);

	/* ÔÚÍ¬²½ÇåÀíÊ±£¬»á±éÀúËùÓĞµÄÁÚ¾ÓÏî(¶ø²»ÏñÒì²½»ØÊÕÊ±£¬Ö»ËÑË÷É¢ÁĞ±íµÄÒ»¸öÍ°)£¬½«ÒıÓÃ¼ÆÊıÎª1ÇÒ·Ç¾²Ì¬µÄÁÚ¾ÓÏîÈ«²¿Çå³ı¡£
	   ×îºó·µ»ØÊÇ·ñÖ´ĞĞÁËÇåÀíµÄ±êÖ¾£¬Èô·µ»ØÖµÎª1±íÊ¾Ö´ĞĞÁËÇåÀí£¬0±íÊ¾Ã»ÓĞÇåÀíÁÚ¾ÓÏî¡£
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
	neigh_hold(n);//µİÔöÁÚ¾Ó½á¹¹µÄÊ¹ÓÃ¼ÆÊı
	/*
	 * ¶¨Ê±Æ÷Á´Èë¶ÓÁĞ»áÁ¢¼´Ö´ĞĞ¶¨Ê±º¯Êı£¬Õâ¸ö¶¨Ê±Æ÷ÊÇÔÚÇ°Ãæneigh_alloc()º¯ÊıÉèÖÃµÄ,Æä¶¨Ê±Ö´ĞĞº¯ÊıÎªneigh_timer_handler()
	 * »ù±¾ÈÎÎñÊÇ¼ì²âÁÚ¾Ó½á¹¹µÄÊ±¼ä£¬²¢µ÷ÕûËüµÄ×´Ì¬¡£
	*/
	if (unlikely(mod_timer(&n->timer, when))) {//ÉèÖÃ¶¨Ê±Æ÷µÄ¶¨Ê±Ö´ĞĞÊ±¼äÁ´Èë¶¨Ê±¶ÓÁĞ
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
 * µ±ÀàËÆµÄip link set eth0 lladdr 01:02:03:04:05:06ÃüÁîµ÷ÓÃneigh_changeaddrº¯Êı¸Ä±äµØÖ·Ê±£¬Õâ¸öº¯Êı»áÉ¨ÃèĞ­Òé»º´æÖĞ
 * µÄËùÓĞÏî£¬²¢½«ÓëÒª¸Ä±äµØÖ·µÄÉè±¸Ïà¹ØµÄÏî±ê¼ÇÎªÍ£ÓÃ(dead)¡£À¬»ø»ØÊÕ½ø³Ì¸ºÔğ´¦ÀíÕâĞ©Í£ÓÃÏî¡£
*/
void neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev)
{
	write_lock_bh(&tbl->lock);
	neigh_flush_dev(tbl, dev);
	write_unlock_bh(&tbl->lock);
}
EXPORT_SYMBOL(neigh_changeaddr);

/* Ò»¡¢×÷ÓÃ:
 * ÁÚ¾Ó×ÓÏµÍ³Î¬»¤µÄÁÚ¾ÓÏîÖĞ£¬²»¹ÜÊ²Ã´Ê±ºòÖ»ÒªÁÚ¾ÓÏîÖĞÓĞÒ»¸öÖ÷ÒªÔªËØ(L3µØÖ·£¬L2µØÖ·»ò½Ó¿ÚÉè±¸)±ä»¯ÁË£¬ÄÇÃ´¸ÃÏîÒ²¾ÍÊ§Ğ§ÁË¡£
 * ´ËÊ±£¬ÄÚºË±ØĞëÈ·±£ÁÚ¾ÓĞ­ÒéÄÜ¹»Ö¸µ¼ÕâĞ©ĞÅÏ¢ÊÇ·ñ·¢Éú±ä»¯¡£
 * ÆäËûµÄÄÚºË×ÓÏµÍ³Òªµ÷ÓÃ¸Ãº¯Êı£¬ÒÔÍ¨ÖªÁÚ¾Ó×ÓÏµÍ³ÓĞ¹ØÉè±¸ºÍL3µØÖ·µÄ±ä»¯¡£
 * L3µØÖ·¸Ä±äµÄÍ¨ÖªÓÉL3Ğ­ÒéËÍ³ö¡£
 * ¶ş¡¢ÄÜÉú²úÁÚ¾ÓÏ´ÒÂ¸ĞĞËÈ¤µÄÍâ²¿ÊÀ½çµÄĞĞÎªºÍº¯ÊıÈçÏÂËùÊ¾:
 * 1.Éè±¸¹Ø±Õ:Ã¿¸öÁÚ¾ÓÏî¶¼ÓëÒ»¸öÉè±¸Ïà¹ØÁª¡£Òò´Ë£¬Èç¹û¸ÃÉè±¸Í£Ö¹ÔËĞĞÁË£¬ÄÇÃ´ËùÓĞÓëÖ®Ïà¹ØµÄÁÚ¾ÓÏî¶¼Òª±»É¾³ı¡£
 * 2.L3µØÖ·¸Ä±ä:Èç¹û¹ÜÀíÔ±¸Ä±äÁË½Ó¿ÚÅäÖÃ£¬ÒÔÇ°Í¨¹ı¸Ã½Ó¿Ú¿Éµ½´ïµÄÖ÷»úÓĞ¿ÉÄÜÍ¨¹ıËüÒÑÎŞ·¨µ½´ï¡£¸Ä±ä½Ó¿ÚµÄL3µØÖ·´¥·¢neigh_ifdownº¯Êı¡£
 * 3.Ğ­Òé¹Ø±Õ:Èç¹û×÷ÎªÄ£¿é°²×°µÄL3Ğ­Òé´ÓÄÚºËÖĞĞ¶ÔØÁË£¬ÄÇÃ´ËùÓĞÏà¹ØµÄÁ¬½ÓÏî¼ş²»ÔÙÓĞÓÃ£¬±ØĞëÒªÉ¾³ı¡£
 * Èı¡¢º¯Êı¶Ôneighbour½á¹¹ÉÏÒªÖ´ĞĞµÄ¶¯×÷:
 *     Ëû»áä¯ÀÀËùÓĞµÄneighbour½á¹¹£¬ÕÒµ½Óë´¥·¢ÊÂ¼şµÄÉè±¸Ïà¹ØµÄ½á¹¹£¬È»ºóÊ¹Æä²»ÔÙ¿ÉÓÃ£¬²»»áÁ¢¼´É¾³ı£¬ÒòÎªÁÚ¾Ó×ÓÏµÍ³ÄÚ¿ÉÄÜÈÔÒıÓÃ¡£
 *     ÔÚneigh_ifdown°Ñ»º´æÖĞµÄÓëÓĞÎÊÌâµÄÉè±¸Ïà¹ØµÄÏîÇåÀíµôÖ®ºó£¬¾Íµ÷ÓÃpneigh_ifdownÇåÀí´úÀí»º´æºÍ´úÀí·şÎñÆ÷µÄproxy_queue¶ÓÁĞÖĞµÄÏà¹ØÏî.
 * 1.Í£Ö¹ËùÓĞÎ´¾öµÄ¶¨Ê±Æ÷¡£
 * 2.½«Ïà¹ØÁÚ¾ÓÏîµÄ×´Ì¬¸ÄÎªNUD_NOARPÌ¬£¬ÕâÑùÊÔÍ¼Ê¹ÓÃ¸ÃÁÚ¾ÓÏîµÄÈÎºÎÁ÷Á¿²»ÔÙ»á´¥·¢solicitationÇëÇó¡£
 * 3.Ê¹ÓÃneigh->outputÖ¸Ïòneigh_blackhole£¬ÒÔ±ã¶ªÆúËÍµ½¸ÃÁÚ¾ÓµÄ·â°ü¶ø²»ÊÇ½«ÆäÌá½»¡£
 * 4.µ÷ÓÃskb_queue_purge,½«ËùÓĞÔÚarp_queue¶ÓÁĞÖĞ´ı´¦ÀíµÄ·â°ü¶ªÆú¡£
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
 * ¸Ãº¯ÊıÓÃÓÚ·ÖÅäĞÂµÄneighbourÊı¾İ´æ´¢¿Õ¼ä,¸Ãº¯ÊıÒ²ÓÃÓÚ³õÊ¼»¯Ò»Ğ©²ÎÊı£¬ÀıÈç£¬Ç¶ÈëµÄ¶¨Ê±Æ÷£¬ÒıÓÃ¼ÆÊıÆ÷£¬Ö¸Ïò¹ØÁªµÄneigh_table(ÁÚ¾ÓĞ­Òé)
 * ½á¹¹µÄÖ¸ÕëºÍ¶Ô·ÖÅäµÄneighbour½á¹¹ÊıÄ¿µÄÕûÌåÍ³¼Æ¡£´Ëº¯ÊıÊ¹ÓÃÁÚ¾Ó×ÓÏµÍ³³õÊ¼»¯Ê±½¨Á¢µÄÄÚ´æ³Ø¡£Èç¹ûµ±Ç°·ÖÅäµÄÁÚ¾Ó½á¹¹ÊıÄ¿´óÓÚÅäÖÃµÄãĞÖµ£¬
 * ²¢ÇÒ½ÓÏÂÀ´µÄÀ¬»ø»ØÊÕÆ÷ÊÔÍ¼ÊÍ·ÅÄ³¿éÄÚ´æÊ§°ÜÁË£¬¸Ãº¯Êı¾ÍÎŞ·¨Íê³É·ÖÅä¡£
 * ²ÎÊıÎªtbl:´ı·ÖÅäÁÚ¾ÓÏîËùÔÚµÄÁÚ¾Ó±í
*/
static struct neighbour *neigh_alloc(struct neigh_table *tbl)
{
	struct neighbour *n = NULL;
	unsigned long now = jiffies;
	int entries;

	/* time_after()º¯Êı¼ì²â×îºóÒ»´Î»ØÊÕµ½ÏÖÔÚµÄÊµ¼Ê¼ä¸ô£¬Èç¹ûĞèÒª»ØÊÕ¾ÍÆô¶¯neigh_forced_gc()º¯Êı£¬
	 * ÒÀ¾İÁÚ¾Ó½á¹¹µÄÊ¹ÓÃ¼ÆÊıºÍ×´Ì¬½øĞĞ»ØÊÕ
	*/
	entries = atomic_inc_return(&tbl->entries) - 1;//»ñÈ¡ÁÚ¾Ó½á¹¹ÊıÁ¿
	if (entries >= tbl->gc_thresh3 ||
	    (entries >= tbl->gc_thresh2 &&
	     time_after(now, tbl->last_flush + 5 * HZ))) {//¼ì²âÊÇ·ñĞèÒª»ØÊÕ:Ç°ÕßµÄÊ±¼ä´Á´óÓÚºóÕßµÄÊ±¼ä´Á b-a<0
		if (!neigh_forced_gc(tbl) &&//Æô¶¯Í¬²½À¬»ø»ØÊÕ
		    entries >= tbl->gc_thresh3)//»ØÊÕºóÊıÁ¿ÈÔÈ»³¬¹ı×î´óãĞÖµ
			goto out_entries;
	}

    //ÔÚÁÚ¾Ó±íÖ¸¶¨µÄ¸ßËÙ»º´æÖĞ·ÖÅä½á¹¹¿Õ¼ä
	n = kmem_cache_zalloc(tbl->kmem_cachep, GFP_ATOMIC);
	if (!n)
		goto out_entries;

	__skb_queue_head_init(&n->arp_queue);//³õÊ¼»¯ÁÚ¾Ó½á¹¹µÄ¶ÓÁĞÍ·(´æ´¢ĞèÒª´¦ÀíµÄ·â°ü)
	rwlock_init(&n->lock);
	n->updated	  = n->used = now;//¼ÇÂ¼µ±Ç°Ê±¼ä
	n->nud_state	  = NUD_NONE;//ÉèÖÃ×´Ì¬
	n->output	  = neigh_blackhole;//ÉèÖÃ·¢ËÍº¯Êı
	n->parms	  = neigh_parms_clone(&tbl->parms);//¼ÇÂ¼ÁÚ¾Ó²ÎÊı½á¹¹
	setup_timer(&n->timer, neigh_timer_handler, (unsigned long)n);//³õÊ¼»¯¶¨Ê±Æ÷£¬¶¨Ê±Æ÷º¯ÊıÎªneigh_timer_handler
	/*
	setup_timer µ÷ÓÃ/include/linux/time.hÖĞº¯Êı
	static inline void setup_timer_key(struct timer_list * timer,
				const char *name,
				struct lock_class_key *key,
				void (*function)(unsigned long),
				unsigned long data)
{
	timer->function = function;        //¼ÇÂ¼ÁÚ¾Ó½á¹¹µÄ¶¨Ê±Ö´ĞĞº¯Êıneigh_timer_handler()
	timer->data = data;                //¼ÇÂ¼ÁÚ¾Ó½á¹¹µÄµØÖ·
	init_timer_key(timer, name, key);  //³õÊ¼»¯¶¨Ê±Æ÷
}
    ÕâÀïÖ»ÊÇ³õÊ¼»¯ÁË¶¨Ê±Æ÷£¬²¢Ã»ÓĞ½«ËüÁ´ÈëÄÚºËµÄ¶¨Ê±Æ÷Ö´ĞĞ¶ÓÁĞ£¬Òò´Ë³õÊ¼»¯ºó»¹»áÖ´ĞĞ¶¨Ê±º¯Êıneigh_timer_handler(),
    ÔÚºóÃæ__neigh_event_send()º¯ÊıµÄ¹ı³ÌÖĞ¿´µ½Õâ¸ö¶¨Ê±Æ÷µÄÆô¶¯
	*/

	NEIGH_CACHE_STAT_INC(tbl, allocs);//µİÔö·ÖÅä¼ÆÊıÆ÷
	n->tbl		  = tbl;//¼ÇÂ¼ÁÚ¾Ó±í
	atomic_set(&n->refcnt, 1);//ÉèÖÃÊ¹ÓÃ¼ÆÊı
	n->dead		  = 1;//³õÊ¼É¾³ı±êÖ¾
out:
	return n;

out_entries:
	atomic_dec(&tbl->entries);//µİ¼õÁÚ¾Ó½á¹¹¼ÆÊıÆ÷
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
º¯ÊıÔ­ĞÍ£º
static void neigh_hash_grow(struct neigh_table *tbl, unsigned long new_entries)
×÷ÓÃ£º
ÔÚ´´½¨ÁÚ¾ÓÏîÊ±£¬Èç¹ûÔÚ¼ÆÈëÒª´´½¨µÄÁÚ¾ÓÏîºó£¬ÁÚ¾Ó±íÁÚ¾ÓÏîµÄ¼ÆÊı³¬¹ıÁËÁÚ¾ÓÉ¢ÁĞ±íµÄÈİÁ¿£¬¾Í»áµ÷ÓÃneigh_hash_grow()À©ÈİÁÚ¾ÓÉ¢ÁĞ±í¡£
²ÎÊı£º
tbl,´ıÀ©ÈİÁÚ¾ÓÏîÉ¢ÁĞ±íËùÊôµÄÁÚ¾Ó±í£¬ARPÖĞµÄarp_tbl
new_entries,À©ÈİºóÁÚ¾ÓÉ¢ÁĞ±íµÄÈİÁ¿

*/
static void neigh_hash_grow(struct neigh_table *tbl, unsigned long new_entries)
{
	struct neighbour **new_hash, **old_hash;
	unsigned int i, new_hash_mask, old_entries;

	NEIGH_CACHE_STAT_INC(tbl, hash_grows);

	BUG_ON(!is_power_of_2(new_entries));
	/*
	µ÷ÓÃneigh_hash_alloc()ÎªÁÚ¾ÓÏîÉ¢ÁĞ±íÖØĞÂ·ÖÅäÄÚ´æ£¬ÔÚ¸Ãº¯ÊıÖĞ£¬¸ù¾İ´ı·ÖÅäµÄÄÚ´æÁ¿´óÓÚPAGE_SIZEÓë·ñÀ´È·¶¨Ê¹ÓÃ
	kzalloc()»òÊÇget_free_pages()·ÖÅäÄÚ´æ
	*/
	new_hash = neigh_hash_alloc(new_entries);
	if (!new_hash)
		return;

	old_entries = tbl->hash_mask + 1;
	new_hash_mask = new_entries - 1;
	old_hash = tbl->hash_buckets;

	get_random_bytes(&tbl->hash_rnd, sizeof(tbl->hash_rnd));//ÖØĞÂ¼ÆËãËæ»úÖµhash_rand
	/*
	ÏÈ½«Ô­ÏÈÁÚ¾ÓÏîÉ¢ÁĞ±íÖĞµÄÁÚ¾ÓÏîÒÆ¶¯µ½À©ÈİºóµÄÁÚ¾ÓÏîÉ¢ÁĞ±íÖĞ£¬È»ºó½«ĞÂÉ¢ÁĞÏîÁĞ±í¼°Æähash_mask±£´æµ½ÁÚ¾Ó±íÖĞ
	*/
	for (i = 0; i < old_entries; i++) {
		struct neighbour *n, *next;

		for (n = old_hash[i]; n; n = next) {
			unsigned int hash_val = tbl->hash(n->primary_key, n->dev);

			hash_val &= new_hash_mask;
			next = n->next;

			n->next = new_hash[hash_val];//ÔÚÏàÓ¦µÄÉ¢ÁĞÍ°ÖĞµÄ¶ÓÁĞÊ×²¿Ìí¼Ó
			new_hash[hash_val] = n;
		}
	}
	tbl->hash_buckets = new_hash;
	tbl->hash_mask = new_hash_mask;

	neigh_hash_free(old_hash, old_entries);//µ÷ÓÃneigh_hash_free()ÊÍ·Å¾ÉÁÚ¾ÓÉ¢ÁĞ±íËùÕ¼ÓÃµÄÄÚ´æ
}
/*
 * ¸Ãº¯Êı»áÔÚarp_tblÖĞ¼ì²éÒª²éÕÒµÄÔªËØ(Íø¹ØºÍÉè±¸)ÊÇ·ñ´æÔÚ£¬²¢ÇÒÔÚ²éÕÒ³É¹¦Ê±·µ»ØÖ¸Ïò¸ÃÔªËØµÄÖ¸Õë¡£
×÷ÓÃ£º
ÁÚ¾ÓÏîµÄ²éÕÒ·Ç³£Æµ·±£ºÌí¼ÓÁÚ¾ÓÏîÊ±ĞèÒª²éÕÒÁÚ¾ÓÏîÊÇ·ñÒÑ´æÔÚ£»É¾³ıÁÚ¾ÓÏîÊ±ĞèÒª²éÕÒ´ıÉ¾³ıµÄÁÚ¾ÓÏîÊÇ·ñ´æÔÚ¡£
²ÎÊı£º
tbl£¬Îª´ı²éÕÒµÄÁÚ¾Ó±í
pkeyºÍdev,ÊÇ²éÕÒÌõ¼ş£¬¼´Èı²ãĞ­ÒéµØÖ·ºÍÁÚ¾ÓÏîµÄÊä³öÉè±¸
*/
struct neighbour *neigh_lookup(struct neigh_table *tbl, const void *pkey,
			       struct net_device *dev)
{
	struct neighbour *n;
	int key_len = tbl->key_len;//È¡µÃµØÖ·³¤¶È
	u32 hash_val;

	NEIGH_CACHE_STAT_INC(tbl, lookups);//µİÔö²éÕÒÁÚ¾Ó±í¼ÆÊıÆ÷

	read_lock_bh(&tbl->lock);
	hash_val = tbl->hash(pkey, dev);//µ÷ÓÃÁÚ¾Ó±íÖĞµÄ¹şÏ£ÔËËãº¯ÊıÈ·¶¨¹şÏ£Öµ
	//ÔÚ¹şÏ£Í°ÖĞ²éÕÒÖ¸¶¨Éè±¸¡¢Ö¸¶¨Íø¹ØµÄÁÚ¾Ó½á¹¹
	for (n = tbl->hash_buckets[hash_val & tbl->hash_mask]; n; n = n->next) {
		if (dev == n->dev && !memcmp(n->primary_key, pkey, key_len)) {
			neigh_hold(n);//µİÔöÁÚ¾Ó½á¹¹µÄ¼ÆÊıÆ÷
			NEIGH_CACHE_STAT_INC(tbl, hits);//µİÔöÁÚ¾Ó±íµÄÃüÖĞ¼ÆÊıÆ÷
			break;
		}
	}
	read_unlock_bh(&tbl->lock);
	return n;//·µ»¹ÕÒµ½µÄÁÚ¾Ó½á¹¹
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
*×÷ÓÃ:ÓÃÀ´ÍêÕûµØ´´½¨Ò»¸öÁÚ¾ÓÏî£¬²¢½«ÆäÌí¼Óµ½É¢ÁĞ±íÉÏ£¬×îºó·µ»ØÖ¸Ïò¸ÃÁÚ¾ÓÏîµÄÖ¸Õë
*tbl: ´ı´´½¨ÁÚ¾Ó±íÏîËùÊôµÄÁÚ¾Ó±í,ÔÚARPÖĞÎªarp_tbl
*pkey: ÏÂÒ»ÌøÈı²ãĞ­ÒéµØÖ·£¬×÷ÎªÁÚ¾Ó±íÏîµÄ¹Ø¼ü×Ö
*dev: ¸ÃÁÚ¾Ó±íÏîµÄÊä³öÉè±¸,ÓëÒª´´½¨µÄÁÚ¾ÓÏîÏà¹ØµÄÉè±¸¡£ÒòÎªÃ¿¸öneighbourÏî¶¼ÓëÒ»¸öL3µØÖ·Ïà¹ØÁª£¬²¢ÇÒºóÕß×ÜÊÇÓëÒ»¸öÉè±¸Ïà¹ØÁª£¬
*     ËùÒÔneighbourÊµÀı¾ÍÓëÒ»¸öÉè±¸Ïà¹ØÁª¡£
**/
struct neighbour *neigh_create(struct neigh_table *tbl, const void *pkey,
			       struct net_device *dev)
{
	u32 hash_val;
	int key_len = tbl->key_len;//È¡µÃIPµØÖ·³¤¶È×÷Îª¼üÖµ
	int error;
	/*
	Ê×ÏÈÎªĞÂµÄÁÚ¾Ó±íÏîstruct neighbour·ÖÅä¿Õ¼ä£¬²¢×öÒ»Ğ©³õÊ¼»¯¡£
	´«ÈëµÄ²ÎÊıtbl¾ÍÊÇÈ«¾ÖÁ¿arp_tbl£¬·ÖÅä¿Õ¼äµÄ´óĞ¡ÊÇtbl->entry_size£¬
	¶øÕâ¸öÖµÔÚÉùÃ÷arp_tblÊ±³õÊ¼»¯Îªsizeof(struct neighbour) + 4£¬¶à³öµÄ4¸ö×Ö½Ú¾ÍÊÇkeyÖµ´æ·ÅµÄµØ·½¡£
	*/
	struct neighbour *n1, *rc, *n = neigh_alloc(tbl);/*·ÖÅäÒ»¸öÁÚ¾Ó½á¹¹ÊµÀı*/

	if (!n) {//·ÖÅäÊ§°Ü·µ»Ø
		rc = ERR_PTR(-ENOBUFS);
		goto out;
	}

	/*½«Èı²ãµØÖ·ºÍÊä³öÉè±¸ÉèÖÃµ½ÁÚ¾Ó±íÏîÖĞ*/
	memcpy(n->primary_key, pkey, key_len);//key_len±ØÒªµÄ£¬ÒòÎªneighbour½á¹¹ÊÇ±»ÓëĞ­ÒéÎŞ¹ØµÄ»º´æ²éÕÒº¯ÊıÊ¹ÓÃ£¬²¢ÇÒ¸÷ÖÖÁÚ¾ÓĞ­Òé±íÊ¾µØÖ·µÄ×Ö½Ú³¤¶È²»Í¬¡£
	n->dev = dev;//ÓÉÓÚneighbourÏîÖĞ°üÀ¨ÁË¶Ônet_device½á¹¹ÖĞdevµÄÒıÓÃ£¬ÄÚºË»áÊ¹ÓÃdev_holdÀ´¶ÔºóÕßµÄÒıÓÃ¼ÆÊıÆ÷¼Ó1£¬ÒÔ´ËÀ´±£Ö¤¸ÃÉè±¸ÔÚneighbour½á¹¹´æÔÚÊÇ²»»á±»É¾³ı¡£
	dev_hold(dev);//Ôö¼ÓÉè±¸µÄ¼ÆÊıÆ÷

	/* Protocol specific setup. Ö´ĞĞÓëÁÚ¾ÓĞ­ÒéÏà¹ØµÄ³õÊ¼»¯º¯Êı£¬½áºÏarp_tbl½á¹¹µÄÄÚÈİ£¬Êµ¼ÊÖ´ĞĞARPÖĞÎªarp_constructor*/
	if (tbl->constructor &&	(error = tbl->constructor(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}

	/* Device specific setup. Éè±¸Ö´ĞĞµÄ³õÊ¼»¯¹¤×÷ÓÉneigh_setupĞéº¯ÊıÍê³É*/
	if (n->parms->neigh_setup &&//Èç¹ûÖ¸¶¨ÁË°²×°º¯Êı¾ÍÖ´ĞĞËü
	    (error = n->parms->neigh_setup(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}
	
	/*½«´´½¨µÄÁÚ¾Ó±íÏî²åÈëÁÚ¾Ó±íÏîhash±íÖĞ*/
	//confirmed×Ö¶Î£¬±íÊ¾¸ÃÁÚ¾ÓÊÇ¿Éµ½´ïµÄ,Õı³£Çé¿öÏÂ£¬¸Ã×Ö¶ÎÓÉ¿Éµ½´ïĞÔÖ¤Ã÷À´¸üĞÂ£¬²¢ÇÒÆäÖµÉèÖÃÎªjiffies±íÊ¾µÄµ±Ç°Ê±¼ä£¬
	//µ«ÊÇÕâÀï£¬´ÓĞÂ½¨µÄ½Ç¶ÈÀ´Ëµ£¬neigh_createº¯Êı»á°ÑconfirmedÖµ¼õÈ¥Ò»Ğ¡¶ÎÊ±¼ä(reachable_timeÖµµÄÒ»°ë)£¬ÕâÑù¾ÍÊ¹µÃÁÚ¾Ó
	//×´Ì¬ÄÜ±ÈÆ½³£ºÍÒªÇóÓĞ¿Éµ½´ïĞÔÖ¤¾İÊ±£¬ÉÔ¿ìµã×ªÒÆµ½NUD_STALEÌ¬
	n->confirmed = jiffies - (n->parms->base_reachable_time << 1);//È·¶¨Ê±¼ä£¬ÆäÖĞjiffiesÎªµ±Ç°Ê±¼ä

	write_lock_bh(&tbl->lock);

    //Èç¹ûÁÚ¾Ó½á¹¹ÊıÁ¿³¬¹ıÁË¹şÏ£Í°µÄ³¤¶È
	if (atomic_read(&tbl->entries) > (tbl->hash_mask + 1))
		neigh_hash_grow(tbl, (tbl->hash_mask + 1) << 1);//µ÷Õû¹şÏ£Í°,À©Ôö1±¶

	hash_val = tbl->hash(pkey, dev) & tbl->hash_mask;//¼ÆËã¹şÏ£Öµ

	if (n->parms->dead) {//ÁÚ¾ÓÅäÖÃ²ÎÊıÕıÔÚ±»É¾³ı£¬²»ÄÜÔÙÊ¹ÓÃ£¬Òò´ËÒ²¾Í²»ÄÜÔÙ¼ÌĞø´´½¨ÁÚ¾ÓÏîÁË
		rc = ERR_PTR(-EINVAL);
		goto out_tbl_unlock;
	}

	//ÔÚ¹şÏ£Í°ÖĞ²éÕÒÒª²åÈëµÄ¶ÓÁĞ
	for (n1 = tbl->hash_buckets[hash_val]; n1; n1 = n1->next) {
		if (dev == n1->dev && !memcmp(n1->primary_key, pkey, key_len)) {
			neigh_hold(n1);
			rc = n1;//¼ÇÂ¼ÏàÍ¬µØÖ·ºÍÉè±¸µÄÁÚ¾Ó½á¹¹£¬Ö±½Ó·µ»ØÕÒµ½µÄÁÚ¾Ó½á¹¹
			goto out_tbl_unlock;
		}
	}

	n->next = tbl->hash_buckets[hash_val];//Ö¸Ïò¶ÓÁĞÖĞÏÂÒ»¸öÁÚ¾Ó½á¹¹
	tbl->hash_buckets[hash_val] = n;//Á´Èë¹şÏ£Í°
	n->dead = 0;//Çå³ıÉ¾³ı±êÖ¾
	neigh_hold(n);//µİÔöÊ¹ÓÃ¼ÆÊı
	write_unlock_bh(&tbl->lock);
	NEIGH_PRINTK2("neigh %p is created.\n", n);
	rc = n;//¼ÇÂ¼ĞÂ´´½¨µÄÁÚ¾Ó½á¹¹
out:
	return rc;//·µ»ØÁÚ¾Ó½á¹¹
out_tbl_unlock:
	write_unlock_bh(&tbl->lock);
out_neigh_release:
	neigh_release(n);//ÕÒµ½ÁËÏàÍ¬µÄÁÚ¾Ó½á¹¹¾ÍÊÍ·ÅĞÂ½¨µÄ
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
 *  É¾³ıÁÚ¾Ó½á¹¹µÄº¯Êı£¬Òª×öµÄÊÂÇéÈçÏÂ:
 *  1.Í£Ö¹ËùÓĞÎ´¾öµÄ¶¨Ê±Æ÷¡£
 *  2.ÊÍ·ÅËùÓĞ¶ÔÍâ²¿Êı¾İ½á¹¹µÄÒıÓÃ£¬ÀıÈç¹ØÁªµÄÉè±¸¼°»º´æµÄL2Ö¡Í·.
 *  3.Èç¹ûÒ»¸öÁÚ¾ÓĞ­ÒéÌá¹©ÁËdestructor·½·¨£¬¸ÃÁÚ¾ÓĞ­Òé¾Í»áÖ´ĞĞÕâ¸ö·½·¨×Ô¼ºÇåÀíÁÚ¾ÓÏî¡£
 *  4.Èç¹ûarp_queue¶ÓÁĞ·Ç¿Õ£¬¾ÍÒª½«ÆäÇå¿Õ(É¾³ıÆäËùÓĞÔªËØ)¡£
 *  5.½«±íÊ¾Ö÷»úÊ¹ÓÃµÄneighbourÏî×ÜÊıµÄÈ«¾Ö¼ÆÊıÆ÷¼õ1.
 *  6.ÊÇ·ñ¸Ãneighbour½á¹¹(½«ÆäÕ¼ÓÃµÄÄÚ´æ¿Õ¼ä·µ»¹¸øÄÚ´æ³Ø)¡£
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

	neigh->output = neigh->ops->connected_output;//¿ÉÒÔ¿´µ½neigh->output±»³õÊ¼»¯Îªconnected_output£¬¶ÔARP¾ÍÊÇneigh_connected_output

	for (hh = neigh->hh; hh; hh = hh->hh_next)
		hh->hh_output = neigh->ops->hh_output;
}

 /*
 ¹¤×÷¶ÓÁĞ»áÒì²½µÄ¸ü¸ÄNUD×´Ì¬,neigh_periodic_workÓÃÓÚNUD_STALE
 ×¢Òâneigh_timer_handlerÊÇÃ¿¸ö±íÏîÒ»¸öµÄ£¬¶øneigh_periodic_workÊÇÎ¨Ò»µÄ
 µ±neigh´¦ÓÚNUD_STALE×´Ì¬Ê±£¬´ËÊ±ËüµÈ´ıÒ»¶ÎÊ±¼ä£¬Ö÷»úÒıÓÃµ½Ëü£¬´Ó¶ø×ªÈëNUD_DELAY×´Ì¬£»
 Ã»ÓĞÒıÓÃ£¬Ôò×ªÈëNUD_FAIL£¬±»ÊÍ·Å¡£²»Í¬ÓÚNUD_INCOMPLETE¡¢NUD_DELAY¡¢NUD_PROBE¡¢NUD_REACHABLE×´Ì¬Ê±µÄ¶¨Ê±Æ÷£¬
 ÕâÀïÊ¹ÓÃµÄÒì²½»úÖÆ£¬Í¨¹ı¶¨ÆÚ´¥·¢neigh_periodic_work()À´¼ì²éNUD_STALE×´Ì¬¡£
*/
static void neigh_periodic_work(struct work_struct *work)
{
	/*
	neigh_periodic_work¶¨ÆÚÖ´ĞĞ£¬µ«Òª±£Ö¤±íÏî²»»á¸ÕÌí¼Ó¾Í±»neigh_periodic_workÇåÀíµô£¬
	ÕâÀïµÄ²ßÂÔÊÇ£ºgc_staletime´óÓÚ1/2 base_reachable_time¡£Ä¬ÈÏµÄ£¬gc_staletime = 30£¬
	base_reachable_time = 30¡£Ò²¾ÍÊÇËµ£¬neigh_periodic_work»áÃ¿15HZÖ´ĞĞÒ»´Î£¬
	µ«±íÏîÔÚNUD_STALEµÄ´æ»îÊ±¼äÊÇ30HZ£¬ÕâÑù£¬±£Ö¤ÁËÃ¿ÏîÔÚ×î²îÇé¿öÏÂÒ²ÓĞ(30 - 15)HZµÄÉúÃüÖÜÆÚ¡£
	*/
	struct neigh_table *tbl = container_of(work, struct neigh_table, gc_work.work);
	struct neighbour *n, **np;
	unsigned int i;

	NEIGH_CACHE_STAT_INC(tbl, periodic_gc_runs);

	write_lock_bh(&tbl->lock);

	/*
	 *	periodically recompute ReachableTime from random function ´ÓËæ»úº¯Êı¶¨ÆÚÖØĞÂ¼ÆËãReachableTime
	 */
	//Ã¿300s½«ÁÚ¾Ó±íËùÓĞneigh_parms½á¹¹ÊµÀıµÄNUD_REACHABLE×´Ì¬³¬Ê±Ê±¼äreachable_time¸üĞÂÎªÒ»¸öĞÂµÄËæ»úÖµ¡£
	if (time_after(jiffies, tbl->last_rand + 300 * HZ)) {
		struct neigh_parms *p;
		tbl->last_rand = jiffies;
		for (p = &tbl->parms; p; p = p->next)
			p->reachable_time =
				neigh_rand_reach_time(p->base_reachable_time);
	}

    //±éÀúÕû¸öÁÚ¾Ó±í£¬Ã¿¸öhash_bucketsµÄÃ¿¸ö±íÏî£¬Èç¹ûÔÚgc_staletimeÄÚÈÔÎ´±»ÒıÓÃ¹ı£¬Ôò»á´ÓÁÚ¾Ó±íÖĞÇå³ı¡£
	for (i = 0 ; i <= tbl->hash_mask; i++) {
		np = &tbl->hash_buckets[i];

		while ((n = *np) != NULL) {
			unsigned int state;

			write_lock(&n->lock);

			//¶ÔÓÚ¾²Ì¬ÁÚ¾ÓÏî»ò´¦ÓÚ¶¨Ê±Æ÷×´Ì¬µÄÁÚ¾ÓÏî²»´¦ÀíÖ±½ÓÌø¹ı
			state = n->nud_state;
			if (state & (NUD_PERMANENT | NUD_IN_TIMER)) {
				write_unlock(&n->lock);
				goto next_elt;
			}

			//Èç¹ûÁÚ¾ÓÏîµÄ×îºóÊ¹ÓÃÊ±¼äÔÚ×îºóÈ·ÈÏÊ±¼äÖ®Ç°£¬Ôòµ÷Õû×îºóÊ¹ÓÃÊ±¼äÎª×îºóÈ·ÈÏÊ±¼ä
			if (time_before(n->used, n->confirmed))
				n->used = n->confirmed;
			/*
				µ÷ÓÃneigh_release()É¾³ıÊÍ·Å·ûºÏÁ½ÖÖÌõ¼şµÄÁÚ¾ÓÏî:
				1.Ó¦ÓÃ¼ÆÊıÎª1ÇÒ×´Ì¬ÎªNUD_FAILED
				2.ÒıÓÃ¼ÆÊıÎª1ÇÒÏĞÖÃÊ±¼ä³¬¹ıÁËÖ¸¶¨ÉÏÏŞgc_staletime
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
		 * ÔÚÕâÀïÊÍ·ÅËø¶¨ÊÇÕıÈ·µÄ£¬¼´Ê¹¹şÏ£±íÔÚÎÒÃÇ±»ÇÀÕ¼µÄÊ±ºòÔö³¤¡£
		 */
		write_unlock_bh(&tbl->lock);
		cond_resched();
		write_lock_bh(&tbl->lock);
	}
	/* Cycle through all hash buckets every base_reachable_time/2 ticks.
	 * ARP entry timeouts range from 1/2 base_reachable_time to 3/2
	 * base_reachable_time.
	 */
	// ÔÚ¹¤×÷×îºó£¬ÔÙ´ÎÌí¼Ó¸Ã¹¤×÷µ½¶ÓÁĞÖĞ£¬²¢ÑÓÊ±1/2 base_reachable_time¿ªÊ¼Ö´ĞĞ£¬
	// ÕâÑù£¬Íê³ÉÁËneigh_periodic_work¹¤×÷Ã¿¸ô1/2 base_reachable_timeÖ´ĞĞÒ»´Î¡£
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
 * ÆäÖĞneigh_timer_handler¶¨Ê±Æ÷¡¢neigh_periodic_work¹¤×÷¶ÓÁĞ»áÒì²½µÄ¸ü¸ÄNUD×´Ì¬£¬
 * neigh_timer_handlerÓÃÓÚNUD_INCOMPLETE, NUD_DELAY, NUD_PROBE, NUD_REACHABLE×´Ì¬£»
 * neigh_periodic_workÓÃÓÚNUD_STALE¡£×¢Òâneigh_timer_handlerÊÇÃ¿¸ö±íÏîÒ»¸öµÄ£¬
 * ¶øneigh_periodic_workÊÇÎ¨Ò»µÄ£¬NUD_STALE×´Ì¬µÄ±íÏîÃ»±ØÒªµ¥¶ÀÊ¹ÓÃ¶¨Ê±Æ÷£¬
 * ¶¨ÆÚ¼ì²é¹ıÆÚ¾Í¿ÉÒÔÁË£¬ÕâÑù´ó´ó½ÚÊ¡ÁË×ÊÔ´
 *
 ÁÚ¾ÓÏî¸÷¸ö×´Ì¬ÖĞ£¬ÓĞĞ©ÊôÓÚ¶¨Ê±×´Ì¬£¬¶ÔÓÚÕâĞ©×´Ì¬Æä×ª±äÓÉ¶¨Ê±Æ÷´¦Àíº¯ÊıÀ´´¦Àí¡£
 Ã¿¸öÁÚ¾ÓÏî¶¼ÓĞÒ»¸ö¶¨Ê±Æ÷£¬¸Ã¶¨Ê±Æ÷ÔÚ´´½¨ÁÚ¾ÓÏîÊ±±»³õÊ¼»¯£¬ËüµÄ´¦Àíº¯ÊıÎªneigh_timer_handler()¡£
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

	//²»´¦ÀíÄÇĞ©²»´¦ÓÚ¶¨Ê±×´Ì¬µÄÁÚ¾ÓÏî
	if (!(state & NUD_IN_TIMER)) {//¶¨Ê±Æ÷×´Ì¬£¬Óë¶¨Ê±Æ÷ÓĞ¹ØµÄ×´Ì¬:NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE
#ifndef CONFIG_SMP
		printk(KERN_WARNING "neigh: timer & !nud_in_timer\n");
#endif
		goto out;
	}

	if (state & NUD_REACHABLE) {
		if (time_before_eq(now,
				   neigh->confirmed + neigh->parms->reachable_time)) {
			//Èç¹û³¬Ê±£¬µ«ÆÚ¼äÊÕµ½¶Ô·½µÄ±¨ÎÄ£¬²»¸ü¸Ä×´Ì¬£¬²¢ÖØÖÃ³¬Ê±Ê±¼äÎªneigh->confirmed+reachable_time
			NEIGH_PRINTK2("neigh %p is still alive.\n", neigh);
			next = neigh->confirmed + neigh->parms->reachable_time;
		} else if (time_before_eq(now,
					  neigh->used + neigh->parms->delay_probe_time)) {
		    //Èç¹û³¬Ê±£¬ÆÚ¼äÎ´ÊÕµ½¶Ô·½±¨ÎÄ£¬µ«Ö÷»úÊ¹ÓÃ¹ı¸ÃÏî£¬ÔòÇ¨ÒÆÖÁNUD_DELAY×´Ì¬£¬
		    //²¢ÖØÖÃ³¬Ê±Ê±¼äÎªneigh->used+delay_probe_time
			NEIGH_PRINTK2("neigh %p is delayed.\n", neigh);
			neigh->nud_state = NUD_DELAY;
			neigh->updated = jiffies;
			neigh_suspect(neigh);
			next = now + neigh->parms->delay_probe_time;
		} else {
		    //Èç¹û³¬Ê±£¬ÇÒ¼ÈÎ´ÊÕµ½¶Ô·½±¨ÎÄ£¬Ò²Î´Ê¹ÓÃ¹ı¸ÃÏî£¬Ôò»³ÒÉ¸ÃÏî¿ÉÄÜ²»¿ÉÓÃÁË£¬
		    //Ç¨ÒÆÖÁNUD_STALE×´Ì¬£¬¶ø²»ÊÇÁ¢¼´É¾³ı£¬neigh_periodic_work()»á¶¨Ê±µÄÇå³ıNUD_STALE×´Ì¬µÄ±íÏî¡£
			NEIGH_PRINTK2("neigh %p is suspected.\n", neigh);
			neigh->nud_state = NUD_STALE;
			neigh->updated = jiffies;
			neigh_suspect(neigh);
			notify = 1;
		}
	} else if (state & NUD_DELAY) {
		if (time_before_eq(now,
				   neigh->confirmed + neigh->parms->delay_probe_time)) {
		    //Èç¹û³¬Ê±£¬ÆÚ¼äÊÕµ½¶Ô·½±¨ÎÄ£¬Ç¨ÒÆÖÁNUD_REACHABLE£¬¼ÇÂ¼ÏÂ´Î¼ì²éÊ±¼äµ½next
		    //NUD_DELAY -> NUD_REACHABLEµÄ×´Ì¬×ªÒÆ£¬ÔÚarp_processÖĞÒ²Ìáµ½¹ı£¬ÊÕµ½arp replyÊ±»áÓĞ±íÏî×´Ì¬
		    //NUD_DELAY -> NUD_REACHABLE¡£ËüÃÇÁ½ÕßµÄÇø±ğÔÚÓÚarp_process´¦ÀíµÄÊÇarpµÄÈ·ÈÏ±¨ÎÄ£¬
		    //¶øneigh_timer_handler´¦ÀíµÄÊÇ4²ãµÄÈ·ÈÏ±¨ÎÄ¡£
			NEIGH_PRINTK2("neigh %p is now reachable.\n", neigh);
			neigh->nud_state = NUD_REACHABLE;
			neigh->updated = jiffies;
			neigh_connect(neigh);
			notify = 1;
			next = neigh->confirmed + neigh->parms->reachable_time;
		} else {
			//Èç¹û³¬Ê±£¬ÆÚ¼äÎ´ÊÕµ½¶Ô·½µÄ±¨ÎÄ£¬Ç¨ÒÆÖÁNUD_PROBE£¬¼ÇÂ¼ÏÂ´Î¼ì²éÊ±¼äµ½next
			NEIGH_PRINTK2("neigh %p is probed.\n", neigh);
			neigh->nud_state = NUD_PROBE;
			neigh->updated = jiffies;
			atomic_set(&neigh->probes, 0);
			next = now + neigh->parms->retrans_time;
		}
	} else {
		/* NUD_PROBE|NUD_INCOMPLETE */
		//µ±neigh´¦ÓÚNUD_PROBE»òNUD_INCOMPLETE×´Ì¬Ê±£¬¼ÇÂ¼ÏÂ´Î¼ì²éÊ±¼äµ½next£¬ÒòÎªÕâÁ½ÖÖ×´Ì¬ĞèÒª·¢ËÍARP½âÎö±¨ÎÄ£¬
		//ËüÃÇ¹ı³ÌµÄÇ¨ÒÆÒÀÀµÓÚARP½âÎöµÄ½ø³Ì¡£
		next = now + neigh->parms->retrans_time;
	}

	/*
	 * ¾­¹ı¶¨Ê±Æ÷³¬Ê±ºóµÄ×´Ì¬×ªÒÆ£¬Èç¹ûneigh´¦ÓÚNUD_PROBE»òNUD_INCOMPLETE£¬Ôò»á·¢ËÍARP±¨ÎÄ£¬
	 * ÏÈ»á¼ì²é±¨ÎÄ·¢ËÍµÄ´ÎÊı£¬Èç¹û³¬¹ıÁËÏŞ¶È£¬±íÃ÷¶Ô·½Ö÷»úÃ»ÓĞ»ØÓ¦£¬Ôòneigh½øÈëNUD_FAILED£¬±»ÊÍ·Åµô¡£
	*/
	if ((neigh->nud_state & (NUD_INCOMPLETE | NUD_PROBE)) &&
	    atomic_read(&neigh->probes) >= neigh_max_probes(neigh)) {
		neigh->nud_state = NUD_FAILED;
		notify = 1;
		neigh_invalidate(neigh);
	}

	// ÉèÖÃ¶¨Ê±Æ÷ÏÂ´Îµ½ÆÚÊ±¼ä
	if (neigh->nud_state & NUD_IN_TIMER) {
		if (time_before(next, jiffies + HZ/2))
			next = jiffies + HZ/2;
		if (!mod_timer(&neigh->timer, next))
			neigh_hold(neigh);
	}
	/*
	 * Èç¹ûÁÚ¾Ó±íÏî×´Ì¬´¦ÓÚNUD_INCOMPLETE »òNUD_PROBE£¬ÇÒ·¢ËÍARPÇëÇó´ÎÊıÎ´´ïµ½ÉÏÏŞ£¬ÔòÏòÁÚ¾Ó·¢ËÍARPÇëÇó 
     * neigh->ops->solicitÔÚ´´½¨±íÏîneighÊ±±»¸³Öµ£¬Ò»°ãÊÇarp_solicit£¬²¢ÇÒÔö¼ÓÌ½²â¼ÆËãneigh->probes
	*/
	if (neigh->nud_state & (NUD_INCOMPLETE | NUD_PROBE)) {
		/*¸ù¾İ»º´æ¶ÓÁĞÖĞµÄµÚÒ»¸ö±*/
		struct sk_buff *skb = skb_peek(&neigh->arp_queue);
		/* keep skb alive even if arp_queue overflows ¼´Ê¹arp_queueÒç³ö£¬ÈÔÈ»±£³Ö»î¶¯ */
		if (skb)
			skb = skb_copy(skb, GFP_ATOMIC);
		write_unlock(&neigh->lock);
		neigh->ops->solicit(neigh, skb);/*·¢ËÍARPÇëÇó*///neigh->ops->solicit±»³õÊ¼»¯Îªarp_solicit()£¬ÓÃÀ´¹¹ÔìºÍ·¢ËÍARPÇëÇó¡£µ«ÊÇ·¢ËÍÍêÇëÇóºóÄØ£¿
		atomic_inc(&neigh->probes);     //×ÔÈ»ÊÇµÈ´ıARPÓ¦´ğÁË£¬µ±ÊÕµ½ARPÓ¦´ğºó£¬×îÖÕ»áµ÷ÓÃarp_process()º¯Êı´¦Àí¡£
		kfree_skb(skb);
	} else {
out:
		write_unlock(&neigh->lock);
	}

	//Ïò¸ĞĞËÈ¤µÄÄ£¿éÍ¨ÖªNETEVENT_NEIGH_UPDATEÊÂ¼ş£¬Èç¹û±àÒëÊ±Ö§³ÖARPD,ÔòĞèÍ¨Öªarpd½ø³Ì
	if (notify)
		neigh_update_notify(neigh);

	neigh_release(neigh);
}

/*
 *ËùÒÔneigh_resolve_outputµÄÖ´ĞĞ½á¹û£¬¾ÍÊÇ1£©½«ÁÚ¾Ó±íÏîÖÃÎªNUD_INCOMPLETE£»
 *2£©½«´ı·¢ËÍµÄ±¨ÎÄ´æÈëÁÚ¾Ó±íÏîµÄ»º´æ¶ÓÁĞ¡£¿´µ½ÕâÀï¾ÍºÜÆæ¹ÖÁË£¬ÁÚ¾Ó±íÏîÖĞµÄmacµØÖ·»¹ÊÇÃ»ÓĞÕÒµ½°¡£¬
 *ÔÙËµÊı¾İ°ü±»·ÅÈëÁÚ¾Ó±íÏî¶ÓÁĞÖĞÈ¥ÒÔºóÓÉË­À´·¢ËÍÄØ£¿
 *×¢ÒâÇ°Ãæneigh_add_timer»¹Æô¶¯ÁËÁÚ¾Ó±íÏîµÄ×´Ì¬¶¨Ê±Æ÷¡£Õâ¸ö×´Ì¬¶¨Ê±Æ÷µÄ´¦Àíº¯ÊıÎªneigh_timer_handler¡£
*/
int __neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	int rc;
	unsigned long now;

	write_lock_bh(&neigh->lock);

	rc = 0;
	/*ÁÚ¾Ó×´Ì¬´¦ÓÚNUD_CONNECTED¡¢NUD_DELAY»òNUD_PROBEÔòÖ±½Ó·µ»Ø */
	if (neigh->nud_state & (NUD_CONNECTED | NUD_DELAY | NUD_PROBE))
		goto out_unlock_bh;//Èç¹ûÁ¬½Ó£¬ÑÓ³Ù£¬Ì½²â×´Ì¬¾ÍÍË³ö

	now = jiffies;//¼ÇÂ¼µ±Ç°Ê±¼ä£¬ÖØĞÂÉèÖÃ×´Ì¬Ç°µÄÊµ¼Ê

	/* ´ËÊ±Ê£ÏÂµÄÎ´¿¼²ì×´Ì¬ÎªNUD_STALE ¡¢ NUD_INCOMPLETEºÍUND_NONE£¬
	Òò´ËÈç¹ûµ±Ç°×´Ì¬²»ÎªNUD_STALEºÍNUD_INCOMPLETE Ôò±ØÎªUND_NONE */
	if (!(neigh->nud_state & (NUD_STALE | NUD_INCOMPLETE))) {//Èç¹û²»ÊÇ¹ıÆÚ×´Ì¬»òÎ´Íê³É×´Ì¬
		/*Èç¹ûÔÊĞí·¢ËÍarp¹ã²¥ÇëÇó±¨ÎÄ»òÕßÔÊĞíÓ¦ÓÃ³ÌĞò·¢ËÍÇëÇó±¨ÎÄÀ´½âÎöÁÚ¾ÓµØÖ·£¬
		Ôò½«ÁÚ¾ÓÏî×´Ì¬ÉèÖÃÎªNUD_INCOMPLETE£¬²¢Æô¶¯ÁÚ¾Ó×´Ì¬´¦Àí¶¨Ê±Æ÷*/
		/*
		 ÔÚ·¢ËÍARP±¨ÎÄÊ±ÓĞ3¸ö²ÎÊı- ucast_probes, mcast_probes, app_probes£¬·Ö±ğ´ú±íµ¥²¥´ÎÊı£¬
		 ¹ã²¥´ÎÊı£¬app_probes±È½ÏÌØÊâ£¬Ò»°ãÇé¿öÏÂÎª0£¬µ±Ê¹ÓÃÁËarpdÊØ»¤½ø³ÌÊ±²Å»áÉèÖÃËüµÄÖµ¡£
		 Èç¹ûÒÑ¾­ÊÕµ½¹ı¶Ô·½µÄ±¨ÎÄ£¬¼´ÖªµÀÁË¶Ô·½µÄMAC-IP£¬ARP½âÎö»áÊ¹ÓÃµ¥²¥ĞÎÊ½£¬´ÎÊıÓÉucast_probes¾ö¶¨£»
		 Èç¹ûÎ´ÊÕµ½¹ı¶Ô·½±¨ÎÄ£¬´ËÊ±ARP½âÎöÖ»ÄÜÊ¹ÓÃ¹ã²¥ĞÎÊ½£¬´ÎÊıÓÉmcasat_probes¾ö¶¨¡£
		*/
		if (neigh->parms->mcast_probes + neigh->parms->app_probes) {//¼ì²éÁÚ¾Ó²ÎÊı½á¹¹µÄÌ½²âÖµ
			atomic_set(&neigh->probes, neigh->parms->ucast_probes);//¼ÇÂ¼Ì½²âÖµ
			neigh->nud_state     = NUD_INCOMPLETE;//ĞŞ¸ÄÎªÎ´Íê³É×´Ì¬
			neigh->updated = jiffies;//¼ÇÂ¼µ±Ç°Ê±¼ä£¬ÖØĞÂÉèÖÃ×´Ì¬ºóµÄÊ±¼ä
			neigh_add_timer(neigh, now + 1);//ÉèÖÃ¶¨Ê±Æ÷
		} else {//Ã»ÓĞÉè¶¨Ì½²âÖµ
		/*·ñÔòÁÚ¾ÓÏîÖ»ÄÜ×ª»»ÎªNUD_FAILED ×´Ì¬£¬²¢ÊÍ·Å´ıÊä³ö±¨ÎÄ£¬Í¬Ê±·µ»Ø1£¬±êÊ¾ÁÚ¾ÓÏîÎŞĞ§£¬²»ÄÜÊä³ö*/
			neigh->nud_state = NUD_FAILED;//ĞŞ¸ÄÎªÊ§°Ü×´Ì¬
			neigh->updated = jiffies;//¼ÇÂ¼µ±Ç°Ê±¼ä£¬ÖØĞÂÉèÖÃ×´Ì¬ºóµÄÊ±¼ä
			write_unlock_bh(&neigh->lock);

			kfree_skb(skb);//ÊÍ·Å·¢ËÍµÄÊı¾İ°ü
			return 1;
		}
	} else if (neigh->nud_state & NUD_STALE) {//Èç¹ûÊÇ¹ıÆÚ×´Ì¬
		/*
		Èç¹ûÁÚ¾ÓÏîµ±Ç°×´Ì¬ÎªNUD_STALE,ÓÉÓÚÓĞ±¨ÎÄÊä³öÁË£¬Òò´Ë×´Ì¬×ª±äÎªNUD_DELAY,²¢ÉèÖÃÁÚ¾Ó×´Ì¬´¦Àí¶¨Ê±Æ÷¡£
		×´Ì¬NUD_DELAY±íÊ¾¿ÉÒÔÊä³ö£¬Òò´ËÒ²·µ»Ø0
		*/
		NEIGH_PRINTK2("neigh %p is delayed.\n", neigh);
		neigh->nud_state = NUD_DELAY;//ĞŞ¸ÄÎªÑÓ³Ù×´Ì¬
		neigh->updated = jiffies;//¼ÇÂ¼µ±Ç°Ê±¼ä£¬ÖØĞÂÉèÖÃ×´Ì¬ºóµÄÊ±¼ä
		neigh_add_timer(neigh,
				jiffies + neigh->parms->delay_probe_time);//ÉèÖÃ¶¨Ê±Æ÷
	}

    /* 
    Èç¹ûÁÚ¾ÓÏîµ±Ç°×´Ì¬ÎªNUD_INCOMPLETE£¬ËµÃ÷ÇëÇó±¨ÎÄÒÑ¾­·¢ËÍ£¬µ«ÉĞÎ´ÊÕµ½Ó¦´ğ¡£´ËÊ±Èç¹ûÇëÇó»º´æ¶ÓÁĞ³¤¶È»¹Î´´ïµ½ÉÏÏŞ£¬
	Ôò½«´ıÊä³ö±¨ÎÄ»º´æµ½¸Ã¶ÓÁĞÖĞ£¬·ñÔòÖ»ÄÜ¶ªÆú¸Ã±¨ÎÄ¡£ÎŞÂÛÊÇÄÇÖÖÇé¿ö¶¼·µ»Ø1£¬±íÊ¾»¹²»ÄÜ·¢ËÍ±¨ÎÄ	
    */
	if (neigh->nud_state == NUD_INCOMPLETE) {//Èç¹ûÊÇÎ´Íê³É×´Ì¬
		if (skb) {//ĞèÒª·¢ËÍÊı¾İ°ü
			/*Èç¹ûÇëÇó»º´æÏî¶ÓÁĞ³¤¶È»¹Î´´ïµ½ÉÏÏŞ£¬Ôò½«´ıÊä³ö±¨ÎÄ»º´æµ½¶ÓÁĞÖĞ£¬·ñÔòÖ»ÄÜ¶ªÆú¸Ã±¨ÎÄ¡£
			  ÎŞÂÛÄÇÖÖÇé¿ö¶¼·µ»Ø1£¬±íÊ¾»¹²»ÄÜ·¢ËÍ±¨ÎÄ*/
			if (skb_queue_len(&neigh->arp_queue) >=
			    neigh->parms->queue_len) {//¼ì²â¶ÓÁĞ³¤¶È£¬ÊÇ·ñ´óÓÚÉèÖÃÖµ
				struct sk_buff *buff;
				buff = __skb_dequeue(&neigh->arp_queue);//È¡³ö²»ÄÜÍê³ÉµÄÊı¾İ°ü£¬´Ó¶ÓÁĞÖĞÍÑÁ´
				kfree_skb(buff);//ÊÍ·ÅÊı¾İ°ü
				NEIGH_CACHE_STAT_INC(neigh->tbl, unres_discards);
			}
			__skb_queue_tail(&neigh->arp_queue, skb);//Ã¿Ò»¸öneighbourÏî¶¼ÓĞËü×Ô¼ºµÄÒ»¸öĞ¡µÄ¡¢Ë½ÓĞµÄarp_queue¶ÓÁĞ¡£½«·¢ËÍÊı¾İ°üÁ´Èë¶ÓÁĞ
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
  * ÓÃÓÚ¸üĞÂneighbour½á¹¹Á´Â·²ãµØÖ·ºÍÁÚ¾Ó½á¹¹×´Ì¬µÄÍ¨ÓÃº¯Êı£¬×îºó·¢ËÍÇ°Ãæ¹ÒÈëµ½¶ÓÁĞ»ã×ÜµÄÊı¾İ°ü¡£
  * neigh----Ö¸ÏòÒª¸üĞÂµÄneighbour½á¹¹
  * lladdr---ĞÂµÄÁ´Â·²ã(L2)µØÖ·¡£lladdr²¢²»×ÜÊÇ³õÊ¼»¯ÎªÒ»¸öĞÂÖµ¡£ËäÈ»²ÎÊıÖ¸¶¨ÁËÓ²¼şµØÖ·£¬µ«ÔÚ´¦ÀíÖĞ¸ù¾İ×´Ì¬µÈÌõ¼ş»¹¿ÉÄÜ»á½øĞĞµ÷Õû
             ÀıÈç,µ±µ÷ÓÃneigh_updateÀ´É¾³ıÒ»¸öneighbour½á¹¹Ê±(ÉèÖÃÆä×´Ì¬ÎªNUD_FAILED,"É¾³ıÁÚ¾Ó")
  *          »á¸ølladdr´«µİÒ»¸öNULLÖµ¡£
  * new------ĞÂµÄNUD×´Ì¬¡£
  * flags----ÓÃÓÚ´«µİĞÅÏ¢£¬ÀıÈç£¬ÊÇ·ñÒª¸²¸ÇÒ»¸öÒÑÓĞµÄÁ´Â·²ãµØÖ·µÈ¡£
*/
int neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new,
		 u32 flags)
{
	u8 old;
	int err;
	int notify = 0;
	struct net_device *dev;
	int update_isrouter = 0;

	write_lock_bh(&neigh->lock);//Ëø¶¨neighbour

	dev    = neigh->dev;//»ñÈ¡ÍøÂçÉè±¸½á¹¹
	old    = neigh->nud_state;//»ñÈ¡ÁÚ¾Ó½á¹¹µÄÔ­À´×´Ì¬
	err    = -EPERM;

	/*ÁÚ¾Ó±íÏîmacµØÖ·µÄÌî³ä*/
	/*
     *Ö»ÓĞ¹ÜÀíÃüÁî(NEIGH_UPDATE_F_ADMIN)¿ÉÒÔ¸Ä±äµ±Ç°×´Ì¬ÊÇNUD_NOARPÌ¬»òNUD_PERMANENTÌ¬µÄÁÚ¾ÓµÄ×´Ì¬¡£
	*/
	if (!(flags & NEIGH_UPDATE_F_ADMIN) &&
	    (old & (NUD_NOARP | NUD_PERMANENT)))
		goto out;//Ô¼ÊøÌõ¼ş²»Âú×ã£¬³ÌĞò¾Í»áÍË³ö

	if (!(new & NUD_VALID)) {//µ±ĞÂ×´Ì¬new²»ÊÇÒ»¸öºÏ·¨×´Ì¬Ê±£¬Èç¹ûËüÊÇNUD_NONEÌ¬»òNUD_INCOMPLETEÌ¬£¬¾ÍÒªÍ£Ö¹Æô¶¯ÁËµÄÁÚ¾Ó¶¨Ê±Æ÷
		neigh_del_timer(neigh);//is the new state NUD_VALID,not Í£Ö¹¶¨Ê±Æ÷
		if (old & NUD_CONNECTED)
			neigh_suspect(neigh);//Èô¾É×´Ì¬ÊÇNUD_CONNECTED£¬µ÷ÓÃº¯Êı½«ÁÚ¾ÓÏÈ±ê¼ÇÎª¿ÉÒÉµÄ(ÒªÇó½øĞĞ¿Éµ½´ïĞÔÈÏÖ¤)¡£
		neigh->nud_state = new;//ÉèÖÃĞÂ×´Ì¬
		err = 0;
		notify = old & NUD_VALID;//Í¨ÖªAPRD
		//µ±Ô­ÏÈ×´Ì¬ÊÇNUD_INCOMPLETE»òNUD_PROBE×´Ì¬Ê±£¬¿ÉÄÜÓĞÔİÊ±ÒòÎªµØÖ·Ã»ÓĞ½âÎö¶øÔİ´æÔÚneigh->arp_queueÖĞµÄ±¨ÎÄ£¬
		//¶øÏÖÔÚ±íÏî¸üĞÂµ½NUD_FAILED£¬¼´½âÎöÎŞ·¨³É¹¦£¬ÄÇÃ´ÕâÃ´Ôİ´æµÄ±¨ÎÄÒ²Ö»ÄÜ±»¶ªÆúneigh_invalidate¡£
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
	Èç¹ûĞÂ×´Ì¬ÎªNUD_CONNECTED£¬ËµÃ÷ÁÚ¾Ó´¦ÓÚÁ¬½Ó×´Ì¬£¬¿ÉÒÔÖ±½Ó¸ù¾İ¸ÃÁÚ¾ÓÏî·¢ËÍÊı¾İ°ü£¬Òò´ËĞèÒª¸üĞÂÈ·ÈÏÊ±¼ä¡£
	ÉèÖÃ¸üĞÂÊ±¼ä
	*/
	if (new & NUD_CONNECTED)
		neigh->confirmed = jiffies;
	neigh->updated = jiffies;//¼ÇÂ¼µ±Ç°Ê±¼ä

	/* If entry was valid and address is not changed,
	   do not change entry state, if new one is STALE.
	   Èç¹ûÌõÄ¿ÓĞĞ§²¢ÇÒµØÖ·Î´¸ü¸Ä£¬Ôò²»Òª¸ü¸ÄÌõÄ¿×´Ì¬£¬Èç¹ûĞÂµÄÊÇSTALE¡£
	 */
	err = 0;
	update_isrouter = flags & NEIGH_UPDATE_F_OVERRIDE_ISROUTER;//NEIGH_UPDATE_F_OVERRIDE_ISROUTER,Ö»ÔÚIPV6ÖĞ´æÔÚ
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
			// NUD_REACHABLE×´Ì¬Ê±£¬ĞÂ×´Ì¬ÎªNUD_STALEÊÇÔÚÏÂÃæÕâ¶Î´úÂëÀïÃæ³ıÈ¥ÁË£¬
			// ÒòÎªNUD_REACHABLE×´Ì¬¸üºÃ£¬²»Ó¦¸Ã»ØÍËµ½NUD_STALE×´Ì¬¡£
			if (lladdr == neigh->ha && new == NUD_STALE &&
			    ((flags & NEIGH_UPDATE_F_WEAK_OVERRIDE) ||
			     (old & NUD_CONNECTED))
			    )
				new = old;
		}
	}

	//ĞÂ¾É×´Ì¬²»Í¬Ê±£¬Ê×ÏÈÉ¾³ı¶¨Ê±Æ÷£¬Èç¹ûĞÂ×´Ì¬ĞèÒª¶¨Ê±Æ÷£¬ÔòÖØĞÂÉèÖÃ¶¨Ê±Æ÷£¬×îºóÉèÖÃ±íÏîneighÎªĞÂ×´Ì¬new¡£
	if (new != old) {
		neigh_del_timer(neigh);//Õª³ı¶¨Ê±Æ÷
		if (new & NUD_IN_TIMER)//Ã¿¸öÁÚ¾ÓµÄ¶¨Ê±Æ÷µÄÃ¿´ÎÆô¶¯¶¼»áµ¼ÖÂ¸ÃÁÚ¾ÓµÄÒıÓÃ¼ÆÊı¼Ó1
			neigh_add_timer(neigh, (jiffies +
						((new & NUD_REACHABLE) ?
						 neigh->parms->reachable_time :
						 0)));//ÖØĞÂÉèÖÃ¶¨Ê±Æ÷
		neigh->nud_state = new;//ĞŞ¸ÄÁÚ¾Ó½á¹¹µÄ×´Ì¬
	}

    //Èç¹ûÁÚ¾Ó±íÏîÖĞµÄµØÖ··¢ÉúÁË¸üĞÂ£¬ÓĞÁËĞÂµÄµØÖ·Öµlladdr£¬ÄÇÃ´¸üĞÂ±íÏîµØÖ·neigh->ha£¬
    //²¢¸üĞÂÓë´Ë±íÏîÏà¹ØµÄËùÓĞ»º´æ±íÏîneigh_update_hhs¡£
	if (lladdr != neigh->ha) {//Èç¹û·şÎñÆ÷MACµØÖ·ÓëÔ­À´¼ÇÂ¼µÄ²»Í¬
		memcpy(&neigh->ha, lladdr, dev->addr_len);//¼ÇÂ¼·şÎñÆ÷MACµØÖ·
		neigh_update_hhs(neigh);
		if (!(new & NUD_CONNECTED))
			neigh->confirmed = jiffies -
				      (neigh->parms->base_reachable_time << 1);//µ÷ÕûÈ·¶¨Ê±¼ä
		notify = 1;
	}
	if (new == old)//Èç¹ûĞŞ¸Ä×´Ì¬ÓëÔ­Ê¼×´Ì¬ÏàÍ¬¾ÍÖ±½Ó·µ»Ø
		goto out;
	if (new & NUD_CONNECTED)//¼ì²éÊÇ·ñÎªÁ¬½Ó×´Ì¬
		neigh_connect(neigh); //ÉèÖÃneigh->output£¬ÖØĞÂÉèÖÃÁÚ¾Ó½á¹¹µÄ·¢ËÍº¯Êı
	else
		neigh_suspect(neigh); //ÉèÖÃÁÚ¾Ó½á¹¹µÄ·¢ËÍº¯Êı
	/* Èç¹ûÁÚ¾Ó±íÏîÓÉÎŞĞ§×´Ì¬±äÎªÓĞĞ§×´Ì¬(×¢:Ö®Ç°×´Ì¬ÎªNUD_INCOMPLETE£¬ÊôÓÚÎŞĞ§×´Ì¬£¬¶ø¼´½«±äÎªNUD_REACHABLEÎªÓĞĞ§×´Ì¬µÄÒ»ÖÖ) */
	if (!(old & NUD_VALID)) {
		struct sk_buff *skb;

		/* Again: avoid dead loop if something went wrong */
		/*±éÀúÁÚ¾Ó±íÏîµÄ»º´æ¶ÓÁĞarp_queue£¬½«»º´æÔÚ¶ÓÁĞÖĞµÄ±¨ÎÄÖğ¸öÊä³ö*/
		while (neigh->nud_state & NUD_VALID &&
		       (skb = __skb_dequeue(&neigh->arp_queue)) != NULL) {
			struct neighbour *n1 = neigh;
			write_unlock_bh(&neigh->lock);
			/* On shaper/eql skb->dst->neighbour != neigh :( */
			if (skb_dst(skb) && skb_dst(skb)->neighbour)
				n1 = skb_dst(skb)->neighbour;
			//ÖÕÓÚ½«ÁÚ¾Ó±íÏîÖĞµÄmacÌî³äÁË£¬¹¹½¨³öÁËÍêÕûµÄÁÚ¾Ó±íÏî£¬Ò²ÖÕÓÚ½«Êı¾İ°ü·¢ËÍ³öÈ¥¡£
			//ÕâÀïÊ¹ÓÃµÄ·¢ËÍº¯ÊıÎªneigh->outputÔÚneigh_connectÖĞ±»ÉèÖÃ¡£ 
			//¶ÔÓÚÉèÖÃÁÚ¾Ó½á¹¹µÄ·¢ËÍº¯Êı£¬Æä½á¹ûÈÔÈ»ÊÇneigh_resolve_output()º¯Êı£¬
			//½ÓÏÂÀ´µ÷ÓÃ¸Ãº¯Êı£¬½«Ç°Ãæ__neigh_event_send()º¯ÊıÁ´Èëµ½ARP¶ÓÁĞµÄÊı¾İ°ü£¬ÖğÒ»·¢ËÍ¸ø·şÎñÆ÷
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
	write_unlock_bh(&neigh->lock);//½âËøneighbour

	//·¢³öÍ¨Öª,Í¨¹ıÄÚºËµÄÍ¨ÖªÁ´ºÍnetlink·¢²¼ÁÚ¾Ó½á¹¹¸üĞÂµÄÏûÏ¢£¬Ç°ÃæµÄarp_init()º¯ÊıÒÑ¾­ÏòÄÚºËµÇ¼ÇÁËARPµÄÍ¨Öª½Úµã
	//arp_notifier£¬netlinkÔò±»IPROUTER2ÓÃÀ´¿ØÖÆÁÚ¾Ó×ÓÏµÍ³¡£
	if (notify)//aprdĞèÒªÒ»¸öÍ¨ÖªÂğ?Èç¹û±àÒëÊ±Ö§³ÖARPD,Ôò»¹ĞèÒªÍ¨ÖªARPD½ø³Ì
		neigh_update_notify(neigh);

	return err;
}
EXPORT_SYMBOL(neigh_update);

struct neighbour *neigh_event_ns(struct neigh_table *tbl,
				 u8 *lladdr, void *saddr,
				 struct net_device *dev)
{
	struct neighbour *neigh = __neigh_lookup(tbl, saddr, dev,
						 lladdr || !dev->addr_len);//²éÕÒÁÚ¾Ó½á¹¹
	if (neigh)
		neigh_update(neigh, lladdr, NUD_STALE,
			     NEIGH_UPDATE_F_OVERRIDE);
	return neigh;
}
EXPORT_SYMBOL(neigh_event_ns);

/*
 * ´Ëº¯ÊıÊµÏÖÍ¨¹ıÁÚ¾ÓÏîÎªÖ¸¶¨Â·ÓÉ»º´æÏî½¨Á¢Ó²¼şÊ×²¿»º´æ
*/
static void neigh_hh_init(struct neighbour *n, struct dst_entry *dst,
			  __be16 protocol)
{
	struct hh_cache	*hh;
	struct net_device *dev = dst->dev;

	/*¸ù¾İĞ­ÒéÔÚÁÚ¾ÓÏîµÄÓ²¼ş»º´æÁĞ±íÖĞ²éÕÒ¶ÔÓ¦µÄÓ²¼şÊ×²¿»º´æ¡£Èç¹û²éÕÒÃüÖĞ£¬
	ÔòÊ¹ÓÃ¸ÃÓ²¼şÊ×²¿»º´æÎªÂ·ÓÉ»º´æ½¨Á¢Ó²¼şÊ×²¿»º´æ¡£
	*/
	for (hh = n->hh; hh; hh = hh->hh_next)
		if (hh->hh_type == protocol)
			break;

	/*Èç¹û²éÕÒÎ´¹û£¬Ôò´´½¨ĞÂµÄÓ²¼şÊ×²¿»º´æ£¬²¢½«ÆäÌí¼Óµ½ÁÚ¾ÓÏîµÄÓ²¼ş»º´æÁĞ±íÖĞ£¬Í¬Ê±¸ù¾İ×´Ì¬ÉèÖÃºÏÊÊµÄhh_outputº¯ÊıÖ¸Õë
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
	/* ½«²éÕÒÃüÖĞµÄ»òÊÇĞÂ´´½¨µÄÓ²¼şÊ×²¿»º´æÉèÖÃµ½Â·ÓÉ»º´æÏîÖĞ */
	if (hh)	{
		atomic_inc(&hh->hh_refcnt);
		dst->hh = hh;
	}
}

/* This function can be used in contexts, where only old dev_queue_xmit
   worked, f.e. if you want to override normal output path (eql, shaper),
   but resolution is not made yet.
   ¸Ãº¯ÊıÊÇÎªÁË±£Ö¤ÏòÏÂ¼æÈİ¡£ÔÚÒıÈëÁÚ¾Ó»ù´¡½á¹¹ÒÔÇ°£¬ÓÉËü¸ºÔğµ÷ÓÃdev_queue_xmitº¯Êı£¬¼´Ê¹L2µØÖ·»¹Ã»ÓĞ×¼±¸ºÃ¡£
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
/*×÷ÓÃ:
 *µ±ÁÚ¾ÓÏî²»´¦ÓÚNUD_CONNECTED×´Ì¬Ê±£¬²»ÔÊĞí¿ìËÙÂ·¾¶·¢ËÍ±¨ÎÄ¡£º¯Êıneigh_resolve_output()ÓÃÓÚÂıËÙ¶ø°²È«µÄÊä³ö£¬
 *Í¨³£ÓÃÀ´³õÊ¼»¯neigh_ops½á¹¹ÊµÀıµÄoutputº¯ÊıÖ¸Õë£¬µ±ÁÚ¾ÓÏî´ÓNUD_CONNECTED×ª¶ø·ÇNUD_CONNECTED×´Ì¬£¬±ã»áµ÷ÓÃ
 *neigh_suspect½«ÁÚ¾ÓÏîµÄoutputÉèÖÃÎªneigh_resolve_output()
 *×¢Òâ:
 * ¸Ãº¯ÊıÔÚÊı¾İ´«ÊäÇ°½«L3µØÖ·½âÎöÎªL2µØÖ·¡£Òò´Ë£¬µ±L3µØÖ·ºÍL2µØÖ·µÄ¶ÔÓ¦¹ØÏµ»¹Ã»ÓĞ½¨Á¢»òÕßĞèÒª¶ÔÆäÈ·ÈÏÊ±£¬
 * ¾Í»áÓÃµ½¸Ãº¯Êı¡£Èç¹û´´½¨Ò»¸ö
 * neighbourĞÂ½á¹¹²¢ÇÒĞèÒª¶ÔÆäL3µØÖ·½øĞĞ½âÎöÊ±£¬³ıÁË"ÌØÊâÇé¿ö"Íâ£¬neigh_resolve_outputÊÇ×÷ÎªÄ¬ÈÏº¯ÊıÊ¹ÓÃµÄ¡£
 * µ±Ö÷»úĞèÒª½âÎöµØÖ·£¬»áµ÷ÓÃneigh_resolve_output£¬Ö÷»úÒıÓÃ±íÏîÃ÷ÏÔ»áÉæ¼°µ½±íÏîµÄNUD×´Ì¬Ç¨ÒÆ£¬
 * NUD_NONE->NUD_INCOMPLETE£¬NUD_STALE->NUD_DELAY¡£
*/
int neigh_resolve_output(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);/*È¡µÃ¶ÔÓ¦µÄÂ·ÓÉ»º´æ*/
	struct neighbour *neigh;
	int rc = 0;

	if (!dst || !(neigh = dst->neighbour))//Èç¹ûÂ·ÓÉÏî»òËüµÄÁÚ¾Ó½á¹¹¶¼Ã»ÓĞ´æÔÚ¾Í·µ»Ø
		goto discard;

	/*Ö¸ÏòÈı²ã£¨ip£©Í·²¿*/
	__skb_pull(skb, skb_network_offset(skb));

	/*È·±£ÓÃÓÚÊä³öµÄÁÚ¾ÓÏî×´Ì¬ÓĞĞ§²ÅÄÜ·¢ËÍÊı¾İ°ü*/
	if (!neigh_event_send(neigh, skb)) {//¼ì²éÁÚ¾Ó½á¹¹ÊÇ·ñ¿ÉÓÃ£¬Èç¹û¿ÉÓÃ¼ÌĞø·¢ËÍ£¬·µ»Ø0Îª¿ÉÓÃ
		int err;
		struct net_device *dev = neigh->dev;
		/*Èç¹ûÁÚ¾ÓÏîµÄÊä³öÉè±¸Ö§³Öhard_header_cache£¬Í¬Ê±Â·ÓÉ»º´æÏîÖĞµÄ¶ş²ãÊ×²¿»º´æÉĞÎ´½¨Á¢£¬
		ÔòÏÈÎª¸ÃÂ·ÓÉ»º´æ½¨Á¢Ó²¼şÊ×²¿»º´æ(struce hh_cache)£¬
		È»ºóÔÚÊä³öµÄ±¨ÎÄÇ°Ìí¼Ó¸ÃÓ²¼şÊ×²¿£¬·ñÔòÖ±½ÓÔÚ±¨ÎÄÇ°Ìí¼ÓÓ²¼şÊ×²¿*/
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
		
		/*Èç¹ûÌí¼ÓÓ²¼şÊ×²¿³É¹¦£¬Ôòµ÷ÓÃqueue_xmit()½«±¨ÎÄÊä³öµ½ÍøÂçÉè±¸*/
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
   ´Ëº¯Êı³õÊ¼»¯neigh_ops½á¹¹ÊµÀıµÄconnected_outputº¯ÊıÖ¸Õë¡£
   µ±ÁÚ¾ÓÏî´Ó·ÇNUD_CONNECTED×ªµ½NUD_CONNECTED×´Ì¬£¬
   ±ãµ÷ÓÃneigh_connect()½«ÁÚ¾ÓÏîµÄoutputÉèÖÃÎªneigh_connected_output()¡£

 * ¸Ãº¯ÊıÖ»ÊÇÌî³äL2ÕíÍ·£¬È»ºóµ÷ÓÃneigh_ops->queue_xmit¡£Òò´Ë£¬ËüÏ£ÍûL2µØÖ·±»½âÎö¡£neighbour½á¹¹ÔÚNUD_CONNECTED×´Ì¬»áÓÃµ½Õâ¸öº¯Êı¡£
*/
int neigh_connected_output(struct sk_buff *skb)
{
	int err;
	struct dst_entry *dst = skb_dst(skb);
	struct neighbour *neigh = dst->neighbour;
	struct net_device *dev = neigh->dev;

	__skb_pull(skb, skb_network_offset(skb));

	read_lock_bh(&neigh->lock);
	/*¹¹½¨±¨ÎÄ¶ş²ãmacÍ·²¿,ÔÚ´ıÊä³öµÄ±¨ÎÄÌí¼ÓÓ²¼şÊ×²¿£¬ÒÔÌ«ÍøÉÏ£¬ÔòÌí¼ÓÒÔÌ«ÍøÖ¡Ê×²¿ */
	err = dev_hard_header(skb, dev, ntohs(skb->protocol),
			      neigh->ha, NULL, skb->len);
	read_unlock_bh(&neigh->lock);
	//Èç¹ûÌí¼ÓÓ²¼şÊ×²¿³É¹¦£¬Ôòµ÷ÓÃqueue_xmit()½«±¨ÎÄÊä³öµ½ÍøÂçÉè±¸¡£
	if (err >= 0)
		err = neigh->ops->queue_xmit(skb);/*·¢ËÍskb*/
	else {
		err = -EINVAL;
		kfree_skb(skb);
	}
	return err;
}
EXPORT_SYMBOL(neigh_connected_output);

/*
  proxy_timer¶¨Ê±Æ÷ÊÇÔÚneigh_table_init_no_netlink()ÖĞ³õÊ¼»¯µÄ£¬Æä´¦Àíº¯ÊıÎªneigh_proxy_process()¡£Ã¿µ±proxy_timerµ½ÆÚÊ±£¬
  ¸Ãº¯Êı¾Í»á´Ó»º´æ¶ÓÁĞÖĞÖğ¸öÈ¡³ö²¢´¦Àí±¨ÎÄ£¬Ö±ÖÁÈ«²¿´¦ÀíÍê±Ï¡£
*/
static void neigh_proxy_process(unsigned long arg)
{
	struct neigh_table *tbl = (struct neigh_table *)arg;
	long sched_next = 0;
	unsigned long now = jiffies;
	struct sk_buff *skb, *n;

	spin_lock(&tbl->proxy_queue.lock);

	skb_queue_walk_safe(&tbl->proxy_queue, skb, n) {//±éÀúproxy_queue¶ÓÁĞ
		long tdif = NEIGH_CB(skb)->sched_next - now;

		//Èç¹ûÑÓÊ±µÄÊ±¼äÒÑ¾­³¬³öµ±Ç°ÇëÇó±¨ÎÄµÄÑÓÊ±Ê±¼ä£¬Ôò½«¸ÃÇëÇó±¨ÎÄ´Ó¶ÓÁĞÖĞÈ¡ÏÂ£¬È»ºó¸ù¾İÁÚ¾Ó±íproxy_redo½Ó¿ÚµÄÓĞĞ§ĞÔÒÔ
		//ÒÔ¼°Êä³öÉè±¸ÊÇ·ñÆôÓÃÀ´¾ö¶¨ÊÇµ÷ÓÃproxy_redo()´¦ÀíÖ®»¹ÊÇ¶ªÆúÖ®¡£
		if (tdif <= 0) {
			struct net_device *dev = skb->dev;
			__skb_unlink(skb, &tbl->proxy_queue);
			if (tbl->proxy_redo && netif_running(dev))
				tbl->proxy_redo(skb);
			else
				kfree_skb(skb);

			dev_put(dev);
		} else if (!sched_next || tdif < sched_next)//ÖØĞÂ¼ÆËã²¢ÉèÖÃproxy_timer¶¨Ê±Æ÷ÏÂ´Îµ½ÆÚÊ±¼ä¡£
			sched_next = tdif;
	}
	del_timer(&tbl->proxy_timer);
	if (sched_next)
		mod_timer(&tbl->proxy_timer, jiffies + sched_next);
	spin_unlock(&tbl->proxy_queue.lock);
}

/*
 * µ±ÔÚÑÓÊ±´¦ÀíµÄ´úÀíÇëÇó±¨ÎÄÊ±£¬»áµ÷ÓÃpneigh_enqueue()½«ÇëÇó±¨ÎÄ»º´æµ½proxy_queue¶ÓÁĞÖĞ£¬
 * È»ºóÉèÖÃproxy_timer¶¨Ê±Æ÷£¬µ½¶¨Ê±Æ÷µ½ÆÚÊ±ÔÙ´¦Àí¸ÃÇëÇó±¨ÎÄ¡£
*/
void pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
		    struct sk_buff *skb)
{
	//ÓĞµ±Ç°Ê±¼ä£¬Ëæ»úÊıºÍproxy_dely¼ÆËãÇëÇó±¨ÎÄµÄÑÓÊ±Ê±¼ä¡£
	unsigned long now = jiffies;
	unsigned long sched_next = now + (net_random() % p->proxy_delay);

	//Èç¹ûÁÚ¾Ó±íµÄ´úÀí±¨ÎÄ»º´æ¶ÓÁĞ³¤¶ÈÒÑ´ïµ½ÉÏÏŞ£¬Ôò½«±¨ÎÄ¶ªÆú
	if (tbl->proxy_queue.qlen > p->proxy_qlen) {
		kfree_skb(skb);
		return;
	}

	//½«Ö®Ç°¼ÆËãµÃµ½µÄÑÓÊ±Ê±¼äºÍLOCALLY_ENQUEUED±êÖ¾±£´æµ½¸ÃÇëÇó±¨ÎÄµÄ¿ØÖÆ¿éÖĞ¡£
	NEIGH_CB(skb)->sched_next = sched_next;
	NEIGH_CB(skb)->flags |= LOCALLY_ENQUEUED;

	//ÏÈÈ¥»îproxy_timer¶¨Ê±Æ÷£¬È»ºóÔÚÔ­µ½ÆÚÊ±¼äºÍ¼ÆËãµÃµ½µÄÑÓÆÚÊ±¼äÖ®ÖĞÈ¡½üÕßÎªĞÂµ½ÆÚÊ±¼ä¡£
	spin_lock(&tbl->proxy_queue.lock);
	if (del_timer(&tbl->proxy_timer)) {
		if (time_before(tbl->proxy_timer.expires, sched_next))
			sched_next = tbl->proxy_timer.expires;
	}
	//°ÑskbµÄÂ·ÓÉ»º´æÏîÖÃ¿Õºó½«ÆäÌí¼Óµ½proxy_queue¶ÓÁĞ
	skb_dst_drop(skb);
	dev_hold(skb->dev);
	__skb_queue_tail(&tbl->proxy_queue, skb);
	mod_timer(&tbl->proxy_timer, sched_next);//ÖØĞÂÉèÖÃproxy_timer¶¨Ê±Æ÷ÏÂ´Îµ½ÆÚÊ±¼ä
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
 * ´Ëº¯ÊıÓÃÓÚ³õÊ¼»¯neigh_table½á¹¹:Ö÷ÒªÍê³ÉÒÔÏÂ¹¤×÷
 * 1.Îªneighbour½á¹¹·ÖÅäÔ¤±¸µÄÄÚ´æ³Ø¡£
 * 2.·ÖÅäÒ»¸öneigh_statistics½á¹¹À´ÊÕ¼¯Ğ­ÒéµÄÍ³¼ÆĞÅÏ¢¡£
 * 3.·ÖÅäÁ½¸öhash±í:hash_bucketsºÍphash_buckets¡£ÕâÁ½¸ö±í·Ö±ğ×÷Îª½âÎö¹ıµÄµØÖ·¹ØÁª»º´æºÍ´úÀíµÄµØÖ·Êı¾İ¿â¡£
 * 4.ÔÚ/proc/netÖĞ½¨Á¢Ò»¸öÎÄ¼ş£¬ÓÃÓÚ×ª´¢»º´æµÄÄÚÈİ¡£ÎÄ¼şÃûÀ´×Ôneigh_table->id
 * 5.Æô¶¯gc_timerÀ¬»ø»ØÊÕ¶¨Ê±Æ÷.
 * 6.³õÊ¼»¯(µ«ÊÇ²»Æô¶¯)proxy_timer´úÀí¶¨Ê±Æ÷ºÍÏà¹ØµÄproxy_queue¶ÓÁĞ¡£
 * 7.Ìí¼Óneigh_table½á¹¹µ½neigh_tablesÈ«¾ÖÁĞ±íÖĞ¡£ºóÕßÓÉÒ»¸öËø±£»¤¡£
 * 8.³õÊ¼»¯ÆäËûÒ»Ğ©²ÎÊı¡£ÀıÈçreachable_time¡£
*/
void neigh_table_init(struct neigh_table *tbl)
{
	struct neigh_table *tmp;

	neigh_table_init_no_netlink(tbl);//³õÊ¼»¯ÁÚ¾Ó±í
	write_lock(&neigh_tbl_lock);//¶Ôneigh_tables²Ù×÷£¬½øĞĞ¼ÓËø´¦Àí
	for (tmp = neigh_tables; tmp; tmp = tmp->next) {
		if (tmp->family == tbl->family)//²é¿´ÏàÍ¬µØÖ·×åµÄÁÚ¾Ó±í
			break;
	}
	//½«ÁÚ¾Ó±í²åÈëµ½¶ÓÁĞµÄÇ°Ãæ
	tbl->next	= neigh_tables;
	neigh_tables	= tbl;//·Åµ½¶ÓÁĞÇ°Ãæ
	write_unlock(&neigh_tbl_lock);

	if (unlikely(tmp)) {//Èç¹ûÕÒµ½ÏàÍ¬µØÖ·×åÁÚ¾Ó±í¾Í´òÓ¡´íÎóĞÅÏ¢
		printk(KERN_ERR "NEIGH: Registering multiple tables for "
		       "family %d\n", tbl->family);
		dump_stack();
	}
}
EXPORT_SYMBOL(neigh_table_init);

/*
 * µ±Ò»¸öĞ­ÒéÊ¹ÓÃÄ£¿é·½Ê½ÔÊĞí£¬²¢ÇÒÄ£¿é±»Ğ¶ÔØÊ±£¬»áµ÷ÓÃ´Ëº¯ÊıÀ´³·Ïúneigh_table_intÔÚ³õÊ¼»¯Ê±Ëù×öµÄ¹¤×÷£¬
 * ²¢ÇÒ»áÇåÀíÔÚĞ­ÒéÉú´æÆÚÄÚ·ÖÅä¸ø¸ÃĞ­ÒéµÄÈÎºÎ×ÊÔ´£¬ÀıÈç£¬¶¨Ê±Æ÷ºÍ¶ÓÁĞ¡£
 * IPv4ÊÇÎ¨Ò»²»ÄÜ±àÒëÎªÄ£¿éµÄĞ­Òé£¬Òò´ËARP²»ĞèÒªÇåÀíº¯Êı.
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
	´ÓÏûÏ¢µÄºó²¿£¬¼´ÁÚ¾ÓĞÅÏ¢Ö®ºó£¬»ñÈ¡±ä³¤µÄÀ©Õ¹ÊôĞÔ£¬²¢Ğ£Ñé±£´æ´æÔÚNDA_DSTÀàĞÍµÄÀ©Õ¹ÊôĞÔ
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
	ÓÉÁÚ¾ÓÏîµÄÍøÂçÉè±¸Ë÷Òı»ñÈ¡¶ÔÓ¦µÄÍøÂçÉè±¸.Èç¹û´æÔÚ¶ş²ãµØÖ·À©Õ¹ÊôĞÔ£¬ÔòĞèĞ£Ñé
	*/
	read_lock(&neigh_tbl_lock);
	//±éÀúneigh_tablesÁ´±íÖĞËùÓĞµÄÁÚ¾Ó±í£¬»ñÈ¡ÓëÏûÏ¢ÖĞ¸ø³öµÄµØÖ·×åÏàÒ»ÖÂµÄÁÚ¾Ó±í
	for (tbl = neigh_tables; tbl; tbl = tbl->next) {
		int flags = NEIGH_UPDATE_F_ADMIN | NEIGH_UPDATE_F_OVERRIDE;
		struct neighbour *neigh;
		void *dst, *lladdr;

		if (tbl->family != ndm->ndm_family)
			continue;
		read_unlock(&neigh_tbl_lock);

		//´ÓÀ©Õ¹ÊôĞÔÖµÖĞ»ñÈ¡Ïà¹ØµÄĞÅÏ¢µÈ´ı´¦Àí
		if (nla_len(tb[NDA_DST]) < tbl->key_len)
			goto out_dev_put;
		dst = nla_data(tb[NDA_DST]);
		lladdr = tb[NDA_LLADDR] ? nla_data(tb[NDA_LLADDR]) : NULL;

		if (ndm->ndm_flags & NTF_PROXY) {
			struct pneigh_entry *pn;

			err = -ENOBUFS;
			pn = pneigh_lookup(tbl, net, dst, dev, 1);//Ìí¼ÓÒ»¸ö´úÀíÏî
			if (pn) {
				pn->flags = ndm->ndm_flags;
				err = 0;
			}
			goto out_dev_put;
		}

		//Ìí¼ÓÁÚ¾ÓÏîÇ°£¬È·±£¸ÃÁÚ¾ÓµÄÊä³öÍøÂçÉè±¸²»ÄÜÎª¿Õ
		if (dev == NULL)
			goto out_dev_put;

		//µ÷ÓÃneigh_lookup()¸ù¾İÁÚ¾ÓÏîµÄµØÖ·ÒÔ¼°Êä³öÍøÂçÉè±¸£¬ÔÚÁÚ¾Ó±íµÄÁÚ¾ÓÉ¢ÁĞ±íÖĞÕÒµ½¶ÔÓ¦µÄÁÚ¾ÓÏî
		neigh = neigh_lookup(tbl, dst, dev);
		if (neigh == NULL) {
			if (!(nlh->nlmsg_flags & NLM_F_CREATE)) {
				err = -ENOENT;
				goto out_dev_put;
			}

			/* Èç¹ûÃ»ÓĞÔÚÁÚ¾Ó±íÖĞÕÒµ½¶ÔÓ¦µÄÁÚ¾ÓÏî£¬ÇÒnetlinkÌí¼ÓÁÚ¾ÓÏîÏûÏ¢Ê×²¿µÄnlmsg_flagsÓòÖĞ´æÔÚNLM_F_CREATE±êÖ¾£¬
			   ¸Ã±êÖ¾±íÊ¾²»´æÔÚ¼´´´½¨Ö®£¬Ôòµ÷ÓÃneigh_lookup_errno()´´½¨²¢Ìí¼ÓÏàÓ¦µÄÁÚ¾ÓÏîµ½É¢ÁĞ±íÖĞ
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
			err = neigh_update(neigh, lladdr, ndm->ndm_state, flags);//¸üĞÂÖ¸¶¨Ïî
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

