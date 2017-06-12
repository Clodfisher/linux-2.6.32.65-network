/* linux/net/ipv4/arp.c
 *
 * Copyright (C) 1994 by Florian  La Roche
 *
 * This module implements the Address Resolution Protocol ARP (RFC 826),
 * which is used to convert IP addresses (or in the future maybe other
 * high-level addresses) into a low-level hardware address (like an Ethernet
 * address).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Fixes:
 *		Alan Cox	:	Removed the Ethernet assumptions in
 *					Florian's code
 *		Alan Cox	:	Fixed some small errors in the ARP
 *					logic
 *		Alan Cox	:	Allow >4K in /proc
 *		Alan Cox	:	Make ARP add its own protocol entry
 *		Ross Martin     :       Rewrote arp_rcv() and arp_get_info()
 *		Stephen Henson	:	Add AX25 support to arp_get_info()
 *		Alan Cox	:	Drop data when a device is downed.
 *		Alan Cox	:	Use init_timer().
 *		Alan Cox	:	Double lock fixes.
 *		Martin Seine	:	Move the arphdr structure
 *					to if_arp.h for compatibility.
 *					with BSD based programs.
 *		Andrew Tridgell :       Added ARP netmask code and
 *					re-arranged proxy handling.
 *		Alan Cox	:	Changed to use notifiers.
 *		Niibe Yutaka	:	Reply for this device or proxies only.
 *		Alan Cox	:	Don't proxy across hardware types!
 *		Jonathan Naylor :	Added support for NET/ROM.
 *		Mike Shaver     :       RFC1122 checks.
 *		Jonathan Naylor :	Only lookup the hardware address for
 *					the correct hardware type.
 *		Germano Caronni	:	Assorted subtle races.
 *		Craig Schlenter :	Don't modify permanent entry
 *					during arp_rcv.
 *		Russ Nelson	:	Tidied up a few bits.
 *		Alexey Kuznetsov:	Major changes to caching and behaviour,
 *					eg intelligent arp probing and
 *					generation
 *					of host down events.
 *		Alan Cox	:	Missing unlock in device events.
 *		Eckes		:	ARP ioctl control errors.
 *		Alexey Kuznetsov:	Arp free fix.
 *		Manuel Rodriguez:	Gratuitous ARP.
 *              Jonathan Layes  :       Added arpd support through kerneld
 *                                      message queue (960314)
 *		Mike Shaver	:	/proc/sys/net/ipv4/arp_* support
 *		Mike McLagan    :	Routing by source
 *		Stuart Cheshire	:	Metricom and grat arp fixes
 *					*** FOR 2.1 clean this up ***
 *		Lawrence V. Stefani: (08/12/96) Added FDDI support.
 *		Alan Cox 	:	Took the AP1000 nasty FDDI hack and
 *					folded into the mainstream FDDI code.
 *					Ack spit, Linus how did you allow that
 *					one in...
 *		Jes Sorensen	:	Make FDDI work again in 2.1.x and
 *					clean up the APFDDI & gen. FDDI bits.
 *		Alexey Kuznetsov:	new arp state machine;
 *					now it is in net/core/neighbour.c.
 *		Krzysztof Halasa:	Added Frame Relay ARP support.
 *		Arnaldo C. Melo :	convert /proc/net/arp to seq_file
 *		Shmulik Hen:		Split arp_send to arp_create and
 *					arp_xmit so intermediate drivers like
 *					bonding can change the skb before
 *					sending (e.g. insert 8021q tag).
 *		Harald Welte	:	convert to make use of jenkins hash
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/fddidevice.h>
#include <linux/if_arp.h>
#include <linux/trdevice.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/rcupdate.h>
#include <linux/jhash.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/ax25.h>
#include <net/netrom.h>
#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
#include <net/atmclip.h>
struct neigh_table *clip_tbl_hook;
#endif

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/netfilter_arp.h>

/*
 *	Interface to generic neighbour cache.
 */
static u32 arp_hash(const void *pkey, const struct net_device *dev);
static int arp_constructor(struct neighbour *neigh);
static void arp_solicit(struct neighbour *neigh, struct sk_buff *skb);
static void arp_error_report(struct neighbour *neigh, struct sk_buff *skb);
static void parp_redo(struct sk_buff *skb);

static const struct neigh_ops arp_generic_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_connected_output,
	.hh_output =		dev_queue_xmit,
	.queue_xmit =		dev_queue_xmit,
};

static const struct neigh_ops arp_hh_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_resolve_output,
	.hh_output =		dev_queue_xmit,
	.queue_xmit =		dev_queue_xmit,
};

static const struct neigh_ops arp_direct_ops = {
	.family =		AF_INET,
	.output =		dev_queue_xmit,
	.connected_output =	dev_queue_xmit,
	.hh_output =		dev_queue_xmit,
	.queue_xmit =		dev_queue_xmit,
};

const struct neigh_ops arp_broken_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_compat_output,
	.connected_output =	neigh_compat_output,
	.hh_output =		dev_queue_xmit,
	.queue_xmit =		dev_queue_xmit,
};

/*
 * ARPЭ���漰���Ĺؼ������������������̳�ʼ�������
 * ��ARP��ַ����Э����ھӱ�ṹ
 * ����:Ϊ��ȡip��ַ��mac��ַ�Ķ�Ӧ��ϵ��ʹ�õġ�
*/
struct neigh_table arp_tbl = {
	.family =	AF_INET,//��ַ��
	.entry_size =	sizeof(struct neighbour) + 4,//�ھӽṹ���ܳ���
	.key_len =	4,//IP��ַ�ĳ���
	.hash =		arp_hash,//��ϣ����ָ��
	.constructor =	arp_constructor,//�����ھӽṹ�ĺ���ָ��
	.proxy_redo =	parp_redo,//������ָ��
	.id =		"arp_cache",//Э��������ΪID
	.parms = {//�ھӲ����ṹ
		.tbl =			&arp_tbl,
		.base_reachable_time =	30 * HZ,
		.retrans_time =	1 * HZ,
		.gc_staletime =	60 * HZ,
		.reachable_time =		30 * HZ,
		.delay_probe_time =	5 * HZ,
		.queue_len =		3,
		.ucast_probes =	3,
		.mcast_probes =	3,
		.anycast_delay =	1 * HZ,
		.proxy_delay =		(8 * HZ) / 10,
		.proxy_qlen =		64,
		.locktime =		1 * HZ,
	},
	.gc_interval =	30 * HZ, //���ռ��ʱ��
	.gc_thresh1 =	128,//������С��ֵ
	.gc_thresh2 =	512,//�����е���ֵ
	.gc_thresh3 =	1024,//���������ֵ
};

int arp_mc_map(__be32 addr, u8 *haddr, struct net_device *dev, int dir)
{
	switch (dev->type) {
	case ARPHRD_ETHER:
	case ARPHRD_FDDI:
	case ARPHRD_IEEE802:
		ip_eth_mc_map(addr, haddr);
		return 0;
	case ARPHRD_IEEE802_TR:
		ip_tr_mc_map(addr, haddr);
		return 0;
	case ARPHRD_INFINIBAND:
		ip_ib_mc_map(addr, dev->broadcast, haddr);
		return 0;
	default:
		if (dir) {
			memcpy(haddr, dev->broadcast, dev->addr_len);
			return 0;
		}
	}
	return -EINVAL;
}


static u32 arp_hash(const void *pkey, const struct net_device *dev)
{
	return jhash_2words(*(u32 *)pkey, dev->ifindex, arp_tbl.hash_rnd);
}

/*
 * �˺�����ARP���ھӳ�ʼ��������������ʼ���µ�neighbour�ṹʵ�������ھӱ�������
 * neigh_create()�б�����
*/
static int arp_constructor(struct neighbour *neigh)
{
	__be32 addr = *(__be32*)neigh->primary_key;//ȡ�õ�ַ
	struct net_device *dev = neigh->dev;//ȡ�������豸
	struct in_device *in_dev;
	struct neigh_parms *parms;

	//����ھ���������豸��IP���ÿ��Ƿ���Ч�������Ч�����IP���ÿ��п�¡һ���ھ����ÿ���ھ��
	//�����ʼ��ʧ�ܣ����ش�����
	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);//ȡ���豸�����ýṹ
	if (in_dev == NULL) {//�ṹ�����ھ��˳���
		rcu_read_unlock();
		return -EINVAL;
	}

	//�����ھӵ�ַ��ȡ�ھӵ�����
	neigh->type = inet_addr_type(dev_net(dev), addr);

	parms = in_dev->arp_parms;//ȡ�����ýṹ���ھӲ���
	/*
	 * __neigh_parms_put �� neigh_parms_clone��Ϊ�������ǰ�߼��١����������ھӲ����ṹ��ʹ�ü�����
	 * ʵ���ϸ������ھӲ���ָ��
	*/
	__neigh_parms_put(neigh->parms);//�ݼ�ԭ���ھӲ�����ʹ�ü���
	neigh->parms = neigh_parms_clone(parms);//��IP���ÿ��п�¡һ���ھ����ÿ���ھ���
	rcu_read_unlock();

	/*�������֧��ARP�������ø��ھ����״̬ΪNUD_NOARP��ͬʱ��arp_direct_ops()��Ϊ�ھ�
	��ĺ���ָ�������ʼ���ھ��������ṹoutput
	*/
	if (!dev->header_ops) {//�Ƿ�װ����·�㺯��������������װ
		neigh->nud_state = NUD_NOARP;//����Ϊ����Ҫ����״̬
		neigh->ops = &arp_direct_ops;//��¼������
		neigh->output = neigh->ops->queue_xmit;//���÷��ͺ���
	} else {
		/* Good devices (checked by reading texts, but only Ethernet is
		   tested)

		   ARPHRD_ETHER: (ethernet, apfddi)
		   ARPHRD_FDDI: (fddi)
		   ARPHRD_IEEE802: (tr)
		   ARPHRD_METRICOM: (strip)
		   ARPHRD_ARCNET:
		   etc. etc. etc.

		   ARPHRD_IPDDP will also work, if author repairs it.
		   I did not it, because this driver does not work even
		   in old paradigm.
		 */

#if 1
		/* So... these "amateur" devices are hopeless.
		   The only thing, that I can say now:
		   It is very sad that we need to keep ugly obsolete
		   code to make them happy.

		   They should be moved to more reasonable state, now
		   they use rebuild_header INSTEAD OF hard_start_xmit!!!
		   Besides that, they are sort of out of date
		   (a lot of redundant clones/copies, useless in 2.1),
		   I wonder why people believe that they work.
		 */
		/*
		��ҪARP֧�ֵ������Ӳ���ӿ�����ΪROSE��AX.25��NETROM�����������ʹ��
		arp_broken_ops()��Ϊ�ھ���ĺ���ָ���
		*/
		switch (dev->type) {//�ж������豸����
		default:
			break;
		case ARPHRD_ROSE:
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
		case ARPHRD_AX25:
#if defined(CONFIG_NETROM) || defined(CONFIG_NETROM_MODULE)
		case ARPHRD_NETROM:
#endif
			neigh->ops = &arp_broken_ops;//��¼���������������Ϊneigh_compat_output()
			neigh->output = neigh->ops->output;//���÷��ͺ���
			return 0;
#endif
		;}
#endif/* ���������������ͣ�ҲҪ���neigh->type���ͣ��������ֵǰ������Ϊ·�������صĵ�ַ���� */
		/*����ھ����ַ���鲥���ͣ�Ҳ����ARP֧�֣�����arp_mc_map()�����鲥��ַ���ѻ�ȡ���鲥��ַ�洢��
		�ھ�����*/
		if (neigh->type == RTN_MULTICAST) {//�鲥����
			neigh->nud_state = NUD_NOARP;//����״̬
			arp_mc_map(addr, neigh->ha, dev, 1);//����MAC��ַ
		} else if (dev->flags&(IFF_NOARP|IFF_LOOPBACK)) {//�ؽ��豸
			neigh->nud_state = NUD_NOARP;//����Ϊ����Ҫ����״̬
			memcpy(neigh->ha, dev->dev_addr, dev->addr_len);//�Ӹ������豸�л�ȡӲ����ַ�洢���ھ�����
		} else if (neigh->type == RTN_BROADCAST || dev->flags&IFF_POINTOPOINT) {//����ǹ㲥���ͻ��ߵ�Ե�����
			neigh->nud_state = NUD_NOARP;//����Ϊ����Ҫ����״̬
			memcpy(neigh->ha, dev->broadcast, dev->addr_len);//���ƹ㲥��ַ��ΪӲ����ַ�洢���ھ�����
		}

		if (dev->header_ops->cache)//�Ƿ��ṩ�˻��庯������������������װ
			neigh->ops = &arp_hh_ops;//��¼������
		else
			neigh->ops = &arp_generic_ops;

		if (neigh->nud_state&NUD_VALID)//��Ч״̬
			neigh->output = neigh->ops->connected_output;//���÷��ͺ���
		else
			neigh->output = neigh->ops->output;//ʹ�ú�����ķ��ͺ���
	}
	return 0;
}

/* arp_error_report()����dst_link_failure()�����㱨�����������ʼ����arp_direct_ops֮��
������neigh_ops�ṹʵ����error_report����ָ�롣���ھ�����л�������δ���͵ı��ģ������ھ�
ȴ�޷�����ʱ������*/
static void arp_error_report(struct neighbour *neigh, struct sk_buff *skb)
{
	dst_link_failure(skb);
	kfree_skb(skb);
}

/*
 * �˺�����������ݰ���Դ��ַ����������ARP��������·������:
 * neigh_timer_handler()->arp_solicit()->arp_send()->arp_xmit()->dev_queue_xmit()��
 * �˺�������Ҫ�����ǻ�ȡԴ��ַ�����ص�ַ��Ȼ�����arp_send()����������������ARP��
 * neigh---�����Ŀ���ھ���
 * skb---�����ڸ��ھ����еĴ����ͱ��ģ�������ȡ��skb��ԴIP��ַ
*/
static void arp_solicit(struct neighbour *neigh, struct sk_buff *skb)
{
	__be32 saddr = 0;
	u8  *dst_ha = NULL;
	struct net_device *dev = neigh->dev;//��ȡ�����豸�ṹ
	__be32 target = *(__be32*)neigh->primary_key;//��ȡ���ص�ַ
	int probes = atomic_read(&neigh->probes);//��ȡʧ�ܼ���
	struct in_device *in_dev = in_dev_get(dev);//��ȡ�豸���ýṹ

	//����ھ��������豸��IP���ÿ��Ƿ���Ч
	if (!in_dev)
		return;
	//����arp_announceϵͳ������ѡ��IP��ַ(����0��1)
	//announce�����������arp����ʱ����IP���ݰ���ȷ��Դ��IP��ַ�Ĺ���
	switch (IN_DEV_ARP_ANNOUNCE(in_dev)) {
	default:
	case 0:		/* By default announce any local IP Ĭ������»ᷢ���κα���IP */
		if (skb && inet_addr_type(dev_net(dev), ip_hdr(skb)->saddr) == RTN_LOCAL)
			saddr = ip_hdr(skb)->saddr;//��ȡIPͷ���е�Դ��ַ
		break;
	case 1:		/* Restrict announcements of saddr in same subnet ����saddr��ͬһ�����еĹ��� */
		if (!skb)
			break;
		saddr = ip_hdr(skb)->saddr;
		if (inet_addr_type(dev_net(dev), saddr) == RTN_LOCAL) {
			/* saddr should be known to target Ӧ��֪��saddr��Ŀ�� */
			if (inet_addr_onlink(in_dev, target, saddr))
				break;
		}
		saddr = 0;
		break;
	case 2:		/* Avoid secondary IPs, get a primary/preferred one */
		break;
	}

	if (in_dev)
		in_dev_put(in_dev);//�ݼ��豸���ýṹʹ�ü���
	if (!saddr)//���û��ָ��Դ��ַ
		saddr = inet_select_addr(dev, target, RT_SCOPE_LINK);//����arp_announceϵͳ������ѡ��ԴIP��ַ

	//���ARP�������ش������Ƿ�ﵽ���ޣ�����ǣ���ֹͣ����
	if ((probes -= neigh->parms->ucast_probes) < 0) {//����ھӲ�����̽��ֵ
		if (!(neigh->nud_state&NUD_VALID))//����ھӽṹ������Ч״̬
			printk(KERN_DEBUG "trying to ucast probe in NUD_INVALID\n");
		dst_ha = neigh->ha;//��ȡ�ھӽṹ��MAC��ַ��ΪĿ��MAC��ַ
		read_lock_bh(&neigh->lock);
	} else if ((probes -= neigh->parms->app_probes) < 0) {
#ifdef CONFIG_ARPD
		neigh_app_ns(neigh);
#endif
		return;
	}

	//���õ���Ӳ��Դ��Ŀ���ַ��IPԴ��Ŀ���ַ����Ϊ����������arp_send()����һ��ARP���Ľ��������
	arp_send(ARPOP_REQUEST, ETH_P_ARP, target, dev, saddr,
		 dst_ha, dev->dev_addr, NULL);//����������ARP��
	if (dst_ha)
		read_unlock_bh(&neigh->lock);
}

/*
 �˺����������ݹ��˹�������ARP�����е�Դ��Ŀ��IP��ַ����ȷ�ϣ�����ֵ��0Ҫ���ˡ�
 ���������ȸ��ݹ����ȡsip��scope��Ȼ����������Ϊ��������inet_confirm_addr()��Դ��Ŀ��
 IP��ַ����ȷ�ϡ�
 ����:
 in_dev,����ARP�����������豸��IP���ƿ�
 sip,���ͷ�IP��ַ
 tip,ARP�����ĵ�Ŀ��IP��ַ
*/
static int arp_ignore(struct in_device *in_dev, __be32 sip, __be32 tip)
{
	int scope;

	//��ȡϵͳ���õĹ��˹��򣬸��ݹ�������Ӧ����
	switch (IN_DEV_ARP_IGNORE(in_dev)) {
	case 0:	/* Reply, the tip is already validated */
		return 0;
	case 1:	/* Reply only if tip is configured on the incoming interface */
		sip = 0;
		scope = RT_SCOPE_HOST;
		break;
	case 2:	/*
		 * Reply only if tip is configured on the incoming interface
		 * and is in same subnet as sip
		 */
		scope = RT_SCOPE_HOST;
		break;
	case 3:	/* Do not reply for scope host addresses */
		sip = 0;
		scope = RT_SCOPE_LINK;
		break;
	case 4:	/* Reserved */
	case 5:
	case 6:
	case 7:
		return 0;
	case 8:	/* Do not reply */
		return 1;
	default:
		return 0;
	}
	return !inet_confirm_addr(in_dev, sip, tip, scope);
}

/*
 arp_filter()����ARP�������еķ��ͷ�IP��ַ��Ŀ����IP��ַ�����������ARP�����ķ��ͷ���·�ɣ�
 ���˵���Щ����·��ʧ�ܣ����ǲ��ҵ���·������豸������ARP�����ĵ��豸��ͬ��ARP������
*/
static int arp_filter(__be32 sip, __be32 tip, struct net_device *dev)
{
	struct flowi fl = { .nl_u = { .ip4_u = { .daddr = sip,
						 .saddr = tip } } };
	struct rtable *rt;
	int flag = 0;
	/*unsigned long now; */
	struct net *net = dev_net(dev);

	if (ip_route_output_key(net, &rt, &fl) < 0)
		return 1;
	if (rt->u.dst.dev != dev) {
		NET_INC_STATS_BH(net, LINUX_MIB_ARPFILTER);
		flag = 1;
	}
	ip_rt_put(rt);
	return flag;
}

/* OBSOLETE FUNCTIONS */

/*
 *	Find an arp mapping in the cache. If not found, post a request.
 *
 *	It is very UGLY routine: it DOES NOT use skb->dst->neighbour,
 *	even if it exists. It is supposed that skb->dev was mangled
 *	by a virtual device (eql, shaper). Nobody but broken devices
 *	is allowed to use this function, it is scheduled to be removed. --ANK
 */

static int arp_set_predefined(int addr_hint, unsigned char * haddr, __be32 paddr, struct net_device * dev)
{
	switch (addr_hint) {
	case RTN_LOCAL:
		printk(KERN_DEBUG "ARP: arp called for own IP address\n");
		memcpy(haddr, dev->dev_addr, dev->addr_len);
		return 1;
	case RTN_MULTICAST:
		arp_mc_map(paddr, haddr, dev, 1);
		return 1;
	case RTN_BROADCAST:
		memcpy(haddr, dev->broadcast, dev->addr_len);
		return 1;
	}
	return 0;
}


int arp_find(unsigned char *haddr, struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	__be32 paddr;
	struct neighbour *n;

	if (!skb_dst(skb)) {
		printk(KERN_DEBUG "arp_find is called with dst==NULL\n");
		kfree_skb(skb);
		return 1;
	}

	paddr = skb_rtable(skb)->rt_gateway;

	if (arp_set_predefined(inet_addr_type(dev_net(dev), paddr), haddr, paddr, dev))
		return 0;

	n = __neigh_lookup(&arp_tbl, &paddr, dev, 1);

	if (n) {
		n->used = jiffies;
		if (n->nud_state&NUD_VALID || neigh_event_send(n, skb) == 0) {
			read_lock_bh(&n->lock);
			memcpy(haddr, n->ha, dev->addr_len);
			read_unlock_bh(&n->lock);
			neigh_release(n);
			return 0;
		}
		neigh_release(n);
	} else
		kfree_skb(skb);
	return 1;
}

/* END OF OBSOLETE FUNCTIONS */
/*
 * �ڴ���·�ɱ�rt_intern_hash()�����У����½���·��������ھӽṹ����ʱ���õ�arp_bind_neighbour()��������ɡ�
 * �ȼ���ھӽṹ�Ƿ���ڣ���������ھ�Ҫ����__neigh_lookup_errno()���ң�����ҵ����ھӽṹ�ͼ�¼��·������
*/
int arp_bind_neighbour(struct dst_entry *dst)
{
	struct net_device *dev = dst->dev;//ȡ�������豸�ṹָ��
	struct neighbour *n = dst->neighbour;//ȡ��·�����е��ھӽṹָ��

	if (dev == NULL)//�����豸����Ϊ��
		return -EINVAL;
	if (n == NULL) {/*���·�ɻ���û�а��ھӱ���*/
		__be32 nexthop = ((struct rtable *)dst)->rt_gateway;/*ȡ����һ��ip��ַ����·������*/
		if (dev->flags&(IFF_LOOPBACK|IFF_POINTOPOINT))//����豸֧�ֻؽӺ͵�Ե�
			nexthop = 0;//���ȡֵ
		n = __neigh_lookup_errno(
#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
		    dev->type == ARPHRD_ATM ? clip_tbl_hook :
#endif
		    &arp_tbl, &nexthop, dev);//���Ҳ�������һ��ip��Ӧ���ھӱ����һ���������ھӱ�ṹ���ڶ���������·�����ص�ַ�������������������豸
		if (IS_ERR(n))
			return PTR_ERR(n);
		dst->neighbour = n;//����һ�����ھӱ����Ŀ�ĵ�ַ��·�ɻ����
	}
	return 0;
}

/*
 * Check if we can use proxy ARP for this path
 */

static inline int arp_fwd_proxy(struct in_device *in_dev, struct rtable *rt)
{
	struct in_device *out_dev;
	int imi, omi = -1;

	if (!IN_DEV_PROXY_ARP(in_dev))
		return 0;

	if ((imi = IN_DEV_MEDIUM_ID(in_dev)) == 0)
		return 1;
	if (imi == -1)
		return 0;

	/* place to check for proxy_arp for routes */

	if ((out_dev = in_dev_get(rt->u.dst.dev)) != NULL) {
		omi = IN_DEV_MEDIUM_ID(out_dev);
		in_dev_put(out_dev);
	}
	return (omi != imi && omi != -1);
}

/*
 *	Interface to link layer: send routine and receive handler.
 */

/*
 *	Create an arp packet. If (dest_hw == NULL), we create a broadcast
 *	message. ��������һ��������ARP���Ͷ��㱨��
 *	����:
 	type �� ��ARPЭ��Ĳ����룬��ARPOP_REPLY��ARPOP_REQUEST��
 	ptype������Э�����ͣ�����̫����ARPЭ�����ͱ���ΪETH_P_ARP(0x0806)
 	dest_ip src_ip ���ARP���ĵ�Ŀ����IP��ַ�ͷ��ͷ�IP��ַ����䵽ARP�����С�
 	dev ���ARP���ĵ������豸
 	dest_hw,target_hw�����ARP���ĵ�Ŀ��Ӳ����ַ��dest_hw��䵽����֡�ײ�
 	src_hw,src_hwλ���ARP���ĵ�ԴӲ����ַ����䵽��̫��֡�ײ���ARP���ġ�
 */
struct sk_buff *arp_create(int type, int ptype, __be32 dest_ip,
			   struct net_device *dev, __be32 src_ip,
			   const unsigned char *dest_hw,
			   const unsigned char *src_hw,
			   const unsigned char *target_hw)
{
	struct sk_buff *skb;
	struct arphdr *arp;//ARPͷ���ṹָ��
	unsigned char *arp_ptr;

	/*
	 *	Allocate a buffer
	 */
    // �������ݰ��ṹ�ռ䣬���仺��飬�䳤�Ȱ���ARPͷ�����Ⱥ���̫��ͷ������
	skb = alloc_skb(arp_hdr_len(dev) + LL_ALLOCATED_SPACE(dev), GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	skb_reserve(skb, LL_RESERVED_SPACE(dev));//�ڻ�����п������ݿ�ռ�
	skb_reset_network_header(skb);//���������ͷ��ָ��
	arp = (struct arphdr *) skb_put(skb, arp_hdr_len(dev));//ָ�����ݿ��е�ARPͷ��
	skb->dev = dev; //��¼�豸�ṹ
	skb->protocol = htons(ETH_P_ARP);//��¼Э������
	if (src_hw == NULL)//���û��ָ��ԴӲ����ַ
		src_hw = dev->dev_addr;//��¼�豸��MAC��ַ
	if (dest_hw == NULL)//���û��ָ��Ŀ��Ӳ����ַ
		dest_hw = dev->broadcast;//��¼�豸�Ĺ㲥��ַ

	/*
	 *	Fill the device header for the ARP frame
	 */
	 //����eth_header_ops�ṹ�е�create()��������eth_header()
	if (dev_hard_header(skb, dev, ptype, dest_hw, src_hw, skb->len) < 0)
		goto out;

	/*
	 * Fill out the arp protocol part.
	 *
	 * The arp hardware type should match the device type, except for FDDI,
	 * which (according to RFC 1390) should always equal 1 (Ethernet).
	 */
	/*
	 *	Exceptions everywhere. AX.25 uses the AX.25 PID value not the
	 *	DIX code for the protocol. Make these device structure fields.
	 */
	switch (dev->type) {
	default:
		arp->ar_hrd = htons(dev->type);//��¼Ӳ������
		arp->ar_pro = htons(ETH_P_IP);//��¼Э������
		break;

#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
	case ARPHRD_AX25:
		arp->ar_hrd = htons(ARPHRD_AX25);
		arp->ar_pro = htons(AX25_P_IP);
		break;

#if defined(CONFIG_NETROM) || defined(CONFIG_NETROM_MODULE)
	case ARPHRD_NETROM:
		arp->ar_hrd = htons(ARPHRD_NETROM);
		arp->ar_pro = htons(AX25_P_IP);
		break;
#endif
#endif

#ifdef CONFIG_FDDI
	case ARPHRD_FDDI:
		arp->ar_hrd = htons(ARPHRD_ETHER);
		arp->ar_pro = htons(ETH_P_IP);
		break;
#endif
#ifdef CONFIG_TR
	case ARPHRD_IEEE802_TR:
		arp->ar_hrd = htons(ARPHRD_IEEE802);
		arp->ar_pro = htons(ETH_P_IP);
		break;
#endif
	}

	arp->ar_hln = dev->addr_len;//��¼�豸�ĵ�ַ����
	arp->ar_pln = 4;//��¼�豸��ַ���ֽ���
	arp->ar_op = htons(type);//��¼����ֵ

	arp_ptr=(unsigned char *)(arp+1);//���ݿ������ڱ���Դ��ַ��

	memcpy(arp_ptr, src_hw, dev->addr_len);//��ֵԴMAC��ַ
	arp_ptr += dev->addr_len;//���ݿ������ڱ���IP��ַ��
	memcpy(arp_ptr, &src_ip, 4);//����ԴIP��ַ
	arp_ptr += 4;//���ݿ������ڱ���Ŀ���ַ��
	if (target_hw != NULL)
		memcpy(arp_ptr, target_hw, dev->addr_len);//����Ŀ��MAC��ַ
	else
		memset(arp_ptr, 0, dev->addr_len);
	arp_ptr += dev->addr_len;//���ݿ������ڱ���Ŀ��IP��ַ��
	memcpy(arp_ptr, &dest_ip, 4);//��ֵĿ��IP��ַ(һ�������ص�ַ)

	return skb;//���ش��������ݰ�

out:
	kfree_skb(skb);
	return NULL;
}

/*
 *	Send an arp packet.
 */
void arp_xmit(struct sk_buff *skb)
{
	/* Send it off, maybe filter it using firewalling first.  */
	NF_HOOK(NFPROTO_ARP, NF_ARP_OUT, skb, NULL, skb->dev, dev_queue_xmit);//������õ���dev_aueue_xmit()�����������ݰ�
}

/*
 *	Create and send an arp packet.���arp��ͷ�ͷ������,������arp_xmit�����������arp����
    ������arp_create()������ͬ
 */
void arp_send(int type, int ptype, __be32 dest_ip,
	      struct net_device *dev, __be32 src_ip,
	      const unsigned char *dest_hw, const unsigned char *src_hw,
	      const unsigned char *target_hw)
{
	struct sk_buff *skb;

	/*
	 *	No arp on this interface.
	 */

	if (dev->flags&IFF_NOARP)//����豸�Ƿ�֧��ARPЭ�飬���ޣ�����Ҫ����ARP����ֱ�ӷ���
		return;

	skb = arp_create(type, ptype, dest_ip, dev, src_ip,
			 dest_hw, src_hw, target_hw);//����ARP��
	if (skb == NULL) {//����ʧ�ܷ���
		return;
	}
	
	/*��������ɹ������ٵ���arp_xmit()���䷢�ͳ�ȥ��arp_xmit()ͨ��NF_HOOK��װ��dev_queue_xmit()
	��netfilter����֮�����dev_queue_xmit()������ġ�
	*/
	arp_xmit(skb);//����arp����
}

/*
 *	Process an arp request.ARPӦ����,��ARP��������
 */
static int arp_process(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;//��ȡ�����豸�ṹ
	struct in_device *in_dev = in_dev_get(dev);//��ȡ�豸���ýṹ
	struct arphdr *arp;
	unsigned char *arp_ptr;
	struct rtable *rt;
	unsigned char *sha;
	__be32 sip, tip;
	u16 dev_type = dev->type;//��ȡ�豸����
	int addr_type;
	struct neighbour *n;
	struct net *net = dev_net(dev);//��ȡ����ռ�ṹ

	/* arp_rcv below verifies the ARP header and verifies the device
	 * is ARP'able.
	 */

	if (in_dev == NULL)//���ýṹ����Ϊ��
		goto out;

	arp = arp_hdr(skb);//��ȡARP�ṹͷ��

	switch (dev_type) {
	default:
		if (arp->ar_pro != htons(ETH_P_IP) ||
		    htons(dev_type) != arp->ar_hrd)
			goto out;
		break;
	case ARPHRD_ETHER:
	case ARPHRD_IEEE802_TR:
	case ARPHRD_FDDI:
	case ARPHRD_IEEE802:
		/*
		 * ETHERNET, Token Ring and Fibre Channel (which are IEEE 802
		 * devices, according to RFC 2625) devices will accept ARP
		 * hardware types of either 1 (Ethernet) or 6 (IEEE 802.2).
		 * This is the case also of FDDI, where the RFC 1390 says that
		 * FDDI devices should accept ARP hardware of (1) Ethernet,
		 * however, to be more robust, we'll accept both 1 (Ethernet)
		 * or 6 (IEEE 802.2)
		 */
		if ((arp->ar_hrd != htons(ARPHRD_ETHER) &&
		     arp->ar_hrd != htons(ARPHRD_IEEE802)) ||
		    arp->ar_pro != htons(ETH_P_IP))
			goto out;
		break;
	case ARPHRD_AX25:
		if (arp->ar_pro != htons(AX25_P_IP) ||
		    arp->ar_hrd != htons(ARPHRD_AX25))
			goto out;
		break;
	case ARPHRD_NETROM:
		if (arp->ar_pro != htons(AX25_P_IP) ||
		    arp->ar_hrd != htons(ARPHRD_NETROM))
			goto out;
		break;
	}

	/* Understand only these message types */
	/* Ŀ��ARP���մ���ֻ֧��ARP�����ARP��Ӧ���������͵�ARP���ľ����� */
	if (arp->ar_op != htons(ARPOP_REPLY) &&
	    arp->ar_op != htons(ARPOP_REQUEST))
		goto out;

/*
 *	Extract fields
 ��ȡARP�����з��ͷ�Ӳ����ַ(sha)�����ͷ�IP��ַ(sip)��Ŀ��Ӳ����ַ(tha)��Ŀ����IP��ַ(tip)��
 ����Ŀ��IP��ַΪ���ص�ַ��ಥ��ַ�ı���
 */
	arp_ptr= (unsigned char *)(arp+1);//ָ�����ݿ��е�ԴMAC��ַ��
	sha	= arp_ptr;//��ȡ�ͻ���MAC��ַ
	arp_ptr += dev->addr_len;//ָ�����ݿ��е�ԴIP��ַ��
	memcpy(&sip, arp_ptr, 4);//��ȡ�ͻ��˵�IP��ַ
	arp_ptr += 4;//ָ��Ŀ��MAC��ַ��
	arp_ptr += dev->addr_len;//ָ��Ŀ��IP��ַ
	memcpy(&tip, arp_ptr, 4);//��ȡĿ��IP��ַ
/*
 *	Check for bad requests for 127.x.x.x and requests for multicast
 *	addresses.  If this is one such, delete it.
 *  ���127.x.x.x�Ĳ�������Ͷಥ��ַ������.����������ģ�ɾ����
 *  ARP�����ѯ��·��ַ���鲥��ַ����Ϊ����ûӴ��Ӧ��mac��ַ����������������ַ��ֱ���˳�
 */
	if (ipv4_is_loopback(tip) || ipv4_is_multicast(tip))
		goto out;

/*
 *     Special case: We must set Frame Relay source Q.922 address
 *     ������������Ǳ�������֡�м�ԴQ.922��ַ
       ���Ӳ������ΪQ.922���ͷ�Ӳ����ַ����ARPӦ���ĵ�Ŀ��Ӳ����ַ������Ϊ�����豸�Ĺ㲥��ַ��
 */
	if (dev_type == ARPHRD_DLCI)
		sha = dev->broadcast;

/*
 *  Process entry.  The idea here is we want to send a reply if it is a
 *  request for us or if it is a request for someone else that we hold
 *  a proxy for.  We want to add an entry to our cache if it is a reply
 *  to us or if it is a request for our address.
 *  (The assumption for this last is that if someone is requesting our
 *  address, they are probably intending to talk to us, so it saves time
 *  if we cache their address.  Their address is also probably not in
 *  our cache, since ours is not in their cache.)
 *
 *  Putting this another way, we only care about replies if they are to
 *  us, in which case we add them to the cache.  For requests, we care
 *  about those for us and those for our proxies.  We reply to both,
 *  and in the case of requests for us we add the requester to the arp
 *  cache.
 */
 /*
 �������롣 ������뷨�ǣ�����Ƕ����ǵ����󣬻�����Ҫ�����ǳ��д����˵���������ϣ�����ͻظ��� 
 ����Ƕ����ǵĻظ������������ǵĵ�ַ��������ϣ���ڻ��������һ����Ŀ�� 
 �����ļ����ǣ�������������������ǵĵ�ַ�����ǿ�����������ǽ�̸������������ǻ������ǵĵ�ַ��
 �����Խ�ʡʱ�䣬���ǵĵ�ַҲ���ܲ������ǵĻ����У���Ϊ���ǵ� ���档�����仰˵������ֻ���Ļظ���
 ������Ƕ����ǣ�����������£����ǽ�������ӵ����档 �����������ǹ�����ЩΪ���Ǻ����ǵĴ����ˡ�
 ���ǻظ����ߣ������������£����ǽ���������ӵ�arp���档
*/

	/* Special case: IPv4 duplicate address detection packet (RFC2131) ���������IPv4�ظ���ַ��ⱨ�ģ�RFC2131��
     * ����յ������ظ���ַ��ⱨ�ģ����ұ���ռ���˼���˵�ַ�������arp_send������Ӧ������
     * �ظ���ַ��ⱨ��(ARP������ԴIPΪȫ0)���������е��ھӱ�����Ϣ��ûͨ����⣬��ʱ��������Ȼû�����壬
     * Ҳ����һ�̾������������������Ƿ�������ظ���ַ��ⱨ���е���Ϣ��������ھӱ��С�
     ��������ĵ�ԴIP��ַΪ0�����ARP�������������IPV4��ַ��ͻ(RFC2131)�������ȷ�������ĵ�Ŀ��IP
     ��ַΪ����IP��ַ���Ը�IP��ַΪԴ��ַ��Ŀ���ַ����ARPӦ���ġ�
    */
	if (sip == 0) {
		if (arp->ar_op == htons(ARPOP_REQUEST) &&
		    inet_addr_type(net, tip) == RTN_LOCAL &&
		    !arp_ignore(in_dev, sip, tip))
			arp_send(ARPOP_REPLY, ETH_P_ARP, sip, dev, tip, sha,
				 dev->dev_addr, sha);
		goto out;
	}

	//����Ҫ����ĵ�ַ�������ģ�����Ҫ�����ĵ�ַ��·�ɱ��д���
	if (arp->ar_op == htons(ARPOP_REQUEST) &&//�����arp����
	    ip_route_input(skb, tip, sip, 0, dev) == 0) {//���һ��ߴ���Ŀ���ַ��·�ɱ�

		rt = skb_rtable(skb);//��ȡ·�ɱ�
		addr_type = rt->rt_type;//��ȡ��ַ����

		/* �����͸�������ARP�����ģ����ȵ���neigh_event_ns()���¶��ڵ��ھ��
		Ȼ�����ϵͳ�����������Ƿ���˺Ͷ���ARP���ģ�������û�б����˻�����������ARPӦ����
		*/
		if (addr_type == RTN_LOCAL) {//����Ǳ���·������
			int dont_send = 0;

			if (!dont_send)
				dont_send |= arp_ignore(in_dev,sip,tip);//�Ƿ����ARPӦ��
			if (!dont_send && IN_DEV_ARPFILTER(in_dev))
				dont_send |= arp_filter(sip,tip,dev);//�Ƿ����ARPӦ��
			if (!dont_send) {//�˺����Ĺ�������arp_tbl�в����Ƿ��Ѱ����жԷ������ĵ�ַ��Ϣ����û�У����½���Ȼ�����neigh_update������״̬
				n = neigh_event_ns(&arp_tbl, sha, &sip, dev);
				if (n) {
					arp_send(ARPOP_REPLY,ETH_P_ARP,sip,dev,tip,sha,dev->dev_addr,sha);//����ARPӦ����ͻ���(�ھ���)
					neigh_release(n);//�ݼ��ھӽṹʹ�ü���
				}
			}
			goto out;
		} else if (IN_DEV_FORWARD(in_dev)) {//���ڲ��Ƿ��͸�������ARP�����ģ�����ϵͳ����ȷ���Ƿ����ARP����
			    if (addr_type == RTN_UNICAST  && rt->u.dst.dev != dev &&
			     (arp_fwd_proxy(in_dev, rt) || pneigh_lookup(&arp_tbl, net, &tip, dev, 0))) {
			     /*
			     	 ���䣺neigh_event_ns()��neigh_release()����ʹ�ò������������ֱ��ͷţ�
			     	 neigh���ͷŵ�������neigh->refcnt==0����neigh����ʱ��refcnt=1��
			     	 ��neigh_event_ns��ʹrefcnt+1��neigh_release��ʹ-1����ʱrefcnt��ֵ����1��
			     	 ֻ�е��´ε�������neigh_releaseʱ�Żᱻ�ͷš�
				 */
				n = neigh_event_ns(&arp_tbl, sha, &sip, dev);//����ѧϰ
				if (n)
					neigh_release(n);

				if (NEIGH_CB(skb)->flags & LOCALLY_ENQUEUED ||
				    skb->pkt_type == PACKET_HOST ||
				    in_dev->arp_parms->proxy_delay == 0) {
					arp_send(ARPOP_REPLY,ETH_P_ARP,sip,dev,tip,sha,dev->dev_addr,sha);
				} else {
					pneigh_enqueue(&arp_tbl, in_dev->arp_parms, skb);
					in_dev_put(in_dev);
					return 0;
				}
				goto out;
			}
		}
	}

	/* Update our ARP tables */
	/*����ARPӦ���ҳ���Ӧ���ھӱ�����û���򴴽�*/
	n = __neigh_lookup(&arp_tbl, &sip, dev, 0);

	if (IPV4_DEVCONF_ALL(dev_net(dev), ARP_ACCEPT)) {
		/* Unsolicited ARP is not accepted by default.
		   It is possible, that this option should be enabled for some
		   devices (strip is candidate)
		 */
		if (n == NULL &&
		    arp->ar_op == htons(ARPOP_REPLY) &&
		    inet_addr_type(net, sip) == RTN_UNICAST)
			n = __neigh_lookup(&arp_tbl, &sip, dev, 1);
	}

	if (n) {
		int state = NUD_REACHABLE;/*�ھӱ��������ΪNUD_REACHABLE ״̬*/
		int override;

		/* If several different ARP replies follows back-to-back,
		   use the FIRST one. It is possible, if several proxy
		   agents are active. Taking the first reply prevents
		   arp trashing and chooses the fastest router.
		   ���������ͬ��ARP�ظ����汳��������ʹ�õ�һ���� ���������������ڻ״̬��
		   ���ǿ��ܵġ� ��ȡ��һ���ظ��ɷ�ֹarp trashing��ѡ������·������
		 */
		override = time_after(jiffies, n->updated + n->parms->locktime);

		/* Broadcast replies and request packets
		   do not assert neighbour reachability.
		   �㲥�ظ��������Ĳ��������ھӿɴ��ԡ�
		 */
		if (arp->ar_op != htons(ARPOP_REPLY) ||//���ARP������Ӧ������
		    skb->pkt_type != PACKET_HOST)//�������ݰ������ڱ�������
			state = NUD_STALE;//����Ϊ����״̬
		/*�����ھӱ�״̬*///neigh_update()��������ָ�����ھ������������Ӳ����ַ��״̬�������ַ��������������д����ھӱ���ģ���
		//���ͨ���˺��������ھӽṹΪ�ɵ���״̬�������¼�¼�ķ�����MAC��ַ������ǰ����뵽�����е����ݰ���
		//��һ���������ҵ����ھӽṹ���ڶ���������������MAC��ַ�������������ǿɵ���״̬��־�����ĸ��������ǹ��ڱ�־��
		neigh_update(n, sha, state, override ? NEIGH_UPDATE_F_OVERRIDE : 0);
		neigh_release(n);//�ݼ��ھӽṹʹ�ü���
	}

out:
	if (in_dev)
		in_dev_put(in_dev);//�ݼ����ýṹʹ�ü���
	consume_skb(skb);//�ͷ����ݰ�
	return 0;
}

static void parp_redo(struct sk_buff *skb)
{
	arp_process(skb);
}


/*
 *	Receive an arp request from the device layer.����������Ҫ��arp���
    �˺��������Ӷ�����ղ�����һ��ARP���ġ�
    ����˵��:
    skb,ARP���ĵ�SKB��
    dev,����ARP���ĵ������豸��������orig_dev����ͬһ���豸
    pt��packet_type�ṹʵ������ARPЭ����˵��arp_packet_type�������ж�����ARPЭ��
        ���պ���Ϊarp_rcv().�ò���arp_rcv()�в�δʹ�á�
    orig_dev,���յ�ARP���ĵ�ԭʼ�����豸��arp_rcv()��δʹ�á�
 */

static int arp_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt, struct net_device *orig_dev)
{
	struct arphdr *arp;

	/* ARP header, plus 2 device addresses, plus 2 IP addresses.  
	���ARP���ĵ�������:�䳤���Ƿ����һ��ARPͷ�����ȣ�������Ӳ����ַ���ȣ��ټ�����IP��ַ����
	*/
	if (!pskb_may_pull(skb, arp_hdr_len(dev)))//��顢�������ݰ�ͷ���ṹ
		goto freeskb;

	/*��ⱨ�ĺ������豸�ı�־��ARP���ĵ�Ӳ����ַ�����������豸��Ӳ����ַ�����Ƿ�ƥ�䣻����
	�豸�Ƿ�֧��ARPЭ�飻ARP�����Ƿ���ת���İ���ARP�����Ƿ����Իػ��ӿڵȡ�
	*/
	arp = arp_hdr(skb);//��ȡARPͷ���ṹ
	if (arp->ar_hln != dev->addr_len ||//�Ա��豸��ַ����
	    dev->flags & IFF_NOARP ||//�豸�Ƿ�֧��ARPЭ��
	    skb->pkt_type == PACKET_OTHERHOST ||//�Ƿ�Ϊ�����������������ݰ�
	    skb->pkt_type == PACKET_LOOPBACK ||//�Ƿ�Ϊ�ؽ�����
	    arp->ar_pln != 4)//����ַ�ֽ���
		goto freeskb;

	//����ܷ������ݰ��ṹ������ܹ�����Ļ���ͨ��skb_clone()��¡һ���µ����ݰ��ṹ����
	//����ʹ������µ����ݰ��ṹ
	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
		goto out_of_mem;

	memset(NEIGH_CB(skb), 0, sizeof(struct neighbour_cb));//���������Ϣ

	//�����ȶ�ARPͷ�����м�飬ȷ�������ͨ��netfiter����֮��ת��arp_process()�д���
	return NF_HOOK(NFPROTO_ARP, NF_ARP_IN, skb, dev, NULL, arp_process);

freeskb:
	kfree_skb(skb);
out_of_mem:
	return 0;
}

/*
 *	User level interface (ioctl)
 */

/*
 *	Set (create) an ARP cache entry.
 */

static int arp_req_set_proxy(struct net *net, struct net_device *dev, int on)
{
	if (dev == NULL) {
		IPV4_DEVCONF_ALL(net, PROXY_ARP) = on;
		return 0;
	}
	if (__in_dev_get_rtnl(dev)) {
		IN_DEV_CONF_SET(__in_dev_get_rtnl(dev), PROXY_ARP, on);
		return 0;
	}
	return -ENXIO;
}

static int arp_req_set_public(struct net *net, struct arpreq *r,
		struct net_device *dev)
{
	__be32 ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;
	__be32 mask = ((struct sockaddr_in *)&r->arp_netmask)->sin_addr.s_addr;

	if (mask && mask != htonl(0xFFFFFFFF))
		return -EINVAL;
	if (!dev && (r->arp_flags & ATF_COM)) {
		dev = dev_getbyhwaddr(net, r->arp_ha.sa_family,
				r->arp_ha.sa_data);
		if (!dev)
			return -ENODEV;
	}
	if (mask) {
		if (pneigh_lookup(&arp_tbl, net, &ip, dev, 1) == NULL)
			return -ENOBUFS;
		return 0;
	}

	return arp_req_set_proxy(net, dev, 1);
}

static int arp_req_set(struct net *net, struct arpreq *r,
		struct net_device * dev)
{
	__be32 ip;
	struct neighbour *neigh;
	int err;

	if (r->arp_flags & ATF_PUBL)
		return arp_req_set_public(net, r, dev);

	ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;
	if (r->arp_flags & ATF_PERM)
		r->arp_flags |= ATF_COM;
	if (dev == NULL) {
		struct flowi fl = { .nl_u = { .ip4_u = { .daddr = ip,
							 .tos = RTO_ONLINK } } };
		struct rtable * rt;
		if ((err = ip_route_output_key(net, &rt, &fl)) != 0)
			return err;
		dev = rt->u.dst.dev;
		ip_rt_put(rt);
		if (!dev)
			return -EINVAL;
	}
	switch (dev->type) {
#ifdef CONFIG_FDDI
	case ARPHRD_FDDI:
		/*
		 * According to RFC 1390, FDDI devices should accept ARP
		 * hardware types of 1 (Ethernet).  However, to be more
		 * robust, we'll accept hardware types of either 1 (Ethernet)
		 * or 6 (IEEE 802.2).
		 */
		if (r->arp_ha.sa_family != ARPHRD_FDDI &&
		    r->arp_ha.sa_family != ARPHRD_ETHER &&
		    r->arp_ha.sa_family != ARPHRD_IEEE802)
			return -EINVAL;
		break;
#endif
	default:
		if (r->arp_ha.sa_family != dev->type)
			return -EINVAL;
		break;
	}

	neigh = __neigh_lookup_errno(&arp_tbl, &ip, dev);
	err = PTR_ERR(neigh);
	if (!IS_ERR(neigh)) {
		unsigned state = NUD_STALE;
		if (r->arp_flags & ATF_PERM)
			state = NUD_PERMANENT;
		err = neigh_update(neigh, (r->arp_flags&ATF_COM) ?
				   r->arp_ha.sa_data : NULL, state,
				   NEIGH_UPDATE_F_OVERRIDE|
				   NEIGH_UPDATE_F_ADMIN);
		neigh_release(neigh);
	}
	return err;
}

static unsigned arp_state_to_flags(struct neighbour *neigh)
{
	unsigned flags = 0;
	if (neigh->nud_state&NUD_PERMANENT)
		flags = ATF_PERM|ATF_COM;
	else if (neigh->nud_state&NUD_VALID)
		flags = ATF_COM;
	return flags;
}

/*
 *	Get an ARP cache entry.
 */

static int arp_req_get(struct arpreq *r, struct net_device *dev)
{
	__be32 ip = ((struct sockaddr_in *) &r->arp_pa)->sin_addr.s_addr;
	struct neighbour *neigh;
	int err = -ENXIO;

	neigh = neigh_lookup(&arp_tbl, &ip, dev);
	if (neigh) {
		read_lock_bh(&neigh->lock);
		memcpy(r->arp_ha.sa_data, neigh->ha, dev->addr_len);
		r->arp_flags = arp_state_to_flags(neigh);
		read_unlock_bh(&neigh->lock);
		r->arp_ha.sa_family = dev->type;
		strlcpy(r->arp_dev, dev->name, sizeof(r->arp_dev));
		neigh_release(neigh);
		err = 0;
	}
	return err;
}

static int arp_req_delete_public(struct net *net, struct arpreq *r,
		struct net_device *dev)
{
	__be32 ip = ((struct sockaddr_in *) &r->arp_pa)->sin_addr.s_addr;
	__be32 mask = ((struct sockaddr_in *)&r->arp_netmask)->sin_addr.s_addr;

	if (mask == htonl(0xFFFFFFFF))
		return pneigh_delete(&arp_tbl, net, &ip, dev);

	if (mask)
		return -EINVAL;

	return arp_req_set_proxy(net, dev, 0);
}

static int arp_req_delete(struct net *net, struct arpreq *r,
		struct net_device * dev)
{
	int err;
	__be32 ip;
	struct neighbour *neigh;

	if (r->arp_flags & ATF_PUBL)
		return arp_req_delete_public(net, r, dev);

	ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;
	if (dev == NULL) {
		struct flowi fl = { .nl_u = { .ip4_u = { .daddr = ip,
							 .tos = RTO_ONLINK } } };
		struct rtable * rt;
		if ((err = ip_route_output_key(net, &rt, &fl)) != 0)
			return err;
		dev = rt->u.dst.dev;
		ip_rt_put(rt);
		if (!dev)
			return -EINVAL;
	}
	err = -ENXIO;
	neigh = neigh_lookup(&arp_tbl, &ip, dev);
	if (neigh) {
		if (neigh->nud_state&~NUD_NOARP)
			err = neigh_update(neigh, NULL, NUD_FAILED,
					   NEIGH_UPDATE_F_OVERRIDE|
					   NEIGH_UPDATE_F_ADMIN);
		neigh_release(neigh);
	}
	return err;
}

/*
 *	Handle an ARP layer I/O control request.
 */

int arp_ioctl(struct net *net, unsigned int cmd, void __user *arg)
{
	int err;
	struct arpreq r;
	struct net_device *dev = NULL;

	switch (cmd) {
		case SIOCDARP:
		case SIOCSARP:
			if (!capable(CAP_NET_ADMIN))
				return -EPERM;
		case SIOCGARP:
			err = copy_from_user(&r, arg, sizeof(struct arpreq));
			if (err)
				return -EFAULT;
			break;
		default:
			return -EINVAL;
	}

	if (r.arp_pa.sa_family != AF_INET)
		return -EPFNOSUPPORT;

	if (!(r.arp_flags & ATF_PUBL) &&
	    (r.arp_flags & (ATF_NETMASK|ATF_DONTPUB)))
		return -EINVAL;
	if (!(r.arp_flags & ATF_NETMASK))
		((struct sockaddr_in *)&r.arp_netmask)->sin_addr.s_addr =
							   htonl(0xFFFFFFFFUL);
	rtnl_lock();
	if (r.arp_dev[0]) {
		err = -ENODEV;
		if ((dev = __dev_get_by_name(net, r.arp_dev)) == NULL)
			goto out;

		/* Mmmm... It is wrong... ARPHRD_NETROM==0 */
		if (!r.arp_ha.sa_family)
			r.arp_ha.sa_family = dev->type;
		err = -EINVAL;
		if ((r.arp_flags & ATF_COM) && r.arp_ha.sa_family != dev->type)
			goto out;
	} else if (cmd == SIOCGARP) {
		err = -ENODEV;
		goto out;
	}

	switch (cmd) {
	case SIOCDARP:
		err = arp_req_delete(net, &r, dev);
		break;
	case SIOCSARP:
		err = arp_req_set(net, &r, dev);
		break;
	case SIOCGARP:
		err = arp_req_get(&r, dev);
		if (!err && copy_to_user(arg, &r, sizeof(r)))
			err = -EFAULT;
		break;
	}
out:
	rtnl_unlock();
	return err;
}

static int arp_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;

	switch (event) {
	case NETDEV_CHANGEADDR:
		neigh_changeaddr(&arp_tbl, dev);
		rt_cache_flush(dev_net(dev), 0);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block arp_netdev_notifier = {
	.notifier_call = arp_netdev_event,
};

/* Note, that it is not on notifier chain.
   It is necessary, that this routine was called after route cache will be
   flushed.
 */
void arp_ifdown(struct net_device *dev)
{
	neigh_ifdown(&arp_tbl, dev);
}


/*
 *	Called once on startup.
 */

static struct packet_type arp_packet_type __read_mostly = {
	.type =	cpu_to_be16(ETH_P_ARP),
	.func =	arp_rcv,
};

static int arp_proc_init(void);

//arpЭ���ʼ������
void __init arp_init(void)
{
	neigh_table_init(&arp_tbl);//ע��һ���麯�����ARPʹ�õ��������ò���,����ȫ���ھӱ����(neigh_tables)

	dev_add_pack(&arp_packet_type);//��װһ��Э�鴦��������arp_rev������δ���ARP��������ں˵Ǽ�ARP���ݰ����ͽṹ
	arp_proc_init();//�����Ὠ��/proc/net/arp�ļ�����ȡ���ļ��ῴ��ARP���������(����ARP�����ַ)
#ifdef CONFIG_SYSCTL
	neigh_sysctl_register(NULL, &arp_tbl.parms, NET_IPV4,//���ں�֧��sysctl�����Դ���һ��Ŀ¼/proc/sys/net/ipv4/neigh,�������neigh_params�ṹ��Ĭ�ϵ��ڲ���
			      NET_IPV4_NEIGH, "ipv4", NULL, NULL);
#endif
	register_netdevice_notifier(&arp_netdev_notifier);//���ں�ע��һ���ص����������ڽ����豸״̬�����ñ仯֪ͨ
}

#ifdef CONFIG_PROC_FS
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)

/* ------------------------------------------------------------------------ */
/*
 *	ax25 -> ASCII conversion
 */
static char *ax2asc2(ax25_address *a, char *buf)
{
	char c, *s;
	int n;

	for (n = 0, s = buf; n < 6; n++) {
		c = (a->ax25_call[n] >> 1) & 0x7F;

		if (c != ' ') *s++ = c;
	}

	*s++ = '-';

	if ((n = ((a->ax25_call[6] >> 1) & 0x0F)) > 9) {
		*s++ = '1';
		n -= 10;
	}

	*s++ = n + '0';
	*s++ = '\0';

	if (*buf == '\0' || *buf == '-')
	   return "*";

	return buf;

}
#endif /* CONFIG_AX25 */

#define HBUFFERLEN 30

static void arp_format_neigh_entry(struct seq_file *seq,
				   struct neighbour *n)
{
	char hbuffer[HBUFFERLEN];
	int k, j;
	char tbuf[16];
	struct net_device *dev = n->dev;
	int hatype = dev->type;

	read_lock(&n->lock);
	/* Convert hardware address to XX:XX:XX:XX ... form. */
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
	if (hatype == ARPHRD_AX25 || hatype == ARPHRD_NETROM)
		ax2asc2((ax25_address *)n->ha, hbuffer);
	else {
#endif
	for (k = 0, j = 0; k < HBUFFERLEN - 3 && j < dev->addr_len; j++) {
		hbuffer[k++] = hex_asc_hi(n->ha[j]);
		hbuffer[k++] = hex_asc_lo(n->ha[j]);
		hbuffer[k++] = ':';
	}
	if (k != 0)
		--k;
	hbuffer[k] = 0;
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
	}
#endif
	sprintf(tbuf, "%pI4", n->primary_key);
	seq_printf(seq, "%-16s 0x%-10x0x%-10x%s     *        %s\n",
		   tbuf, hatype, arp_state_to_flags(n), hbuffer, dev->name);
	read_unlock(&n->lock);
}

static void arp_format_pneigh_entry(struct seq_file *seq,
				    struct pneigh_entry *n)
{
	struct net_device *dev = n->dev;
	int hatype = dev ? dev->type : 0;
	char tbuf[16];

	sprintf(tbuf, "%pI4", n->key);
	seq_printf(seq, "%-16s 0x%-10x0x%-10x%s     *        %s\n",
		   tbuf, hatype, ATF_PUBL | ATF_PERM, "00:00:00:00:00:00",
		   dev ? dev->name : "*");
}

static int arp_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "IP address       HW type     Flags       "
			      "HW address            Mask     Device\n");
	} else {
		struct neigh_seq_state *state = seq->private;

		if (state->flags & NEIGH_SEQ_IS_PNEIGH)
			arp_format_pneigh_entry(seq, v);
		else
			arp_format_neigh_entry(seq, v);
	}

	return 0;
}

static void *arp_seq_start(struct seq_file *seq, loff_t *pos)
{
	/* Don't want to confuse "arp -a" w/ magic entries,
	 * so we tell the generic iterator to skip NUD_NOARP.
	 */
	return neigh_seq_start(seq, pos, &arp_tbl, NEIGH_SEQ_SKIP_NOARP);
}

/* ------------------------------------------------------------------------ */

static const struct seq_operations arp_seq_ops = {
	.start  = arp_seq_start,
	.next   = neigh_seq_next,
	.stop   = neigh_seq_stop,
	.show   = arp_seq_show,
};

static int arp_seq_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &arp_seq_ops,
			    sizeof(struct neigh_seq_state));
}

static const struct file_operations arp_seq_fops = {
	.owner		= THIS_MODULE,
	.open           = arp_seq_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release	= seq_release_net,
};


static int __net_init arp_net_init(struct net *net)
{
	if (!proc_net_fops_create(net, "arp", S_IRUGO, &arp_seq_fops))
		return -ENOMEM;
	return 0;
}

static void __net_exit arp_net_exit(struct net *net)
{
	proc_net_remove(net, "arp");
}

static struct pernet_operations arp_net_ops = {
	.init = arp_net_init,
	.exit = arp_net_exit,
};

static int __init arp_proc_init(void)
{
	return register_pernet_subsys(&arp_net_ops);
}

#else /* CONFIG_PROC_FS */

static int __init arp_proc_init(void)
{
	return 0;
}

#endif /* CONFIG_PROC_FS */

EXPORT_SYMBOL(arp_broken_ops);
EXPORT_SYMBOL(arp_find);
EXPORT_SYMBOL(arp_create);
EXPORT_SYMBOL(arp_xmit);
EXPORT_SYMBOL(arp_send);
EXPORT_SYMBOL(arp_tbl);

#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
EXPORT_SYMBOL(clip_tbl_hook);
#endif
