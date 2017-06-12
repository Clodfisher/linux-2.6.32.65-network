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
 * ARP协议涉及到的关键变量，按照如下流程初始化这个表
 * 是ARP地址解析协议的邻居表结构
 * 作用:为获取ip地址与mac地址的对应关系而使用的。
*/
struct neigh_table arp_tbl = {
	.family =	AF_INET,//地址族
	.entry_size =	sizeof(struct neighbour) + 4,//邻居结构的总长度
	.key_len =	4,//IP地址的长度
	.hash =		arp_hash,//哈希函数指针
	.constructor =	arp_constructor,//创建邻居结构的函数指针
	.proxy_redo =	parp_redo,//处理函数指针
	.id =		"arp_cache",//协议名称作为ID
	.parms = {//邻居参数结构
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
	.gc_interval =	30 * HZ, //回收间隔时间
	.gc_thresh1 =	128,//回收最小阈值
	.gc_thresh2 =	512,//回收中等阈值
	.gc_thresh3 =	1024,//回收最大阈值
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
 * 此函数是ARP的邻居初始化函数，用来初始化新的neighbour结构实例，在邻居表创建函数
 * neigh_create()中被调用
*/
static int arp_constructor(struct neighbour *neigh)
{
	__be32 addr = *(__be32*)neigh->primary_key;//取得地址
	struct net_device *dev = neigh->dev;//取得网络设备
	struct in_device *in_dev;
	struct neigh_parms *parms;

	//检测邻居输出网络设备的IP配置块是否有效，如果有效，则从IP配置块中克隆一份邻居配置块给邻居项，
	//否则初始化失败，返回错误码
	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);//取得设备的配置结构
	if (in_dev == NULL) {//结构不存在就退出·
		rcu_read_unlock();
		return -EINVAL;
	}

	//根据邻居地址获取邻居的类型
	neigh->type = inet_addr_type(dev_net(dev), addr);

	parms = in_dev->arp_parms;//取得配置结构的邻居参数
	/*
	 * __neigh_parms_put 和 neigh_parms_clone互为逆操作，前者减少、后者增加邻居参数结构的使用计数器
	 * 实际上更新了邻居参数指针
	*/
	__neigh_parms_put(neigh->parms);//递减原来邻居参数的使用计数
	neigh->parms = neigh_parms_clone(parms);//从IP配置块中克隆一份邻居配置块给邻居项
	rcu_read_unlock();

	/*如果无需支持ARP，则设置该邻居项的状态为NUD_NOARP，同时用arp_direct_ops()作为邻居
	项的函数指针表，并初始化邻居项的输出结构output
	*/
	if (!dev->header_ops) {//是否安装了链路层函数表，由驱动程序安装
		neigh->nud_state = NUD_NOARP;//设置为不需要解析状态
		neigh->ops = &arp_direct_ops;//记录函数表
		neigh->output = neigh->ops->queue_xmit;//设置发送函数
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
		需要ARP支持的情况，硬件接口类型为ROSE、AX.25、NETROM这三种情况，使用
		arp_broken_ops()作为邻居项的函数指针表。
		*/
		switch (dev->type) {//判断网络设备类型
		default:
			break;
		case ARPHRD_ROSE:
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
		case ARPHRD_AX25:
#if defined(CONFIG_NETROM) || defined(CONFIG_NETROM_MODULE)
		case ARPHRD_NETROM:
#endif
			neigh->ops = &arp_broken_ops;//记录函数表，输出函数则为neigh_compat_output()
			neigh->output = neigh->ops->output;//设置发送函数
			return 0;
#endif
		;}
#endif/* 对于其他网卡类型，也要检查neigh->type类型，这个类型值前面设置为路由器网关的地址类型 */
		/*如果邻居项地址是组播类型，也无需ARP支持，调用arp_mc_map()解析组播地址，把获取的组播地址存储到
		邻居项中*/
		if (neigh->type == RTN_MULTICAST) {//组播类型
			neigh->nud_state = NUD_NOARP;//设置状态
			arp_mc_map(addr, neigh->ha, dev, 1);//设置MAC地址
		} else if (dev->flags&(IFF_NOARP|IFF_LOOPBACK)) {//回接设备
			neigh->nud_state = NUD_NOARP;//设置为不需要解析状态
			memcpy(neigh->ha, dev->dev_addr, dev->addr_len);//从该网络设备中获取硬件地址存储到邻居项中
		} else if (neigh->type == RTN_BROADCAST || dev->flags&IFF_POINTOPOINT) {//如果是广播类型或者点对点类型
			neigh->nud_state = NUD_NOARP;//设置为不需要解析状态
			memcpy(neigh->ha, dev->broadcast, dev->addr_len);//复制广播地址作为硬件地址存储到邻居项中
		}

		if (dev->header_ops->cache)//是否提供了缓冲函数，由网卡驱动程序安装
			neigh->ops = &arp_hh_ops;//记录函数表
		else
			neigh->ops = &arp_generic_ops;

		if (neigh->nud_state&NUD_VALID)//有效状态
			neigh->output = neigh->ops->connected_output;//设置发送函数
		else
			neigh->output = neigh->ops->output;//使用函数表的发送函数
	}
	return 0;
}

/* arp_error_report()调用dst_link_failure()向三层报告错误。用来初始化除arp_direct_ops之外
的三个neigh_ops结构实例的error_report函数指针。当邻居项缓存中还存在有未发送的报文，而该邻居
却无法访问时被调用*/
static void arp_error_report(struct neighbour *neigh, struct sk_buff *skb)
{
	dst_link_failure(skb);
	kfree_skb(skb);
}

/*
 * 此函数会根据数据包的源地址创建并发送ARP包，调用路线如下:
 * neigh_timer_handler()->arp_solicit()->arp_send()->arp_xmit()->dev_queue_xmit()。
 * 此函数的主要任务是获取源地址和网关地址，然后调用arp_send()函数，创建并发送ARP包
 * neigh---请求的目的邻居项
 * skb---缓存在改邻居项中的待发送报文，用来获取改skb的源IP地址
*/
static void arp_solicit(struct neighbour *neigh, struct sk_buff *skb)
{
	__be32 saddr = 0;
	u8  *dst_ha = NULL;
	struct net_device *dev = neigh->dev;//获取网络设备结构
	__be32 target = *(__be32*)neigh->primary_key;//获取网关地址
	int probes = atomic_read(&neigh->probes);//获取失败计数
	struct in_device *in_dev = in_dev_get(dev);//获取设备配置结构

	//检测邻居项网络设备的IP配置块是否有效
	if (!in_dev)
		return;
	//根据arp_announce系统参数，选择IP地址(规则0或1)
	//announce参数，从输出arp请求时，从IP数据包中确定源邋IP地址的规则。
	switch (IN_DEV_ARP_ANNOUNCE(in_dev)) {
	default:
	case 0:		/* By default announce any local IP 默认情况下会发布任何本地IP */
		if (skb && inet_addr_type(dev_net(dev), ip_hdr(skb)->saddr) == RTN_LOCAL)
			saddr = ip_hdr(skb)->saddr;//获取IP头部中的源地址
		break;
	case 1:		/* Restrict announcements of saddr in same subnet 限制saddr在同一子网中的公告 */
		if (!skb)
			break;
		saddr = ip_hdr(skb)->saddr;
		if (inet_addr_type(dev_net(dev), saddr) == RTN_LOCAL) {
			/* saddr should be known to target 应该知道saddr的目标 */
			if (inet_addr_onlink(in_dev, target, saddr))
				break;
		}
		saddr = 0;
		break;
	case 2:		/* Avoid secondary IPs, get a primary/preferred one */
		break;
	}

	if (in_dev)
		in_dev_put(in_dev);//递减设备配置结构使用计数
	if (!saddr)//如果没有指定源地址
		saddr = inet_select_addr(dev, target, RT_SCOPE_LINK);//根据arp_announce系统参数，选择源IP地址

	//检测ARP请求报文重传次数是否达到上限，如果是，则停止发送
	if ((probes -= neigh->parms->ucast_probes) < 0) {//检查邻居参数的探测值
		if (!(neigh->nud_state&NUD_VALID))//如果邻居结构处于无效状态
			printk(KERN_DEBUG "trying to ucast probe in NUD_INVALID\n");
		dst_ha = neigh->ha;//获取邻居结构的MAC地址作为目标MAC地址
		read_lock_bh(&neigh->lock);
	} else if ((probes -= neigh->parms->app_probes) < 0) {
#ifdef CONFIG_ARPD
		neigh_app_ns(neigh);
#endif
		return;
	}

	//将得到的硬件源、目标地址和IP源、目标地址等作为参数，调用arp_send()创建一个ARP报文将其输出。
	arp_send(ARPOP_REQUEST, ETH_P_ARP, target, dev, saddr,
		 dst_ha, dev->dev_addr, NULL);//创建并发送ARP包
	if (dst_ha)
		read_unlock_bh(&neigh->lock);
}

/*
 此函数用来根据过滤规则对输出ARP报文中的源，目的IP地址进行确认，返回值非0要过滤。
 函数中首先根据规则获取sip和scope，然后将这两者作为参数调用inet_confirm_addr()对源，目的
 IP地址进行确认。
 参数:
 in_dev,输入ARP请求报文网络设备的IP控制块
 sip,发送方IP地址
 tip,ARP请求报文的目标IP地址
*/
static int arp_ignore(struct in_device *in_dev, __be32 sip, __be32 tip)
{
	int scope;

	//获取系统配置的过滤规则，根据规则做相应处理
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
 arp_filter()根据ARP请求报文中的发送方IP地址和目的邋IP地址，查找输出到ARP请求报文发送方的路由，
 过滤掉那些查找路由失败，或是查找到的路由输出设备与输入ARP请求报文的设备不同的ARP请求报文
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
 * 在创建路由表rt_intern_hash()函数中，对新建的路由项查找邻居结构，这时调用的arp_bind_neighbour()函数来完成。
 * 先检查邻居结构是否存在，如果不存在就要调用__neigh_lookup_errno()查找，如果找到了邻居结构就记录在路由项中
*/
int arp_bind_neighbour(struct dst_entry *dst)
{
	struct net_device *dev = dst->dev;//取得网络设备结构指针
	struct neighbour *n = dst->neighbour;//取得路由项中的邻居结构指针

	if (dev == NULL)//网络设备不能为空
		return -EINVAL;
	if (n == NULL) {/*如果路由缓存没有绑定邻居表项*/
		__be32 nexthop = ((struct rtable *)dst)->rt_gateway;/*取得下一跳ip地址，即路由网关*/
		if (dev->flags&(IFF_LOOPBACK|IFF_POINTOPOINT))//如果设备支持回接和点对点
			nexthop = 0;//清空取值
		n = __neigh_lookup_errno(
#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
		    dev->type == ARPHRD_ATM ? clip_tbl_hook :
#endif
		    &arp_tbl, &nexthop, dev);//查找并创建下一跳ip对应的邻居表项，第一个参数是邻居表结构，第二个参数是路由网关地址，第三个参数是网络设备
		if (IS_ERR(n))
			return PTR_ERR(n);
		dst->neighbour = n;//将下一跳的邻居表项和目的地址的路由缓存绑定
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
 *	message. 用来创建一个完整的ARP类型二层报文
 *	参数:
 	type 　 　ARP协议的操作码，如ARPOP_REPLY、ARPOP_REQUEST等
 	ptype　三层协议类型，如以太网上ARP协议类型编码为ETH_P_ARP(0x0806)
 	dest_ip src_ip 输出ARP报文的目的邋IP地址和发送方IP地址，填充到ARP报文中。
 	dev 输出ARP报文的网络设备
 	dest_hw,target_hw，输出ARP报文的目的硬件地址，dest_hw填充到二层帧首部
 	src_hw,src_hw位输出ARP报文的源硬件地址，填充到以太网帧首部和ARP报文。
 */
struct sk_buff *arp_create(int type, int ptype, __be32 dest_ip,
			   struct net_device *dev, __be32 src_ip,
			   const unsigned char *dest_hw,
			   const unsigned char *src_hw,
			   const unsigned char *target_hw)
{
	struct sk_buff *skb;
	struct arphdr *arp;//ARP头部结构指针
	unsigned char *arp_ptr;

	/*
	 *	Allocate a buffer
	 */
    // 分配数据包结构空间，分配缓冲块，其长度包含ARP头部长度和以太网头部长度
	skb = alloc_skb(arp_hdr_len(dev) + LL_ALLOCATED_SPACE(dev), GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	skb_reserve(skb, LL_RESERVED_SPACE(dev));//在缓冲块中开辟数据块空间
	skb_reset_network_header(skb);//设置网络层头部指针
	arp = (struct arphdr *) skb_put(skb, arp_hdr_len(dev));//指向数据块中的ARP头部
	skb->dev = dev; //记录设备结构
	skb->protocol = htons(ETH_P_ARP);//记录协议类型
	if (src_hw == NULL)//如果没有指定源硬件地址
		src_hw = dev->dev_addr;//记录设备的MAC地址
	if (dest_hw == NULL)//如果没有指定目标硬件地址
		dest_hw = dev->broadcast;//记录设备的广播地址

	/*
	 *	Fill the device header for the ARP frame
	 */
	 //调用eth_header_ops结构中的create()函数，即eth_header()
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
		arp->ar_hrd = htons(dev->type);//记录硬件类型
		arp->ar_pro = htons(ETH_P_IP);//记录协议类型
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

	arp->ar_hln = dev->addr_len;//记录设备的地址长度
	arp->ar_pln = 4;//记录设备地址的字节数
	arp->ar_op = htons(type);//记录类型值

	arp_ptr=(unsigned char *)(arp+1);//数据块中用于保存源地址处

	memcpy(arp_ptr, src_hw, dev->addr_len);//赋值源MAC地址
	arp_ptr += dev->addr_len;//数据块中用于保存IP地址处
	memcpy(arp_ptr, &src_ip, 4);//复制源IP地址
	arp_ptr += 4;//数据块中用于保存目标地址处
	if (target_hw != NULL)
		memcpy(arp_ptr, target_hw, dev->addr_len);//复制目标MAC地址
	else
		memset(arp_ptr, 0, dev->addr_len);
	arp_ptr += dev->addr_len;//数据块中用于保存目标IP地址处
	memcpy(arp_ptr, &dest_ip, 4);//赋值目标IP地址(一般是网关地址)

	return skb;//返回创建的数据包

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
	NF_HOOK(NFPROTO_ARP, NF_ARP_OUT, skb, NULL, skb->dev, dev_queue_xmit);//这里调用的是dev_aueue_xmit()函数发送数据包
}

/*
 *	Create and send an arp packet.填充arp包头和封包内容,并调用arp_xmit函数传送这个arp请求
    参数和arp_create()参数相同
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

	if (dev->flags&IFF_NOARP)//检查设备是否支持ARP协议，若无，则不需要发送ARP报文直接返回
		return;

	skb = arp_create(type, ptype, dest_ip, dev, src_ip,
			 dest_hw, src_hw, target_hw);//创建ARP包
	if (skb == NULL) {//创建失败返回
		return;
	}
	
	/*如果创建成功，则再调用arp_xmit()将其发送出去，arp_xmit()通过NF_HOOK封装了dev_queue_xmit()
	在netfilter处理之后调用dev_queue_xmit()输出报文。
	*/
	arp_xmit(skb);//发送arp请求
}

/*
 *	Process an arp request.ARP应答处理,即ARP输入流程
 */
static int arp_process(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;//获取网络设备结构
	struct in_device *in_dev = in_dev_get(dev);//获取设备配置结构
	struct arphdr *arp;
	unsigned char *arp_ptr;
	struct rtable *rt;
	unsigned char *sha;
	__be32 sip, tip;
	u16 dev_type = dev->type;//获取设备类型
	int addr_type;
	struct neighbour *n;
	struct net *net = dev_net(dev);//获取网络空间结构

	/* arp_rcv below verifies the ARP header and verifies the device
	 * is ARP'able.
	 */

	if (in_dev == NULL)//配置结构不能为空
		goto out;

	arp = arp_hdr(skb);//获取ARP结构头部

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
	/* 目的ARP接收处理只支持ARP请求和ARP相应，其他类型的ARP报文均丢弃 */
	if (arp->ar_op != htons(ARPOP_REPLY) &&
	    arp->ar_op != htons(ARPOP_REQUEST))
		goto out;

/*
 *	Extract fields
 获取ARP报文中发送方硬件地址(sha)、发送方IP地址(sip)、目的硬件地址(tha)和目的邋IP地址(tip)，
 丢弃目的IP地址为环回地址或多播地址的报文
 */
	arp_ptr= (unsigned char *)(arp+1);//指向数据块中的源MAC地址处
	sha	= arp_ptr;//获取客户端MAC地址
	arp_ptr += dev->addr_len;//指向数据块中的源IP地址处
	memcpy(&sip, arp_ptr, 4);//获取客户端的IP地址
	arp_ptr += 4;//指向目标MAC地址处
	arp_ptr += dev->addr_len;//指向目标IP地址
	memcpy(&tip, arp_ptr, 4);//获取目标IP地址
/*
 *	Check for bad requests for 127.x.x.x and requests for multicast
 *	addresses.  If this is one such, delete it.
 *  检测127.x.x.x的不良请求和多播地址的请求.如果是这样的，删除它
 *  ARP不会查询环路地址和组播地址，因为他们没哟对应的mac地址，因此遇到这两类地址，直接退出
 */
	if (ipv4_is_loopback(tip) || ipv4_is_multicast(tip))
		goto out;

/*
 *     Special case: We must set Frame Relay source Q.922 address
 *     特殊情况：我们必须设置帧中继源Q.922地址
       如果硬件类型为Q.922则发送方硬件地址，即ARP应答报文的目标硬件地址，设置为网络设备的广播地址。
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
 进程输入。 这里的想法是，如果是对我们的请求，或者是要求我们持有代理人的请求，我们希望发送回复。 
 如果是对我们的回复，或者是我们的地址请求，我们希望在缓存中添加一个条目。 
 （最后的假设是，如果有人正在请求我们的地址，他们可能有意跟我们交谈，所以如果我们缓存他们的地址，
 它可以节省时间，他们的地址也可能不在我们的缓存中，因为我们的 缓存。）换句话说，我们只关心回复，
 如果他们对我们，在这种情况下，我们将它们添加到缓存。 对于请求，我们关心那些为我们和我们的代理人。
 我们回复两者，在请求的情况下，我们将请求者添加到arp缓存。
*/

	/* Special case: IPv4 duplicate address detection packet (RFC2131) 特殊情况：IPv4重复地址检测报文（RFC2131）
     * 如果收到的是重复地址检测报文，并且本机占用了检测了地址，则调用arp_send发送相应。对于
     * 重复地址检测报文(ARP报文中源IP为全0)，它所带有的邻居表现信息还没通过检测，此时缓存它显然没有意义，
     * 也许下一刻就有其它主机声明它非法，因此重复地址检测报文中的信息不会加入邻居表中。
     如果请求报文的源IP地址为0，则该ARP报文是用来检测IPV4地址冲突(RFC2131)，因此在确定请求报文的目标IP
     地址为本地IP地址后，以该IP地址为源地址及目标地址发送ARP应答报文。
    */
	if (sip == 0) {
		if (arp->ar_op == htons(ARPOP_REQUEST) &&
		    inet_addr_type(net, tip) == RTN_LOCAL &&
		    !arp_ignore(in_dev, sip, tip))
			arp_send(ARPOP_REPLY, ETH_P_ARP, sip, dev, tip, sha,
				 dev->dev_addr, sha);
		goto out;
	}

	//下面要处理的地址解析报文，并且要解析的地址在路由表中存在
	if (arp->ar_op == htons(ARPOP_REQUEST) &&//如果是arp请求
	    ip_route_input(skb, tip, sip, 0, dev) == 0) {//查找或者创建目标地址的路由表

		rt = skb_rtable(skb);//获取路由表
		addr_type = rt->rt_type;//获取地址类型

		/* 处理发送给本机的ARP请求报文，首先调用neigh_event_ns()更新对于的邻居项，
		然后根据系统设置来决定是否过滤和丢弃ARP报文，最后如果没有被过滤或丢弃掉，则发送ARP应答报文
		*/
		if (addr_type == RTN_LOCAL) {//如果是本地路由类型
			int dont_send = 0;

			if (!dont_send)
				dont_send |= arp_ignore(in_dev,sip,tip);//是否忽略ARP应答
			if (!dont_send && IN_DEV_ARPFILTER(in_dev))
				dont_send |= arp_filter(sip,tip,dev);//是否过滤ARP应答
			if (!dont_send) {//此函数的功能是在arp_tbl中查找是否已包含有对方主机的地址信息，若没有，则新建，然后调用neigh_update来更新状态
				n = neigh_event_ns(&arp_tbl, sha, &sip, dev);
				if (n) {
					arp_send(ARPOP_REPLY,ETH_P_ARP,sip,dev,tip,sha,dev->dev_addr,sha);//发送ARP应答给客户端(邻居项)
					neigh_release(n);//递减邻居结构使用计数
				}
			}
			goto out;
		} else if (IN_DEV_FORWARD(in_dev)) {//对于不是发送给本机的ARP请求报文，根据系统参数确定是否进行ARP代理
			    if (addr_type == RTN_UNICAST  && rt->u.dst.dev != dev &&
			     (arp_fwd_proxy(in_dev, rt) || pneigh_lookup(&arp_tbl, net, &tip, dev, 0))) {
			     /*
			     	 补充：neigh_event_ns()与neigh_release()配套使用并不代表创建后又被释放，
			     	 neigh被释放的条件是neigh->refcnt==0，但neigh创建时的refcnt=1，
			     	 而neigh_event_ns会使refcnt+1，neigh_release会使-1，此时refcnt的值还是1，
			     	 只有当下次单独调用neigh_release时才会被释放。
				 */
				n = neigh_event_ns(&arp_tbl, sha, &sip, dev);//被动学习
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
	/*根据ARP应答找出对应的邻居表项，如果没有则创建*/
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
		int state = NUD_REACHABLE;/*邻居表项将被更新为NUD_REACHABLE 状态*/
		int override;

		/* If several different ARP replies follows back-to-back,
		   use the FIRST one. It is possible, if several proxy
		   agents are active. Taking the first reply prevents
		   arp trashing and chooses the fastest router.
		   如果几个不同的ARP回复跟随背靠背，请使用第一个。 如果几个代理程序处于活动状态，
		   这是可能的。 采取第一个回复可防止arp trashing并选择最快的路由器。
		 */
		override = time_after(jiffies, n->updated + n->parms->locktime);

		/* Broadcast replies and request packets
		   do not assert neighbour reachability.
		   广播回复和请求报文不会声明邻居可达性。
		 */
		if (arp->ar_op != htons(ARPOP_REPLY) ||//如果ARP包不是应答类型
		    skb->pkt_type != PACKET_HOST)//或者数据包不属于本地类型
			state = NUD_STALE;//设置为过期状态
		/*更新邻居表状态*///neigh_update()用来更新指定的邻居项，更新内容是硬件地址和状态（二层地址就是在这个函数中存入邻居表项的）。
		//最后通过此函数设置邻居结构为可到达状态，并更新记录的服务器MAC地址，发送前面挂入到队列中的数据包。
		//第一个参数查找到的邻居结构，第二个参数服务器的MAC地址，第三个参数是可到达状态标志，第四个参数则是过期标志。
		neigh_update(n, sha, state, override ? NEIGH_UPDATE_F_OVERRIDE : 0);
		neigh_release(n);//递减邻居结构使用计数
	}

out:
	if (in_dev)
		in_dev_put(in_dev);//递减配置结构使用计数
	consume_skb(skb);//释放数据包
	return 0;
}

static void parp_redo(struct sk_buff *skb)
{
	arp_process(skb);
}


/*
 *	Receive an arp request from the device layer.处理两种主要的arp封包
    此函数用来从二层接收并处理一个ARP报文。
    参数说明:
    skb,ARP报文的SKB。
    dev,接收ARP报文的网络设备，可能与orig_dev不是同一个设备
    pt，packet_type结构实例，对ARP协议来说是arp_packet_type，在其中定义了ARP协议
        接收函数为arp_rcv().该参数arp_rcv()中并未使用。
    orig_dev,接收到ARP报文的原始网络设备，arp_rcv()中未使用。
 */

static int arp_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt, struct net_device *orig_dev)
{
	struct arphdr *arp;

	/* ARP header, plus 2 device addresses, plus 2 IP addresses.  
	检测ARP报文的完整性:其长度是否等于一个ARP头部长度，加两个硬件地址长度，再加两个IP地址长度
	*/
	if (!pskb_may_pull(skb, arp_hdr_len(dev)))//检查、调整数据包头部结构
		goto freeskb;

	/*检测报文和网络设备的标志。ARP报文的硬件地址长度与网络设备的硬件地址长度是否匹配；网络
	设备是否支持ARP协议；ARP报文是否是转发的包；ARP报文是否来自回环接口等。
	*/
	arp = arp_hdr(skb);//获取ARP头部结构
	if (arp->ar_hln != dev->addr_len ||//对比设备地址长度
	    dev->flags & IFF_NOARP ||//设备是否支持ARP协议
	    skb->pkt_type == PACKET_OTHERHOST ||//是否为发给其他主机的数据包
	    skb->pkt_type == PACKET_LOOPBACK ||//是否为回接类型
	    arp->ar_pln != 4)//检查地址字节数
		goto freeskb;

	//检查能否共享数据包结构，如果能够共享的话就通过skb_clone()克隆一个新的数据包结构包，
	//函数使用这个新的数据包结构
	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
		goto out_of_mem;

	memset(NEIGH_CB(skb), 0, sizeof(struct neighbour_cb));//清零控制信息

	//以上先对ARP头部进行检查，确定无误后，通过netfiter处理之后，转到arp_process()中处理
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

//arp协议初始化函数
void __init arp_init(void)
{
	neigh_table_init(&arp_tbl);//注册一个虚函数表和ARP使用的其它常用参数,插入全局邻居表队列(neigh_tables)

	dev_add_pack(&arp_packet_type);//安装一个协议处理函数，即arp_rev函数如何处理ARP封包，向内核登记ARP数据包类型结构
	arp_proc_init();//函数会建立/proc/net/arp文件，读取该文件会看到ARP缓存的内容(包括ARP代理地址)
#ifdef CONFIG_SYSCTL
	neigh_sysctl_register(NULL, &arp_tbl.parms, NET_IPV4,//若内核支持sysctl，可以创建一个目录/proc/sys/net/ipv4/neigh,用于输出neigh_params结构的默认调节参数
			      NET_IPV4_NEIGH, "ipv4", NULL, NULL);
#endif
	register_netdevice_notifier(&arp_netdev_notifier);//向内核注册一个回调函数，用于接收设备状态和配置变化通知
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
