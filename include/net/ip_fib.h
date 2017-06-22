/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Forwarding Information Base.
 *
 * Authors:	A.N.Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
 /*
 路由子系统的核心是转发信息库(Forwarding Information Base, FIB)，即路由表。
 路由表用来存储:
 1.用于确定输入数据报是应该转发给本机的上层协议还是继续转发的信息。
 2.如果需要转发，正确转发数据报所需要的信息。
 3.输出数据包从哪个具体的网络设备输出的信息。
 */
 /*
 ip_fib.h:主要作用是，定义路由表等结构、宏和函数原型。
 */

#ifndef _NET_IP_FIB_H
#define _NET_IP_FIB_H

#include <net/flow.h>
#include <linux/seq_file.h>
#include <net/fib_rules.h>

struct fib_config {
	u8			fc_dst_len;
	u8			fc_tos;
	u8			fc_protocol;
	u8			fc_scope;
	u8			fc_type;
	/* 3 bytes unused */
	u32			fc_table;
	__be32			fc_dst;
	__be32			fc_gw;
	int			fc_oif;
	u32			fc_flags;
	u32			fc_priority;
	__be32			fc_prefsrc;
	struct nlattr		*fc_mx;
	struct rtnexthop	*fc_mp;
	int			fc_mx_len;
	int			fc_mp_len;
	u32			fc_flow;
	u32			fc_nlflags;
	struct nl_info		fc_nlinfo;
 };

struct fib_info;

//下一跳,包含诸如外出网络设备(nh_dev),外出接口索引(nh_oif)，范围(nf_scope)等信息
struct fib_nh {
	struct net_device	*nh_dev;    //字段指出了将流量传输到下一跳所使用的网络设备(net_device对象)。
	struct hlist_node	nh_hash;
	struct fib_info		*nh_parent;
	unsigned		nh_flags;       //设置下一跳标志，网络设备被禁用时，此值将被设置为RTNH_F_DEAD
	unsigned char		nh_scope;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	int			nh_weight;         //下一条权值。当用户没有明确配置时被设置为默认值1
	int			nh_power;    //使该下一跳被选中的令牌，这个值是在初始化fib_info->fib_power时，首先被初始化为fib_nh->nh_weight.每次fib_select_multipath选中该下一跳是就递减该值，
	                         //当该值递减为0时，不再选中该下一跳，直到nh_power被重新初始化为fib_nh->nh_weight(这里在重新初始化fib_info->fib_power值时进行的)。
#endif
#ifdef CONFIG_NET_CLS_ROUTE
	__u32			nh_tclassid;
#endif
	int			nh_oif;
	__be32			nh_gw;         //下一跳路由地址
};

/*
 * This structure contains data shared by many of routes.
 */

//fib_node结构和fib_alias结构的组合用于标识一条路由表项，同时存储相关信息，比如下一跳网关，网络设备(fib_dev),优先级(fib_priority)，路由选择协议标识符(fib_protocol)
//等重要的路由信息则存储在fib_info结构中
struct fib_info {
	struct hlist_node	fib_hash;
	struct hlist_node	fib_lhash;
	struct net		*fib_net;                 //fib_info对象所属的网络命名空间
	int			fib_treeref;                  //一个引用计数器，表示包含指向该fib_info对象的引用的fib_alias对象的数量
	atomic_t		fib_clntref;              //一个引用计数器，当其为零时，此fib_info将会被释放
	int			fib_dead;                     //一个标志，指出了是否允许方法free_fib_info()将fib_info对象释放，当为1时是，为0时表示处于活动状态，释放失败
	unsigned		fib_flags;                //若fib_info无效，将此值设置为RTNH_F_DEAD        
	int			fib_protocol;                 //路由的路由选择协议标识
	__be32			fib_prefsrc;              //有时候，你可能想将查找键指定为特定的源地址，为此可设置fib_prefsrc.
	u32			fib_priority;                 //路由的优先级,默认为0，表示最高优先级，值越大，表示优先级越低。
	u32			fib_metrics[RTAX_MAX];        //此处的fib_metrics与ip route的参数metric没有任何关系，其是一个包含15个元素的数组，存储了各种指标，很多都与tcp协议相关
#define fib_mtu fib_metrics[RTAX_MTU-1]       //以下几个define值，只是数组fib_metrics中常用元素的别名
#define fib_window fib_metrics[RTAX_WINDOW-1]
#define fib_rtt fib_metrics[RTAX_RTT-1]
#define fib_advmss fib_metrics[RTAX_ADVMSS-1]
	int			fib_nhs;                     //下一条数量,没有设置多路径路由选择(CONFIG_IP_ROUTE_MULTIPATH)时，其值不能超过1
#ifdef CONFIG_IP_ROUTE_MULTIPATH //多路径路由选择功能为路由指定了多条替代路径，并可能给这些路径指定不同的权重。这种功能提供了诸如容错，证件宽带和提高安全性等好处
	int			fib_power;       //该字段被初始化为fib_info实例所有下一跳权值(fib_nh->nh_weight)的总和，但不包含由于某些原因而不能使用的下一跳(带有RTNH_F_DEAD标识)
#endif
	struct fib_nh		fib_nh[0];           //表示下一跳，使用多路径路由选择时，可在一条路由中指定多个下一跳，在这种情况下，将有一个下一跳数组。
#define fib_dev		fib_nh[0].nh_dev         //将数据包传输到下一跳的网络设备
};


#ifdef CONFIG_IP_MULTIPLE_TABLES
struct fib_rule;
#endif

struct fib_result {
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
	struct fib_info *fi;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	struct fib_rule	*r;
#endif
};

struct fib_result_nl {
	__be32		fl_addr;   /* To be looked up*/
	u32		fl_mark;
	unsigned char	fl_tos;
	unsigned char   fl_scope;
	unsigned char   tb_id_in;

	unsigned char   tb_id;      /* Results */
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
	int             err;      
};

#ifdef CONFIG_IP_ROUTE_MULTIPATH

#define FIB_RES_NH(res)		((res).fi->fib_nh[(res).nh_sel])

#define FIB_TABLE_HASHSZ 2

#else /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_NH(res)		((res).fi->fib_nh[0])

#define FIB_TABLE_HASHSZ 256

#endif /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_PREFSRC(res)		((res).fi->fib_prefsrc ? : __fib_res_prefsrc(&res))
#define FIB_RES_GW(res)			(FIB_RES_NH(res).nh_gw)
#define FIB_RES_DEV(res)		(FIB_RES_NH(res).nh_dev)
#define FIB_RES_OIF(res)		(FIB_RES_NH(res).nh_oif)

//对每个路由表实例创建一个fib_table结构，这个结构主要由一个路由表标识和管理该路由表的一组函数指针组成
struct fib_table {
	struct hlist_node tb_hlist; //用来将各个路由表链接成一个双向链表
	u32		tb_id;              //路由表标识。在支持策略路由的情况下，系统中最多可以有256个路由表，枚举类型rt_class_t定义了保留的路由路由表ID
	int		tb_default;
	int		(*tb_lookup)(struct fib_table *tb, const struct flowi *flp, struct fib_result *res);
	int		(*tb_insert)(struct fib_table *, struct fib_config *);
	int		(*tb_delete)(struct fib_table *, struct fib_config *);
	int		(*tb_dump)(struct fib_table *table, struct sk_buff *skb,
				     struct netlink_callback *cb);
	int		(*tb_flush)(struct fib_table *table);
	void		(*tb_select_default)(struct fib_table *table,
					     const struct flowi *flp, struct fib_result *res);

	unsigned char	tb_data[0]; //路由表项的散列表起始地址。在FIB_HASH算法中指向fn_hash结构，而在FIB_TRIE算法中则指向trie结构
};

#ifndef CONFIG_IP_MULTIPLE_TABLES

#define TABLE_LOCAL_INDEX	0
#define TABLE_MAIN_INDEX	1

static inline struct fib_table *fib_get_table(struct net *net, u32 id)
{
	struct hlist_head *ptr;

	ptr = id == RT_TABLE_LOCAL ?
		&net->ipv4.fib_table_hash[TABLE_LOCAL_INDEX] :
		&net->ipv4.fib_table_hash[TABLE_MAIN_INDEX];
	return hlist_entry(ptr->first, struct fib_table, tb_hlist);
}

static inline struct fib_table *fib_new_table(struct net *net, u32 id)
{
	return fib_get_table(net, id);
}

static inline int fib_lookup(struct net *net, const struct flowi *flp,
			     struct fib_result *res)
{
	struct fib_table *table;

	table = fib_get_table(net, RT_TABLE_LOCAL);
	if (!table->tb_lookup(table, flp, res))
		return 0;

	table = fib_get_table(net, RT_TABLE_MAIN);
	if (!table->tb_lookup(table, flp, res))
		return 0;
	return -ENETUNREACH;
}

#else /* CONFIG_IP_MULTIPLE_TABLES */
extern int __net_init fib4_rules_init(struct net *net);
extern void __net_exit fib4_rules_exit(struct net *net);

#ifdef CONFIG_NET_CLS_ROUTE
extern u32 fib_rules_tclass(struct fib_result *res);
#endif

extern int fib_lookup(struct net *n, struct flowi *flp, struct fib_result *res);

extern struct fib_table *fib_new_table(struct net *net, u32 id);
extern struct fib_table *fib_get_table(struct net *net, u32 id);

#endif /* CONFIG_IP_MULTIPLE_TABLES */

/* Exported by fib_frontend.c */
extern const struct nla_policy rtm_ipv4_policy[];
extern void		ip_fib_init(void);
extern int fib_validate_source(__be32 src, __be32 dst, u8 tos, int oif,
			       struct net_device *dev, __be32 *spec_dst,
			       u32 *itag, u32 mark);
extern void fib_select_default(struct net *net, const struct flowi *flp,
			       struct fib_result *res);

/* Exported by fib_semantics.c */
extern int ip_fib_check_default(__be32 gw, struct net_device *dev);
extern int fib_sync_down_dev(struct net_device *dev, int force);
extern int fib_sync_down_addr(struct net *net, __be32 local);
extern int fib_sync_up(struct net_device *dev);
extern __be32  __fib_res_prefsrc(struct fib_result *res);
extern void fib_select_multipath(const struct flowi *flp, struct fib_result *res);

/* Exported by fib_{hash|trie}.c */
extern void fib_hash_init(void);
extern struct fib_table *fib_hash_table(u32 id);

static inline void fib_combine_itag(u32 *itag, struct fib_result *res)
{
#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	u32 rtag;
#endif
	*itag = FIB_RES_NH(*res).nh_tclassid<<16;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	rtag = fib_rules_tclass(res);
	if (*itag == 0)
		*itag = (rtag<<16);
	*itag |= (rtag>>16);
#endif
#endif
}

extern void free_fib_info(struct fib_info *fi);

static inline void fib_info_put(struct fib_info *fi)
{
	if (atomic_dec_and_test(&fi->fib_clntref))
		free_fib_info(fi);
}

static inline void fib_res_put(struct fib_result *res)
{
	if (res->fi)
		fib_info_put(res->fi);
#ifdef CONFIG_IP_MULTIPLE_TABLES
	if (res->r)
		fib_rule_put(res->r);
#endif
}

#ifdef CONFIG_PROC_FS
extern int __net_init  fib_proc_init(struct net *net);
extern void __net_exit fib_proc_exit(struct net *net);
#else
static inline int fib_proc_init(struct net *net)
{
	return 0;
}
static inline void fib_proc_exit(struct net *net)
{
}
#endif

#endif  /* _NET_FIB_H */
