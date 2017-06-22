/*
net/ipv4/fib_lookup.h:主要作用是，定义路由查找的相关函数原型。
*/
#ifndef _FIB_LOOKUP_H
#define _FIB_LOOKUP_H

#include <linux/types.h>
#include <linux/list.h>
#include <net/ip_fib.h>

//fib_alias实例代表一条路由表项，目的地址相同但其他配置参数不同的表项共享fib_node实例
struct fib_alias {
	struct list_head	fa_list;   //将共享同一个fib_node实例的所有fib_alias实例链接在一起
	struct fib_info		*fa_info;  //指针指向一个fib_info实例，该实例存储着如何处理与该路由相匹配数据报的信息
	u8			fa_tos;            //路由的服务类型比特位字段
	u8			fa_type;           //路由表项的类型，如RTN_UNICAST、RTN_LOCAL等
	u8			fa_scope;          //路由表项的作用范围
	u8			fa_state;          //一些标志的位图
#ifdef CONFIG_IP_FIB_TRIE
	struct rcu_head		rcu;
#endif
};

#define FA_S_ACCESSED	0x01

/* Exported by fib_semantics.c */
extern int fib_semantic_match(struct list_head *head,
			      const struct flowi *flp,
			      struct fib_result *res, int prefixlen);
extern void fib_release_info(struct fib_info *);
extern struct fib_info *fib_create_info(struct fib_config *cfg);
extern int fib_nh_match(struct fib_config *cfg, struct fib_info *fi);
extern int fib_dump_info(struct sk_buff *skb, u32 pid, u32 seq, int event,
			 u32 tb_id, u8 type, u8 scope, __be32 dst,
			 int dst_len, u8 tos, struct fib_info *fi,
			 unsigned int);
extern void rtmsg_fib(int event, __be32 key, struct fib_alias *fa,
		      int dst_len, u32 tb_id, struct nl_info *info,
		      unsigned int nlm_flags);
extern struct fib_alias *fib_find_alias(struct list_head *fah,
					u8 tos, u32 prio);
extern int fib_detect_death(struct fib_info *fi, int order,
			    struct fib_info **last_resort,
			    int *last_idx, int dflt);

static inline void fib_result_assign(struct fib_result *res,
				     struct fib_info *fi)
{
	if (res->fi != NULL)
		fib_info_put(res->fi);
	res->fi = fi;
	if (fi != NULL)
		atomic_inc(&fi->fib_clntref);
}

#endif /* _FIB_LOOKUP_H */
