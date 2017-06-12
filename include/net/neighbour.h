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

#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)                  //��ʱ��״̬���붨ʱ���йص�״̬
#define NUD_VALID	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)   //��Ч״̬�����˳�ʼ״̬���״̬, NUD_INCOMPLETE,NUD_FAILE
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)                             //����״̬���Ѿ���ȷ�еĽ��۵�״̬�ɵ��
                                                                                            //��ֱ�ӷ������ݰ����ھӽṹ

struct neighbour;

/*
 * ����ÿ���豸���ھ�Э����Ϊ���е�����һ�����(�ھ�ϴ�²�������)�������ڴ󲿷ֽӿ��Ͽ����������Э��(���磬IPv4��IPv6)��
 * ����һ��net_device�ṹ���Թ������
 * neigh_parms�ṹ
*/
struct neigh_parms
{
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
	struct net_device *dev;//ָ���neigh_parmsʵ������Ӧ�������豸
	struct neigh_parms *next;//������neigh_paramsʵ��������һ��ÿ��neigh_tableʵ�����и��Ե�neigh_parms����
	int	(*neigh_setup)(struct neighbour *);
	void	(*neigh_cleanup)(struct neighbour *);
	struct neigh_table *tbl;//ָ���neigh_parmsʵ���������ھӱ�

	void	*sysctl_table;//�ھӱ��sysctl������arp����arpģ���ʼ������arp_init()�ж����ʼ���ģ������û�����ͨ��proc�ļ�ϵͳ
	                      //����д�ھӱ�Ĳ���

	int dead;//���ֶ�ֵ���Ϊ1������ھӲ���ʵ�����ڱ�ɾ����������ʹ�ã�Ҳ�����ٴ�����Ӧ�����豸���ھ�������������豸����ʱ����
	         //neigh_parms_release()����
	atomic_t refcnt;//���ü���
	struct rcu_head rcu_head;//Ϊ����ͬ�����ʶ����õĲ���

	int	base_reachable_time;//Ϊ����reachable_time�Ļ�׼ֵ,30s
	int	retrans_time;//�ش�һ������ǰ�ӳٵ�jiffiesֵ��Ĭ��ֵΪ1s
	int	gc_staletime;//һ���ھ��������������(û�б�ʹ��)ʱ�䵽��gc_staletime��û�б�������Ὣ��ɾ��.Ĭ��ֵΪ60s
	int	reachable_time;//��ΪNUD_REACHEABLE״̬��ʱʱ�䣬��ֵΪ���ֵ������
	                   //base_reachable_time/2��3*base_reachable_time/2֮���һ�����ֵ��
	                   //ͨ��300s��neigh_periodic_work()�и���һ��
	int	delay_probe_time;//�ھ���ά����NUD_DELAY״̬delay_probe_time֮�����NUD_PROBE״̬�����ߴ���NUD_REACHABLE״̬���ھ�������ʱ��
	                     //����delay_probe_time��ֱ�ӽ���NUD_DELAY״̬

	int	queue_len;//proxy_queue���г������ޡ�
	int	ucast_probes;//������ARP�ػ�����ǰ���Է��͵���̽�������Ĭ��ֵΪ3
	int	app_probes;//һ�������Ϊ0����ʹ����arpd�ػ�����ʱ�Ż���������ֵ
	int	mcast_probes;//�ಥ��㲥�ڱ�ʶһ���ھ���ɴ�֮ǰ��ೢ�Խ����Ĵ�����Ĭ��ֵΪ3��
	int	anycast_delay;//����Ӧһ��IPv6�ھ�������Ϣ֮ǰ����ӳٵ�jiffiesֵ����anycast��֧�ֻ�û��ʵ�֣�Ĭ��ֵΪ1s
	int	proxy_delay;//�����յ�һ����δ֪����ARP��ַARP����ʱ�����ӳ�porxy_delay jiffies��Ӧ����������һЩ����·�ֹARP���ĵĺ鷺��Ĭ��ֵΪ0.8s
	int	proxy_qlen;//������proxy-ARP��ַ���Ŷӵ����ݰ�����Ĭ��ֵΪ64
	int	locktime;//һ��ARP�������ڻ����б����jiffiesֵ.�ڴ��ڶ���һ���Ŀ���ӳ�������£���ͨ������Ϊ�������ô���������ֹARP���涶����Ĭ��ֵΪ1s
};

/* �����洢ͳ����Ϣ��һ���ýṹʵ����Ӧһ�������豸�ϵ�һ���ھ�Э�� */
struct neigh_statistics
{
	unsigned long allocs;		/* number of allocated neighs ��¼�ѷ����neighbour�ṹʵ���������������ͷŵ�ʵ�� */
	unsigned long destroys;		/* number of destroyed neighs ��neigh_destroy��ɾ�����ھ����ܺ� */
	unsigned long hash_grows;	/* number of hash resizes  ����hash_bucketsɢ�б�Ĵ��� */

	unsigned long res_failed;	/* number of failed resolutions ���Խ���һ���ھӵ�ַ��ʧ�ܴ������Ⲣ���Ƿ���arp�����ĵĴ�����
	                              ���Ƕ���һ���ھ���˵����neigh_timer_handler()�����г��Զ�ʧ��֮��Ž��м��� */

	unsigned long lookups;		/* number of lookups ����neigh_lookup()���ܴ��� */
	unsigned long hits;		/* number of hits (among lookups) ����neigh_lookup() �ɹ������ܴ��� */

	/* IPV6�ֱ�������ʶ���յ������鲥�򵥲���ַ��ARP���������� */
	unsigned long rcv_probes_mcast;	/* number of received mcast ipv6 */
	unsigned long rcv_probes_ucast; /* number of received ucast ipv6 */

	/* �ֱ����neigh_periodic_timer()��neigh_forced_gc()�Ĵ��� */
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
 * �洢�ھӵ��й���Ϣ������L2��L3��ַ��NUD״̬�������ھӾ������豸�ȡ�ע�⣬һ��neighbour�����һ̨�����йأ�����
 * ��һ��L3��ַ��أ���Ϊһ̨���������ж��L3��ַ������·�������ж���ӿڣ����Ҳ�ж��L3��ַ
*/
struct neighbour
{//�ھ����ݽṹ
	struct neighbour	*next;//��ɶ��е�ָ�룬ͨ��next���ھ�����뵽ɢ�б�Ͱ�����ϣ�����Ͱ��ǰ�������µ��ھ���
	struct neigh_table	*tbl;//�ھӱ�ṹ�����ھ������ڵ��ھӱ�������ھ����Ӧ����һ��ipv4��ַ������ֶ�ָ��arp_tbl
	struct neigh_parms	*parms;//�ھӲ����ṹ
	struct net_device		*dev;//�����豸ָ�룬��ÿ���ھ���˵��ֻ����һ�����������ʸ��ھӵ������豸
	unsigned long		used;//ʹ��ʱ��,�������ʹ�ø��ھ����ʱ�䣬���ֶ�ֵ�������������ݴ���ͬ�����£����ھӲ�����NUD_CONNECTED
	                         //״̬ʱ����ֵ��neigh_event_send()�����У������ھ�״̬����NUD_CONNECTED״̬ʱ����ֵ��ʱ��ͨ��gc_timer��ʱ������������
	unsigned long		confirmed;//ȷ��ʱ��,��������յ����Զ�Ӧ�ھ���ı���ʱ�䣬�����ͨ��neigh_confirm()�����£��ھ���ϵͳ��neigh_update()����
	unsigned long		updated;//����ʱ��(��������״̬���ʱ��)
	__u8			flags;//��־λ
	__u8			nud_state;//״̬��־
	__u8			type;//���ͣ���ֵ����������ΪRTN_UNICAST,RTN_LOCAL,RTN_BROADCAST����
	__u8			dead;//�����־���������Ϊ1������ζ�Ÿ��ھ������ڱ�ɾ��������ͨ���������ս���ɾ��
	atomic_t		probes;//ʧ�ܼ�����,����arp��̽��������ֵ�ڶ�ʱ���������б���⣬����ֵ�ﵽָ�������ޣ����ھ�������NUD_FAILED״̬
	rwlock_t		lock;//��д�����������Ʒ����ھ���Ķ�д��
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];//MAC��ַ��ͨ��������ַ���ᳬ��32B���������Ϊ32
	struct hh_cache		*hh;//��·ͷ�����棬���ٷ��ͣ�ָ�򻺴�Ķ���Э���ײ�hh_cache�ṹʵ������
	atomic_t		refcnt;//���ü�����
	int			(*output)(struct sk_buff *skb);//���ͺ���ָ�룬������������������ھӡ����ھ�����������������У�������״̬ʱ���ϱ仯�ģ�
	                                           //�Ӷ����¸ú���ָ���ָ��ͬ��������������統�ھ�Ϊ�ɴ�ʱ������neigh_connect��output
	                                           //����Ϊneigh_ops->connected_output
	struct sk_buff_head	arp_queue;//��Ҫ��������ݰ�����
	struct timer_list	timer;//��ʱ����,����������ֳ�ʱ����Ķ�ʱ��
	const struct neigh_ops	*ops;//ָ���ھ����ָ���ʵ����ÿһ���ھ�Э�鶼�ṩ3��4�ֲ�ͬ���ھ����ָ���ʵ������һ�ֻ���Ҫ����
	                             //����Э���ַ�����͡������豸�����͵�
	u8			primary_key[0];//����ֵ��һ�������ص�ַ����ʵ��ʹ�ÿռ��Ǹ�������Э���ַ���ȶ�̬����ģ�����IPV4Ϊ32λĿ��IP��ַ
};

/*
 * һ�麯����������ʾL3Э��(��IP)��dev_queue_xmit֮��Ľӿڡ�
 * �ھ����ָ��������ھӵ����������в�ͬʱ�ڱ����õĶ������ָ����ɣ������ж������ָ����ʵ������(IPV4�е�IP��)��
 * dev_queue_xmit()֮��ĵ��õ���������ʹ���ڲ�ͬ��״̬��
*/
struct neigh_ops
{
	int			family;//��ʶ�����ĵ�ַ�壬����ARPΪAF_INET��
	void			(*solicit)(struct neighbour *, struct sk_buff*);//���������ĺ������ڷ��͵�һ������ʱ����Ҫ�µ��ھ������
	                                                                //���ı����浽arp�����У�Ȼ�����solicit()����������
	void			(*error_report)(struct neighbour *, struct sk_buff*);//���ھ������δ���͵ı��ģ������ھ���ɵ���ʱ��������
	                                                                     //�������㱨�����ĺ�����ARP��Ϊarp_error_report()�����ջ�
	                                                                     //�����ķ��ͷ�����һ���������ɴ��ICMP����ġ�
	int			(*output)(struct sk_buff*);//��ͨ�õ����������������������������������ʵ����������������̣���˴��ڽ϶��У����
	                                       //��������ȷ�����ĵ��������˸ú������������Դ�����⣬��Ҫ��neigh_ops->output��
	                                       //neighbour->output()����
	int			(*connected_output)(struct sk_buff*);//��ȷ���ھӿɵ���ʱ����״̬ΪNUD_CONNECTEDʱʹ�õ��������.���������������Ҫ
													 //����Ϣ���Ѿ߱�����˸ú���ֻ�Ǽ򵥵���Ӷ����ײ���Ҳ��˱�output()��Ķࡣ
	int			(*hh_output)(struct sk_buff*);//�ѻ����˶����ײ��������ʹ�õ��������
	int			(*queue_xmit)(struct sk_buff*);//ʵ���ϣ����ϼ����������������hh_output�⣬���������������ݰ���ֻ����׼���ö����ײ�
	                                           //֮�󣬵���queue_xmit�ӿڡ�
};

/*
 *pneigh_entry�ṹʵ������������������������ֻ�кͽṹ�еĽ����豸�Լ�Ŀ���ַ��ƥ����ܴ�������pneigh_entryʵ�����洢��
 *�ھӱ�phash_bucketsɢ�б��У���֮Ϊ�������ͨ��ip neigh add proxy�������
*/
struct pneigh_entry
{
	struct pneigh_entry	*next;//��pneigh_entry�ṹʵ�����ӵ�phash_bucketsɢ�б��һ��Ͱ��
#ifdef CONFIG_NET_NS
	struct net		*net;
#endif
	struct net_device	*dev;//ͨ���������豸���յ���ARP�����Ĳ��ܴ���
	u8			flags;//NTF_PROXY������ֱ�־����ip�����ڴ�����ھ�ʱ����Ӵ˱�־��ip neigh add proxy 10.0.0.4 dev eth0
	u8			key[0];//�洢����Э���ַ���洢�ռ����neigh_table�ṹ��key_len�ֶη��䣬ֻ��Ŀ�ĵ�ַ�͸�����Э���ַ�����arp����
	                   //���Ĳ��ܴ���
};

/*
 *	neighbour table manipulation �ھӱ����
 *  ����һ���ھ�Э��Ĳ��������ܺ������Լ��ھ���ɢ�б�ÿ���ھ�Э�鶼�иýṹ��һ��ʵ�����ں��е�arp_tbl����ARP��ַ����Э����ھӱ�ṹ��
 *  ����ʵ�������뵽һ����̬����neigh_tablesָ���һ��ȫ�ֱ��У�
 *  ����neigh_table_lock����������������ֻ����ȫ�ֱ�������ԣ������Ա���ÿ����Ŀ�����ݽ��б���.
 */
struct neigh_table
{//�ھӱ�ṹ
	struct neigh_table	*next;//ָ������е���һ���ھӱ��������г���ARP��arp_tbl������IPV6T��DECNEʵ��nd_tbl��dn_neigh_table��
	int			family;//��ַ�壬ARPΪAF_INET
	int			entry_size;//�ھ���ṹ�Ĵ�С����arp_tbl��˵����ʼ��Ϊsizeof(neighbour)+4,
	                       //������Ϊ��ARP��neighbour��������һ����Ա�㳤����primary_key��ʵ��ָ��һ��ipv4��ַ��4
	int			key_len;//IP��ַ���ȣ���Ϊipv4��ΪIP��ַ�����Ϊ4
	__u32			(*hash)(const void *pkey, const struct net_device *);//��ϣ����ָ�룬���������ϣֵ,arp��Ϊarp_hash()
	int			(*constructor)(struct neighbour *);//�����ھӽṹ�ĺ���ָ��,��arp��Ϊarp_constructor�����ھӱ��ִ�������neigh_create����
	int			(*pconstructor)(struct pneigh_entry *);//IPv6ʹ�õĴ�������ָ��
	void			(*pdestructor)(struct pneigh_entry *);//IPv6ʹ�õ��ͷź���ָ��
	void			(*proxy_redo)(struct sk_buff *skb);//������ָ�룬����������neigh_table->queue��������еĴ���ARP���ġ�
	char			*id;//Э��������ΪID����������neighbour�ṹʵ���Ļ�������ַ�����arp_tbl�ĸ��ֶ�Ϊ"arp_cache"
	struct neigh_parms	parms;//�ھӲ����ṹ,�洢һЩ��Э����صĿɵ��ڲ��������ش���ʱʱ�䡢proxy_queue���г��ȵ�
	/* HACK. gc_* shoul follow parms without a gap! */
	int			gc_interval;//�������մ����ھ���ļ��ʱ�䣬Ĭ��ֵΪ30s
	int			gc_thresh1;//����������Ҫ���ֶ������ھ����������е��ھ��������ڸ�ֵ������ִ���������գ�arp_tbl����Ϊ128
	int			gc_thresh2;//�����е���ֵ(�����ޣ��������ջ��������ڻ���ǰ���ֻ����е��ھ������ֵ5s)��arp_tbl����Ϊ512
	int			gc_thresh3;//���������ֵ(Ӳ����),һ��������ʵ�ʵ��ھ�����������ֵ��ִ���������գ�arp_tbl����Ϊ1024
	unsigned long		last_flush;//�������ʱ�䣬��¼���һ�ε���neigh_forced_gc()ǿ��ˢ���ھӱ��ʱ�䣬������Ϊ�Ƿ�����������յ��ж�����
	struct delayed_work	gc_work;//�������ն�ʱ��
	struct timer_list 	proxy_timer;//����ʱ��������proxy_queue���еĶ�ʱ������proxy_queue����Ϊ��ʱ����һ��arp���ļ�����оͻ�����
	                                //�ö�ʱ�����ö�ʱ����neigh_table_init()�г�ʼ������������Ϊneigh_proxy_process().
	struct sk_buff_head	proxy_queue;//�������,���ڽ��յ�����Ҫ���д����ARP���ģ����Ƚ��仺�浽proxy_queue�����У��ڶ�ʱ��������
	                                //���ڶ�����д���
	atomic_t		entries;//���������ھӽṹ����������neigh_alloc()��������neigh_destroy()�ͷ��ھ���ʱ����
	rwlock_t		lock;//��д��������neigh_lookup()ֻ��Ҫ���ھӱ���neigh_periodic_timer()����Ҫ��д�ھӱ�
	unsigned long		last_rand;//�������ʱ�䣬���ڼ�¼neigh_parms�ṹ��reachable_time��Ա���һ�α����µ�ʱ��
	struct kmem_cache		*kmem_cachep;//���ڷ����ھӽṹ�ĸ��ٻ���
	struct neigh_statistics	*stats;//�ھ�ͳ�ƽṹ���й��ھӱ����ھ���ĸ���ͳ������
	struct neighbour	**hash_buckets;//�ھӽṹ�Ĺ�ϣͰ������ھ���������ɢ�б��������ɶ�̬����
	unsigned int		hash_mask;//��ϣͰ�ĳ��ȣ��ھ�ɢ�б�Ͱ����1���Է�����������ؼ���
	__u32			hash_rnd;//�������������hash_bucketsɢ�б�����ʱ����ؼ��֣������ܵ�ARP����
	struct pneigh_entry	**phash_buckets;//����IP��ַ�Ķ���(Ŀ�Ĵ���)����neigh_table_no_netlink()����ɳ�ʼ��
};

/* flags for neigh_update() */
//ָ��ǰ��L2��ַ���Ա�lladdr���ǡ������͸ı�ʹ�������ʶ������replace��add���Э��������ʹ�������ʶ����һ��L2��ַ����һ����С�����ڡ�
#define NEIGH_UPDATE_F_OVERRIDE			0x00000001
//�������������ṩ����·���ַlladdr�뵱ǰ��֪���ھ�neigh->ha����·���ַ��ͬ����ô�����ַ���ǿ��ɵ�(Ҳ����˵���ھӵ�״̬ת�Ƶ�NUD_STATE,
//�Ա�����ɵ�������֤)��
#define NEIGH_UPDATE_F_WEAK_OVERRIDE		0x00000002
//��ʶIPV6 NTF_ROUTER��ʶ���Ա����ǡ�
#define NEIGH_UPDATE_F_OVERRIDE_ISROUTER	0x00000004
//��ʶ����ھ��Ǹ�·�����������ʶ���ڳ�ʼ��neighbour->flags�е�ipv6��ʶNTF_ROUTER.
#define NEIGH_UPDATE_F_ISROUTER			0x40000000
//�����Ըı䡣��˼��˵�ı������û��ռ����
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
* ֻ�д˺����ŵ���ʵ��ִ��ɾ������ĺ���neigh_destroy��ÿ�ζ�һ���ṹ�������ͷź󣬾͵����Դ�neigh_release����
* �����Ļ��������ü�������1�������ü�������Ϊ0ʱ��neigh_release�͵���neigh_destroy����������ɾ���ýṹ.
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
 neigh_event_send()���ڼ���ھ���״̬�Ƿ���Ч������ھ���״̬ΪNUD_CONNECTED��NUD_DELAY��NUD_PROBE��
 ����ֱ�ӷ��ͣ���˷���0��ʾ��Ч���������__neigh_event_send()����һ����⣬�����Ч��������ġ�

 * ����������У������ھӽṹ���´����ģ�������Ҫ�ر�ע��:����״̬������ΪNUD_NONE��ʼ״̬(neigh_alloc()����),
 * �������½����ھӽṹ����neigh_evnt_send()������δ���
 * neigh_event_send -> __neigh_event_send
 * ֻ����nud_state��NUD_NONE, NUD_STALE, NUD_INCOMPLETE״̬ʱ�������
*/
static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	neigh->used = jiffies;//���ȼ�¼��ǰ��ʹ��ʱ��
	//����ھӽṹ�Ƿ������ӡ��ӳ١�̽��״̬
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);//��ʱ�ھӽṹΪ����״̬�����ת��˺���
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
 * �ú�����neigh_lookup������������ʧ�ܺ͸ú��������������������create��ʶʱ���ú�����ʹ��neigh_create����������һ��neighbour�
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
 * �ú���ʹ��neigh_lookup�������鿴Ҫ���ҵ��ھ����Ƿ���ڣ����ҵ�����ʧ��ʱ�����Ǵ���һ���µ�neighbourʵ����
 * ���˲���Ҫ����creat��ʶ�⣬�ú��������Ϻ�__neigh_lookup������ͬ��
 * ��һ������:�ھӱ�ṹarp_tbl
 * �ڶ�������:·�����ص�ַ
 * ����������:�����豸
*/
static inline struct neighbour *
__neigh_lookup_errno(struct neigh_table *tbl, const void *pkey,
  struct net_device *dev)
{
	/*������һ��ip��ַ�����dev���Ҷ�Ӧ���ھӱ��������ҵ�(֮ǰ���ҹ�)��ֱ�ӷ���*/
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n)//�ҵ����ھӽṹ�ͷ��ظ���һ������
		return n;

	
	return neigh_create(tbl, pkey, dev);//���û�в��ҵ��򴴽���Ӧ���ھӱ���
}

struct neighbour_cb {
	unsigned long sched_next;
	unsigned int flags;
};

#define LOCALLY_ENQUEUED 0x1

#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)

#endif
