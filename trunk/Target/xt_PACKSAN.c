#include <linux/netfilter/x_tables.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/udp.h>

static unsigned int packsan_tg4(struct sk_buff *skb,
		const struct xt_target_param *par)
{
	

}
static struct xt_target packsan_tg_reg __read_mostly = {
		.name 		= "PACKSAN",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.table		= "mangle",
		.hooks		= ( 1 << NF_INET_LOCAL_IN )|
				  ( 1 << NF_INET_POST_ROUTING ),
		.target		= packsan_tg4,
		.targetsize 	= XT_ALIGN(0),
		.me		= THIS_MODULE,
	};		



static int __init packsan_tg_init(void)
{
	return xtables_register_target(&packsan_tg_reg);
}
static void __exit packsan_tg_exit(void)
{
 	xtables_unregister_target(&packsan_tg_reg);
}

module_init(packsan_tg_init);
module_exit(packsan_tg_exit);

MODULE_AUTHOR ("PACKSAN TEAM");
MODULE_DESCRIPTION("Xtables: Packet Sanitizer, clean your packets from bad strings!!!");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_PACKSAN");

