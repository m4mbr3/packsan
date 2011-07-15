#include "xt_packsan.h"

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <net/dsfield.h>
#include <linux/skbuff.h>


static int packsan_mt_check (const struct  xt_mtchk_param *par)
{
	const struct xt_packsan_mtinfo *info = par->matchinfo;
	
	pr_info("Added a rule with -m ipaddr in the %s table; this rule is "
		"reachable through hooks 0x%x\n",
		par-> table, par-> hook_mask);
	
	if (!(info->flags & (XT_PACKSAN_SRC | XT_PACKSAN_DST))) {
		pr_info("not testing for anything \n");
		return -EINVAL;
	}
	if (ntohl(info->src.ip) == 0xDEADBEEF){
	/*this just for fun */
		pr_info("I'm sorry, Dave. I'm afraid I can't let you do that. \n");
		return -EPERM;
	}
	return 0;
}

static void packsan_mt_destroy(const struct xt_mtdtor_param *par)
{	
	const struct xt_packsan_mtinfo *info = par->matchinfo;
	pr_info ("Test for address %081X removed \n", info->src.ip);
}
static bool packsan_mt(const struct sk_buff *skb, const struct xt_action_param *par)
{

	const struct xt_packsan_mtinfo *info = par->matchinfo;
	const struct iphdr *iph = ip_hdr(skb);
	
	if (info->flags & XT_PACKSAN_SRC)
		if ((iph->saddr != info->src.ip) ^
			!!(info->flags & XT_PACKSAN_SRC_INV))
		{
			pr_notice("src IP - no match\n");
			return false;
		}
	if (info-> flags & XT_PACKSAN_DST)
		if ((iph->daddr != info-> dst.ip) ^
			!!(info->flags & XT_PACKSAN_DST_INV))
		{
			pr_notice("dst IP - no match\n");
			return false;
		}
	return true;

}
static struct xt_match packsan_mt4_reg __read_mostly = {
		.name		=	"packsan",
		.revision	=	0,
		.family		=	NFPROTO_IPV4,
		.match 		=	packsan_mt,
		.checkentry	=	packsan_mt_check,
		.destroy	=	packsan_mt_destroy,
		.matchsize 	=	sizeof(struct xt_packsan_mtinfo),
		.me		= 	THIS_MODULE,
	};
static int  __init packsan_mt_init (void)
{
	return xt_register_match(&packsan_mt4_reg);
}

static void __exit packsan_mt_exit(void)
{
	return xt_unregister_match(&packsan_mt4_reg);
}


module_init(packsan_mt_init);
module_exit(packsan_mt_exit);


MODULE_AUTHOR("PACKSAN TEAM");
MODULE_DESCRIPTION("Xtables: Packet sanitizer, clean your packets from bad strings!!!");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_packsan");
