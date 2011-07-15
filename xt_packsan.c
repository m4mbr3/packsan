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
#include <linux/gfp.h>
/* This Function is used for comparing two strings passed by parameter

   return: an int = 1 if the two strings are equal
	   -1 if the two strings are different
   
   we use it for checking the name of table into check entry function

*/
int str_cmp(char* s1, char* s2)
{
	__u32* i =(__u32*) kmalloc(sizeof(__u32),GFP_KERNEL);
	i=0;
	while(s1[*i] == s2[i] && s1[*i] != '\0' && s2[*i] != '\0') *i++;
	if (s1[*i] == '\0' && s2[*i] == '\0')
		{
			kfree(i);
			return 1;
		}
	else
		{
			kfree(i);
			return -1;
		}
}

/* This Function is called when in a new rule there is "-m packsan" 

   return: an int < 0 if the rule is  not correct
	   0 if it is good

   xt_matchk_param: is defined in /include/linux/netfilter/x_tables.h 
	   check it for more info about xt_matchk_param
   
   Our checkentry function check if the format of rule is `iptables -A (INPUT|POSTROUTING) -t mangle  -m packsan`
*/
static int packsan_mt_check (const struct  xt_mtchk_param *par)
{
	const struct xt_packsan_mtinfo *info = par->matchinfo;
	
	
	pr_info("Added a rule with -m packsan in the %s table; this rule is "
		"reachable through hooks 0x%x\n",
		par-> table, par-> hook_mask);
	
	if (!(par->hook_mask & (XT_PACKSAN_LOCAL_IN | XT_PACKSAN_POST_ROUTING))) {
		pr_info("Noone hook selected!!! \n");
		return -EINVAL;
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
