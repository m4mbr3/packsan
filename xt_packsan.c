#include "xt_packsan.h"
//#include "xt_packsan_util.h"

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <net/dsfield.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <linux/gfp.h>
#include "linux/textsearch.h"

inline static bool ps_look_and_replace(char *data_start, size_t data_len);

/* This Function is called when in a new rule there is "-m packsan" 

   return: an int < 0 if the rule is  not correct
	   0 if it is good

   xt_matchk_param: is defined in /include/linux/netfilter/x_tables.h 
	   check it for more info about xt_matchk_param
   
   Our checkentry function check if the format of rule is `iptables -A (INPUT|POSTROUTING) -t mangle  -m packsan`
*/
static int packsan_mt_check (const struct  xt_mtchk_param *par)
{
	//const struct xt_packsan_mtinfo *info = par->matchinfo;
	__u8* p= kmalloc(sizeof(__u8[8]),GFP_KERNEL);
	
	
	pr_info("Added a rule with -m packsan in the %s table; this rule is "
		"reachable through hooks 0x%x\n",
		par-> table, par-> hook_mask);
	
	if (!(par->hook_mask & ( XT_PACKSAN_LOCAL_IN | XT_PACKSAN_POST_ROUTING ))) {
		pr_info("Noone hook selected!!! \n");
		return -EINVAL;
	}
	
	p[0] =  'm';
	p[1] =  'a';
	p[2] =  'n';
	p[3] =  'g';
	p[4] =  'l';
	p[5] =  'e';
	p[6] =  '\0';
	if( strcmp(par->table, p) == -1){
		pr_info("The inserted table isn't  mangle!!!");
		kfree(p);
		return -EINVAL;
	}
	kfree(p);
	return 0;
}

static void packsan_mt_destroy(const struct xt_mtdtor_param *par)
{	
	const struct xt_packsan_mtinfo *info = par->matchinfo;
	pr_info ("Test for address %081X removed \n", info->src.ip);
}
static bool packsan_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	size_t data_len;
	char *data_start;
	/*
	const struct xt_packsan_mtinfo *info = par->matchinfo;
	const struct iphdr *iph = ip_hdr(skb);
	*/
	data_start = skb->data + ip_hdrlen(skb) + sizeof(struct tcphdr);
	data_len = skb->len - ip_hdrlen(skb) - sizeof(struct tcphdr);
	return ps_look_and_replace(data_start, data_len);
	//return true;

}

inline static bool ps_look_and_replace(char *data_start, size_t data_len) {
	bool result=false;
	char pattern[] = "ciao";
	struct ts_state state;
	struct ts_config *conf;
	int pos;
	conf = textsearch_prepare("bm", pattern, strlen(pattern), GFP_KERNEL, TS_AUTOLOAD);
	pos = textsearch_find_continuous(conf, &state, data_start, data_len);
	if (pos != UINT_MAX) {
		printk("found entry at %d\n", pos);
		result = true;
	}
	textsearch_destroy(conf);
	return result;
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
