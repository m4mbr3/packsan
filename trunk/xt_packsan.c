#include "xt_packsan.h"
//#include "xt_packsan_util.h"

#include <linux/module.h>
//#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/inet.h>
#include <linux/ip.h>
//#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/netfilter/x_tables.h>
//#include <net/dsfield.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_string.h>
#include <net/checksum.h>
#include <net/tcp.h>

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


/*
NO, NON E' EFFICIENTE NE' FIGO PER UN CA..O, COME KNUTH-MORRIS-PRAT O BOYER MOORE, MA ALMENO FUNZIONA ...
diversamente da

textsearch_prepare("kmp", pattern, strlen(pattern), GFP_KERNEL, TS_AUTOLOAD);
* 
* non supporta i patterns ...

*/
static unsigned int dummy_search(char *text, unsigned int len, char *pattern, unsigned int pattern_len) {
	unsigned int text_index = 0;
	unsigned int pat_index = 0;
	bool found=false;
	
	for(text_index=0; (text_index < len) && (pat_index < pattern_len) ; text_index++) {
		//printk(" %c - %c |",*(text + text_index),*(pattern + pat_index));
		if(*(text + text_index) == *(pattern + pat_index)) {
			pat_index++;
			found=true;
		} else {
			//printk("\n differ\n");
			text_index-=pat_index;
			//text_index++;
			pat_index=0;
			found=false;
		}
	}
	//printk("\n");
	if(found==true) {
		//printk("true!\n");
		return text_index-pat_index;
	} else {
		return UINT_MAX;
	}
}

void inline replace(char* original, char* replacement, unsigned int rep_len) {
	int index;
	
	for(index=0; index < rep_len; index++) {
		*(original + index)=*(replacement + index);
	}
}

static bool packsan_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	unsigned int data_len;
	char *data_start;
	int index;
	unsigned int rep_len;
	char pattern[] = "ciao";
	char replacement[] = "CIAO";
	unsigned int position;
	struct iphdr *ip_head = ip_hdr(skb);
	struct tcphdr *tcp_head = (struct tcphdr *)(skb->data + ip_hdrlen(skb));
	//il problema è la endianess ...
	__u8 tcpHdrLen = ((*((__u8*)tcp_head+12)) >> 4)*4;
	unsigned int tcplen = (char*)skb->tail - (char*)tcp_head;
	
	
	//printk("ip header len is %d\n",ip_hdrlen(skb));
	//printk("tcp header len is %d\n",tcpHdrLen);
		
	//calculate the payload beginning address
	data_start = skb->data + ip_hdrlen(skb) + tcpHdrLen;
	
	//calculate the payload length
	data_len = (char*)skb->tail - (char*)data_start;
	printk("received packet\n");
	printk("length is %d\n",data_len);
	
	//check the string and print the payload
	rep_len = strlen(pattern);
	position = dummy_search(data_start,data_len,pattern,rep_len);
	for(index = 0; index < data_len; index++) {
			printk("%c",*(data_start+index));
	}
	//printk("pos is %d\n",position);
	
	//if matches, replace and recalculate checksums
	if(position != UINT_MAX) {
		printk("found matching entry: ");
		for(index = 0; index < data_len; index++) {
			printk("%c",*(data_start + position + index));
		}
		replace(data_start + position, replacement,rep_len);
		//verify replacement
		for(index = 0; index < data_len; index++) {
			printk("%c",*(data_start + position + index));
		}
		//checksums
		tcp_head->check = 0;
		tcp_head->check = tcp_v4_check(tcplen, ip_head->saddr, ip_head->daddr, csum_partial((char *)tcp_head, tcplen, 0));
		ip_head->check = 0;
		ip_head->check = ip_fast_csum(ip_head, (char*)skb->tail - (char*)ip_head);
		
		printk("\n");
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
