#ifndef XT_PACKSAN_H_
#define XT_PACKSAN_H_
#include "xt_packsan.h"
#endif /* XT_PACKSAN_H_ */

//#include <linux/module.h>
//#include <linux/kernel.h>
//#include <linux/netfilter.h>
//#include <linux/inet.h>
//#include <linux/ip.h>
//#include <linux/in.h>
//#include <linux/tcp.h>
//#include <linux/udp.h>
//#include <linux/skbuff.h>
//#include <linux/netfilter/xt_string.h>
//#include <net/checksum.h>
//#include <net/tcp.h>
//#include <asm/checksum.h>

// GENERIC LIBRARIES (for both match and target)
#ifndef NETFILTER_H_
#define NETFILTER_H_
#include <linux/netfilter.h>
#endif /* NETFILTER_H_ */

#ifndef X_TABLES_H_
#define X_TABLES_H_
#include <linux/netfilter/x_tables.h>
#endif /* X_TABLES_H */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>


//distance of data offset field in tcp header
#ifndef DOFF_DISTANCE
#define DOFF_DISTANCE 12
#endif
//udp header length
#ifndef UDP_HDR_LEN
#define UDP_HDR_LEN 8
#endif

//do you want to have a VERBOSE log of the module activity? set it to non-zero
#ifndef LOG
#define LOG 1
#endif

struct ps_match_occurrence;
typedef struct ps_match_occurrence ps_match;
extern const unsigned int strings_number;
extern const char* strings[];
extern const char* var_len_replacements[];
extern const char* const_len_replacements[];
extern void dealloc_all_list(ps_match*);
extern ps_match* KMP_Matcher(char*, int, const char*, int, unsigned int, int*);


/* This Function is called when in a new rule there is "-m packsan" 

   return: an int < 0 if the rule is  not correct
	   0 if it is good

   xt_matchk_param: is defined in /include/linux/netfilter/x_tables.h 
	   check it for more info about xt_matchk_param
   
   Our checkentry function check if the format of rule is `iptables -A (INPUT|POSTROUTING) -t mangle  -m packsan`
*/
static int packsan_mt_check (const struct  xt_mtchk_param *par)
{
	  pr_info("\n*************PACKSAN MATCHER*****************\n");
	  pr_info("Added a rule with -m packsan in the %s table \n ",
		par-> table);
	  if (!(par->hook_mask & ( XT_PACKSAN_LOCAL_IN | XT_PACKSAN_POST_ROUTING ))) {
		  pr_info("Noone hook selected!!! \n");
		  return -EINVAL;
	  }
	  if( strcmp(par->table, "mangle") == -1){
		  pr_info("The inserted table value isn't  mangle!!!");
		  return -EINVAL;
	  }
	  pr_info("\nThe new rule has been inserted!!!\n");
	  pr_info("\n**********Enjoy it********************\n");
	  return 1;
}

static void packsan_mt_destroy(const struct xt_mtdtor_param *par)
{	
	pr_info ("\n************PACKSAN MATCHER***************\n");
	pr_info ("\nYou have Destroyed one rule with -m packsan\n");
	pr_info ("\n************Goodbye********************\n");
}


static bool packsan_mt(const struct sk_buff *skb, struct xt_action_param *par)
{	
	// length of layer 4 payload
	unsigned int l4_payload_len;
	// beginning of layer 4 payload
	char *l4_payload_start;
	//matches number and length
	int matches=0;
	int match_len;
	
	//index is only for various cycles
	int index;
	
	//pointer to ip header inside skb
	struct iphdr *ip_head = ip_hdr(skb);
	//pointer to tcp header inside skb
	struct tcphdr *tcp_head = (struct tcphdr *)(skb->data + ip_hdrlen(skb));
		
	//head of matches list
	ps_match* string_head=NULL;
	//transport header length
	unsigned int l4_hdr_len;
	//PROVA ALLOCAZIONE NUOVO SPAZIO
	//unsigned int headers_len, new_payload_len;
	
	if(ip_head->protocol == IPPROTO_TCP) {
		
		#ifdef LOG
		printk("TCP\n");
		#endif
		
		//TCP header length: the very problem is endianess: network data are big endian, x86 is little endian: mercy!
		// DOFF_DISTANCE = 12 is the distance from the beginning of the 4-bit field data offset,
		//containing the tcp header dimension in 32-bit words and other optional bits: all big endian for our pleasure!
		// the correct value is found via bit shifting (need only the left 4 bits) and multiply
		l4_hdr_len = ((*((__u8*)tcp_head+DOFF_DISTANCE)) >> 4)*4;
		
	}  else if(ip_head->protocol == IPPROTO_UDP) {
		
		#ifdef LOG
		printk("UDP\n");
		#endif
		
		l4_hdr_len = sizeof(struct udphdr);
		
	} else {
		
		//ICMP packet: out of the balls! cannot be modified
		return false;
	}

	//calculate the payload beginning address
	l4_payload_start = skb->data + ip_hdrlen(skb) + l4_hdr_len;
	
	//calculate the payload length
	l4_payload_len = (char*)skb->tail - (char*)l4_payload_start;
	
	#ifdef LOG
	printk("received packet\n");
	printk("l4 payload length is %d\n",l4_payload_len);
	//print the payload
	printk("packet payload is\n");
	for(index = 0; index < l4_payload_len; index++) {
		printk("%c",*(l4_payload_start+index));
	}
	printk("\n");
	#endif
	
	//find multiple strings
	for(index=0; index < strings_number; index++) {
		match_len = strlen(strings[index]);
		string_head = KMP_Matcher(l4_payload_start, l4_payload_len, strings[index], match_len, index, &matches);
		//update data length
		if(string_head != NULL) {
			  printk("packet matched\n");
			  dealloc_all_list(string_head);
			  return true;
		}
	}
	
	return false;

}

static struct xt_match packsan_mt4_reg __read_mostly = {
		.name			=	"packsan",
		.revision		=	0,
		.family		=	NFPROTO_IPV4,
		.match 		=	packsan_mt,
		.checkentry		=	packsan_mt_check,
		.destroy		=	packsan_mt_destroy,
		.matchsize 		=	sizeof(struct xt_packsan_mtinfo),
		.me			= 	THIS_MODULE,
	};
	
static int  __init packsan_mt_init (void)
{
	return xt_register_match(&packsan_mt4_reg);
}

static void __exit packsan_mt_exit(void)
{
	xt_unregister_match(&packsan_mt4_reg);
}


module_init(packsan_mt_init);
module_exit(packsan_mt_exit);


MODULE_AUTHOR("PACKSAN TEAM <packsanteam@gmail.com");
MODULE_DESCRIPTION("Xtables: Packet sanitizer, clean your packets from bad strings!!!");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_packsan");

