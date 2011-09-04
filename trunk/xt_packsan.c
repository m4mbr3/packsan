#include "xt_packsan.h"
#include "xt_packsan_util.h"
//typedef struct match_occurrence ps_match;

/* This Function is called when in a new rule there is "-m packsan" 

   return: an int < 0 if the rule is  not correct
	   0 if it is good

   xt_matchk_param: is defined in /include/linux/netfilter/x_tables.h 
	   check it for more info about xt_matchk_param
   
   Our checkentry function check if the format of rule is `iptables -A (INPUT|POSTROUTING) -t mangle  -m packsan`
*/
static int packsan_mt_check (const struct  xt_mtchk_param *par)
{
	__u8* p= kmalloc(sizeof(__u8[8]),GFP_KERNEL);
	  p[0] =  'm';
	  p[1] =  'a';
	  p[2] =  'n';
	  p[3] =  'g';
	  p[4] =  'l';
	  p[5] =  'e';
	  p[6] =  '\0';
	  pr_info("Added a rule with -m packsan in the %s table \n ",
		par-> table);
	  if (!(par->hook_mask & ( XT_PACKSAN_LOCAL_IN | XT_PACKSAN_POST_ROUTING ))) {
		  pr_info("Noone hook selected!!! \n");
		  return -EINVAL;
	  }
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


static bool packsan_mt(struct sk_buff *skb, struct xt_action_param *par)
{
	
	// length of layer 4 payload
	unsigned int l4_payload_len;
	// beginning of layer 4 payload
	char *l4_payload_start;
	
	
	
	//matches number and length
	int matches=0, match_len;
	
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
	unsigned int headers_len, new_payload_len;
	
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
		return true;
	}
	//calculate the headers length
	headers_len = ip_hdrlen(skb) + l4_hdr_len;
	
	//calculate the payload beginning address
	l4_payload_start = skb->data + headers_len;
	
	//calculate the payload length
	l4_payload_len = (char*)skb->tail - (char*)l4_payload_start;
	
	#ifdef LOG
	printk("received packet\n");
	printk("length is %d\n",l4_payload_len);
	//print the payload
	for(index = 0; index < l4_payload_len; index++) {
		printk("%c",*(l4_payload_start+index));
	}
	printk("\n");
	#endif
	
	new_payload_len=l4_payload_len;
	
	//find multiple strings
	for(index=0; index < STRINGS; index++) {
		matches = 0;
		match_len = strlen(strings[index]);
		string_head = KMP_Matcher(l4_payload_start, l4_payload_len, strings[index], match_len, index, &matches);
		//update data length
		if(string_head != NULL) {
			  printk("1 packet matched\n");
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

