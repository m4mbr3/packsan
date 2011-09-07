/*! \file xt_packsan.c
 * \brief The match for iptables.
 * 
 * This file contains the packsan match, with the matching function and 
 * the data structures needed to load it through iptables.
 * 
 */


#include "xt_packsan.h"
#ifndef X_TABLES_H_
#define X_TABLES_H_
#include <linux/netfilter/x_tables.h>
#endif /* X_TABLES_H_ */



/*! \def DOFF_DISTANCE
 * Distance of data offset field in tcp header
 */
#define DOFF_DISTANCE 12

/*! \def UDP_HDR_LEN
 * UDP header length: it's constant.
 */
#define UDP_HDR_LEN 8

/*! \def LOG
 * \brief Set it to 1 to log the activity.
 * 
 * Do you want to have a VERBOSE log of the module activity? set it to non-zero.
 */
#ifndef LOG
#define LOG 1
#endif

/*! \defgroup Extern_Declarations External members, contained in xt_packsan.h and in common.
 */
struct ps_match_occurrence;
struct xt_action_param;
//typedef struct ps_match_occurrence ps_match;
extern const unsigned int strings_number; /*!< \ingroup Extern_Declarations Number of the strings to search for inside the packet */
extern const char* strings[]; /*!< \ingroup Extern_Declarations Strings to search for inside the packet */
extern const char* var_len_replacements[]; /*!< \ingroup Extern_Declarations Strings with different length from corresponding ones in strings: for UDP substitution */
extern const char* const_len_replacements[]; /*!< \ingroup Extern_Declarations Strings with same length of corresponding ones in string: for TCP matches */
extern void dealloc_all_list(ps_match*); /*!< \ingroup Extern_Declarations Function to deallocate the list of matches */
extern ps_match* KMP_Matcher(char*, int, const char*, int, unsigned int, int*); /*!< \ingroup Extern_Declarations KMP matcher */


/* This Function is called when in a new rule there is "-m packsan" 

   return: an int < 0 if the rule is  not correct
	   0 if it is good

   xt_matchk_param: is defined in /include/linux/netfilter/x_tables.h 
	   check it for more info about xt_matchk_param
   
   Our checkentry function check if the format of rule is `iptables -A (INPUT|POSTROUTING) -t mangle  -m packsan`
*/

/*! \fn int packsan_mt_check (const struct  xt_mtchk_param *par)
 * 
 * \brief Function to check the insertion table and hook in iptables.
 * 
 * This function checks whether the module is being inserted into mangle table of INPUT or POSTROUTING hooks.
 * This means that the command must start with
 * 
 * `iptables -A (INPUT|POSTROUTING) -t mangle  -m packsan`
 * 
 * \param par the parameters given to iptables
 * \return 0 if the insertion conditions are met, -EINVAL otherwise
 */

static int packsan_mt_check (const struct xt_mtchk_param *par)
{
	  pr_info("\n*************PACKSAN MATCHER*****************\n");
	  pr_info("Added a rule with -m packsan in the %s table \n ",
		par-> table);
	  if (!(par->hook_mask & ( XT_PACKSAN_LOCAL_IN | XT_PACKSAN_POST_ROUTING ))) {
		  pr_info("No hook selected!!! \n");
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


/*! \fn void packsan_mt_destroy(const struct xt_mtdtor_param *par)
 * 
 * \brief Function called on module removal.
 * 
 * This function performs all the actions needed before the module removal.
 * At the present time, it just notifies via the kernel log.
 * 
 * \param par structure that describes some details about the module invocation
 */

static void packsan_mt_destroy(const struct xt_mtdtor_param *par)
{	
	pr_info ("\n************PACKSAN MATCHER***************\n");
	pr_info ("\nYou have Destroyed one rule with -m packsan\n");
	pr_info ("\n************Goodbye********************\n");
}

/*! \fn bool packsan_mt(const struct sk_buff *skb, struct xt_action_param *par)
 * \brief The matching function.
 * 
 * This function looks for an occurence of a string of string array inside the packet: if one is found the packet is matched.
 * 
 * \param skb the struct sk_buff that stores the packet information and data
 * \param par a struct that has some additional information about the packet (I/O devices, fragments ... see docs)
 * \return true if the packet matches at least one string, false otherwise
 */

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

/*! \var struct xt_match packsan_mt4_reg
 * \brief this struct contains all the information to register the module inside iptables.
 */

static struct xt_match packsan_mt4_reg __read_mostly = {
		.name			=	"packsan",
		.revision		=	0,
		.family		=	NFPROTO_IPV4,
		.match 		=	packsan_mt,
		.checkentry		=	packsan_mt_check,
		.destroy		=	packsan_mt_destroy,
		.matchsize 		=	0,
		.me			= 	THIS_MODULE,
	};
	
/*! \fn int  __init packsan_mt_init (void)
 * \brief Function called at the module insertion to register the matcher.
 * 
 * It registers the matcher by calling a proper function of iptables and passing it packsan_mt4_reg.
 * 
 * \return 0 if the insertion succeeds, non - 0 otherwise
 */	
	
static int  __init packsan_mt_init (void)
{
	return xt_register_match(&packsan_mt4_reg);
}

/*! \fn void __exit packsan_mt_exit(void)
 * \brief Function called at the module extraction to unregister the matcher.
 * 
 * It unregisters the matcher by calling a proper function of iptables and passing it packsan_mt4_reg.
 * 
 * \return 0 if the extraction succeeds, non - 0 otherwise
 */

static void __exit packsan_mt_exit(void)
{
	xt_unregister_match(&packsan_mt4_reg);
}

module_init(packsan_mt_init); /*!< Linux macro to indicate which function to call at insertion. */

module_exit(packsan_mt_exit); /*!< Linux macro to indicate which function to call at extraction. */

/*! \defgroup Module_info
 * \brief Linux macros to register basic module information.
 */
MODULE_AUTHOR("PACKSAN TEAM <packsanteam@gmail.com"); /*!< \ingroup Module_info */
MODULE_DESCRIPTION("Xtables: Packet sanitizer, clean your packets from bad strings!!!"); /*!< \ingroup Module_info */
MODULE_LICENSE("GPL"); /*!< \ingroup Module_info */
MODULE_ALIAS("ipt_packsan"); /*!< \ingroup Module_info */
