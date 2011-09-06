#ifndef XT_PACKSAN_H_
#define XT_PACKSAN_H_
#include "../xt_packsan.h"
#endif /* XT_PACKSAN_H_ */

//#include <linux/module.h>
//#include <linux/kernel.h>
//#include <linux/inet.h>
//#include <linux/ip.h>
//#include <linux/in.h>
//#include <linux/tcp.h>
//#include <linux/udp.h>
//#include <linux/skbuff.h>
//#include <linux/netfilter/xt_string.h>

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


#include <net/checksum.h>
#include <net/tcp.h>
#include <asm/checksum.h>

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

//if you want to trick Linux TCP socket and change expected SYN (not available at the moment ...)
/*
#ifndef TCP_TRICK
#define TCP_TRICK 1
#endif
*/


struct ps_match_occurrence;
typedef struct ps_match_occurrence ps_match;
extern const unsigned int strings_number;
extern const char* strings[]; 
extern const char* var_len_replacements[];
extern const char* const_len_replacements[];
extern void dealloc_all_list(ps_match*);
extern ps_match* KMP_Matcher(char*, int, const char*, int, unsigned int, int*);

const char* *replacements;

void inline varlen_replace(char* original, unsigned int original_len, char* new, ps_match* matches) {
	
	//original_index stores the actual position in the old area, new_index in the new one
	int original_index=matches->position, new_index=0,index;
	
	do {
		
		//copy unmodified data
		for(;original_index < matches->position; original_index++) {
			*(new + new_index)=*(original + original_index);
			new_index++;
		}
		
		//copy the string to replace
		for(index=0; index < strlen(replacements[matches->string_index]); index++) {
			*(new + new_index)=*(replacements[matches->string_index]+index);
			new_index++;
		}
		
		original_index += strlen(strings[matches->string_index]);
		
		matches = matches->next;
		
	} while(matches != NULL);
	
	//cycle to copy the last part of unmodified data (if any)
	for(; original_index < original_len; original_index++) {
			*(new + new_index)=*(original + original_index);
			new_index++;
	}
	
}


static ps_match* insert_by_position(ps_match* head, ps_match* string_head) {
	
	ps_match* old = NULL; 
	ps_match* last = head;
	ps_match* string_next;
	
	while(string_head != NULL) {
		//copia temporanea del prossimo in string_next
		string_next = string_head->next;
		//trovo il punto di inserimento nella lista generale: o la fine o quello prima della posizione maggiore
		while((last != NULL) && (last->position < string_head->position)) {
			old = last;
			last = last->next;
		}
		//ripunto dopo l'inserimento
		string_head->next = last;
		if(old == NULL) {
			//la lista non è stata scorsa: string_head è la nuova testa
			head = string_head;
		} else {
			//la lista è stata scorsa: redirezione dei puntatori
			old->next = string_head;
		}
		//l'ultimo match visitato è proprio string_head
		old = string_head;
		//avanti col prossimo match
		string_head = string_next;
	}
	return head;
}

static unsigned int packsan_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	// length of layer 4 payload
	unsigned int l4_payload_len;
	// beginning of layer 4 payload
	char *l4_payload_start;
	//pointer for the resized skb data area
	char* new_skb_data;

	//matches number and length
	int matches=0, match_len;
	
	//index is only for various cycles
	int index;
	
	//pointer to ip header inside skb
	struct iphdr *ip_head = ip_hdr(skb);
	//pointer to tcp header inside skb
	struct tcphdr *tcp_head = (struct tcphdr *)(skb->data + ip_hdrlen(skb));
	//pointer to udp header inside skb
	struct udphdr *udp_head = (struct udphdr *)(tcp_head);
	//transport area length: header + payload
	__u16 l4_len = (char*)skb->tail - (char*)tcp_head;
	//head of matches list
	ps_match* head = NULL;
	ps_match* string_head=NULL;
	//transport header length
	__u16 l4_hdr_len, l3_hdr_len;
	__s16 payload_diff;
	//various lengths
	__u16 tail_space, headers_len, new_payload_len;

	
	
	if(ip_head->protocol == IPPROTO_TCP) {
		
		#ifdef LOG
		printk("TCP\n");
		#endif
		
		//TCP header length: the very problem is endianess: network data are big endian, x86 is little endian: mercy!
		// DOFF_DISTANCE = 12 is the distance from the beginning of the 4-bit field data offset,
		//containing the tcp header dimension in 32-bit words and other optional bits: all big endian for our pleasure!
		// the correct value is found via bit shifting (need only the left 4 bits) and multiply
		l4_hdr_len = ((*((__u8*)tcp_head+DOFF_DISTANCE)) >> 4)*4;
		replacements = const_len_replacements;
		
	}  else {
		
		#ifdef LOG
		printk("UDP\n");
		#endif
		
		l4_hdr_len = sizeof(struct udphdr);
		replacements = var_len_replacements;
		
	}
	
	//calculate the headers length
	l3_hdr_len = ip_hdrlen(skb);
	headers_len = l3_hdr_len + l4_hdr_len;
	
	//calculate the payload beginning address
	l4_payload_start = skb->data + headers_len;
	
	//calculate the payload length
	l4_payload_len = (char*)skb->tail - (char*)l4_payload_start;
	
	new_payload_len=l4_payload_len;
	
	//find multiple strings
	for(index=0; index < strings_number; index++) {
		matches = 0;
		match_len = strlen(strings[index]);
		string_head = KMP_Matcher(l4_payload_start, l4_payload_len, strings[index], match_len, index, &matches);
		//update data length
		if(string_head != NULL) {
			new_payload_len += (matches*(strlen(replacements[index]) - match_len));
			if(head == NULL) {
				//firstest match
				head = string_head;
			} else {
				//following match: lists merging
				head=insert_by_position(head, string_head);
			}
		}
	}
	
	#ifdef LOG
	printk("found something, ready for replacement!\n");
	string_head = head;
	do{
		printk("found occurrence at position %d\n",string_head->position);
		string_head = string_head->next;
	} while(string_head != NULL);
	#endif
	
	//payload_diff is the difference between new and old l4 payload
	payload_diff = new_payload_len - l4_payload_len;
	//from the end of payload to skb->end
	tail_space = (char*)(skb->end) - (char*)skb->tail;
	//skb_data_len += match_len;
	new_skb_data =  (char*)kmalloc(new_payload_len - head->position,GFP_ATOMIC);
	
	
	
	#ifdef LOG
	printk("headers length is %d\n",headers_len);
	printk("tail space is %d\n",tail_space);
	printk("payload difference space is %d\n",match_len);
	/*
	printk("old headers:\n");
	for(index=0; index < headers_len ; index++) {
		printk("%02x ",*(skb->data + index));
	}
	printk("\n");
	*/
	#endif
			
	//COPY DATA FROM OLD TO NEW SKB DATA AREA
	//copy and modify the text to the new area
	varlen_replace(l4_payload_start, l4_payload_len, new_skb_data, head);
			
	//resize the packet area
	if ((__s16)payload_diff > (__s16)tail_space) {
		pskb_expand_head(skb,0,match_len, GFP_ATOMIC);
		#ifdef LOG
		printk("DANGEROUS EXPANSION\n");
		#endif
	} else {
		skb->tail += match_len;
	}
	//must ALWAYS ne done, pskb_expand_head doesn't do by itself (bug? maybe ...)
	skb->len += payload_diff;
	
	//copy the changed text back to the packet
	memcpy(skb->data + headers_len + head->position, new_skb_data, new_payload_len - head->position);
	
	//deallocate the list
	dealloc_all_list(head);
	
	//release new data
	kfree(new_skb_data);
			
	#ifdef LOG
	//new payload
	
	#endif
	
	//UPDATE ALL HEADERS POINTERS
	ip_head = (struct iphdr *)(skb->data);
	l4_len += (__s16)payload_diff;
	
		
	if(ip_head->protocol == IPPROTO_TCP) {
		
		/*
		// mmmmh, can't trick Linux TCP socket and change expected SYN (at the moment ...)
		#ifdef TCP_TRICK
		if(skb->sk == NULL) {
			printk("sk is NULL\n");
		} else {
			printk("expected syn should be %02x",tcp_sk(skb->sk)->rcv_nxt);
		}
		//trick TCP ACK mechanism: decrement sequence number
		tcp_head->seq = htonl(ntohl(tcp_head->seq) - (__s32)payload_diff);
		#endif
		*/
					
		tcp_head = (struct tcphdr *)(skb->data + l3_hdr_len);
		
		//recalculate and store checksums
		tcp_head->check = 0;
		tcp_head->check = tcp_v4_check(l4_len, ip_head->saddr, ip_head->daddr, csum_partial((char *)tcp_head, l4_len, 0));
	} else {
		//update data length
		udp_head = (struct udphdr *)(skb->data + l3_hdr_len);
		udp_head->len = htons(l4_len);
		if(udp_head->check != 0) {
		//for UDP: checksum is recalculated only if needed
		udp_head->check = 0;
		udp_head->check = csum_tcpudp_magic(ip_head->saddr,ip_head->daddr,l4_len,IPPROTO_UDP,csum_partial((char *)udp_head, l4_len, 0));
		}
		printk("\n");
	}
	ip_head->tot_len = htons(l3_hdr_len + l4_len);
	ip_head->check = 0;
	ip_head->check = ip_fast_csum(ip_head, l3_hdr_len);
	
	#ifdef LOG
	printk("new packet:\n");
	for(index=0; index < new_payload_len + headers_len ; index++) {
		printk("%02x ",*(skb->data + index));
	}
	printk("\n");
	
	printk("new payload:\n");
	for(index=0; index < new_payload_len; index++) {
		printk("%c",*(skb->data + headers_len + index));
	}
	printk("\n");
	
	printk("new l4 length is  0x%d\n",l4_len);
	printk("IP header length is %d\n",l3_hdr_len);
	#endif

	return true;
}

static struct xt_target packsan_tg_reg __read_mostly = {
		.name 		= "PACKSAN",
		.revision		= 0,
		.family		= NFPROTO_IPV4,
		.table		= "mangle",
		.hooks		= ( 1 << NF_INET_LOCAL_IN )|( 1 << NF_INET_POST_ROUTING ),
		.target		= packsan_tg4,
		.targetsize 	= XT_ALIGN(0),
		.me		= THIS_MODULE,
	};		



static int __init packsan_tg_init(void)
{
	return  xt_register_target(&packsan_tg_reg);
}
static void __exit packsan_tg_exit(void)
{
 	xt_unregister_target(&packsan_tg_reg);
}

module_init(packsan_tg_init);
module_exit(packsan_tg_exit);

MODULE_AUTHOR ("PACKSAN TEAM:<packsanteam@gmail.com>");
MODULE_DESCRIPTION("Xtables: Packet Sanitizer, clean your packets from bad strings!!!");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_PACKSAN");

