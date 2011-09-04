#include <linux/netfilter/x_tables.h>
#include "../xt_packsan_util.h"
static unsigned int packsan_tg4(struct sk_buff *skb,
		const struct xt_target_param *par)
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
	int index, payload_diff;
	
	//pointer to ip header inside skb
	struct iphdr *ip_head = ip_hdr(skb);
	//pointer to tcp header inside skb
	struct tcphdr *tcp_head = (struct tcphdr *)(skb->data + ip_hdrlen(skb));
	//pointer to udp header inside skb
	struct udphdr *udp_head = (struct udphdr *)(tcp_head);
	//transport area length: header + payload
	unsigned int l4_len = (char*)skb->tail - (char*)tcp_head;
	
	//head of matches list
	ps_match* head = NULL;
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
			new_payload_len += (matches*(strlen(replacements[index]) - match_len));
			if(head == NULL) {
				//primissimo match
				head = string_head;
			} else {
				//match successivo: merge delle liste
				head=insert_by_position(head, string_head);
			}
		}
	}
	
	printk("old headers:\n");
	for(index=0; index < headers_len ; index++) {
		printk("%02x ",*(skb->data + index));
	}
	printk("\n");
	
	//if found some match, build new data area and replace strings
	if(head != NULL) {
		
		#ifdef LOG
		printk("found something, ready for replacement!\n");
		string_head = head;
		do{
			printk("found occurrence at position %d\n",string_head->position);
			string_head = string_head->next;
		} while(string_head != NULL);
		#endif
		
		new_skb_data = (char*)kmalloc(new_payload_len - head->position,GFP_ATOMIC);
		
		//then the text
		varlen_replace(l4_payload_start + head->position, l4_payload_len - head->position, new_skb_data, head);
		
		payload_diff = new_payload_len - l4_payload_len;
		skb->tail += payload_diff;
		skb->len += payload_diff;
		l4_len += payload_diff;
		
		//finally the skb_shared_info
		memcpy(l4_payload_start + head->position,new_skb_data,new_payload_len - head->position);
		
		//deallocate the list
		dealloc_all_list(head);
		
		#ifdef LOG
		//new payload
		printk("new payload:\n");
		for(index=0; index < new_payload_len; index++) {
			printk("%c",*(l4_payload_start+index));
		}
		printk("\n");
		//printk("new area allocated\n");
		printk("new IP length is %d\n",new_payload_len + headers_len);		
		#endif
		
		//release new data
		kfree(new_skb_data);
		
		if(ip_head->protocol == IPPROTO_TCP) {
			//fuck TCP ACK mechanism: decrement sequence number
			tcp_head->seq = htonl(ntohl(tcp_head->seq) - payload_diff);
			//recalculate and store checksums
			tcp_head->check = 0;
			tcp_head->check = tcp_v4_check(l4_len, ip_head->saddr, ip_head->daddr, csum_partial((char *)tcp_head, l4_len, 0));
		} else {
			//update data length
			udp_head->len = htons(ntohs(udp_head->len) + payload_diff);
			if(udp_head->check != 0) {
			//for UDP: checksum is recalculated only if needed
			udp_head->check = 0;
			udp_head->check = csum_tcpudp_magic(ip_head->saddr,ip_head->daddr,l4_len,IPPROTO_UDP,csum_partial((char *)udp_head, l4_len, 0));
			}
		}
		ip_head->tot_len = htons(new_payload_len + headers_len);
		ip_head->check = 0;
		ip_head->check = ip_fast_csum(ip_head, ip_hdrlen(skb));
		
		#ifdef LOG
		printk("new headers:\n");
		for(index=0; index < headers_len ; index++) {
			printk("%02x ",*(skb->data + index));
		}
		printk("\n");
		
		printk("new packet:\n");
		for(index=0; index < new_payload_len + headers_len ; index++) {
			printk("%02x ",*(skb->data + index));
		}
		printk("\n");
		#endif
	
	}

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

