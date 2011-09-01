#include "xt_packsan.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_string.h>
#include <net/checksum.h>
#include <net/tcp.h>
#include <asm/checksum.h>
//distance of data offset field in tcp header
#define DOFF_DISTANCE 12
//udp header length
#define UDP_HDR_LEN 8
#define STRINGS 2
//do you want to have a VERBOSE log of the module activity? set it to non-zero
#define LOG 1

//struttura che rappresenta un nodo nella lista delle occorrenze.
typedef struct match_occurrence {
	//number of the string which has been found, in the hypothesis that
	//more strings are searched for
	unsigned int string_index;
    unsigned int position;
    struct match_occurrence* next;
} ps_match;

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
	//const struct xt_packsan_mtinfo *info = par->matchinfo;
	//__u8* p= kmalloc(sizeof(__u8[8]),GFP_KERNEL);
	
	pr_info("Added a rule with -m packsan in the %s table; this rule is "
		"reachable through hooks 0x%x\n",
		par-> table, par-> hook_mask);
	
	if (!(par->hook_mask & ( XT_PACKSAN_LOCAL_IN | XT_PACKSAN_POST_ROUTING ))) {
		pr_info("Noone hook selected!!! \n");
		return -EINVAL;
	}
	
	/*
	p[0] =  'm';
	p[1] =  'a';
	p[2] =  'n';
	p[3] =  'g';
	p[4] =  'l';
	p[5] =  'e';
	p[6] =  '\0';
	*/
	
	if( strcmp(par->table, "mangle") == -1){
		pr_info("The inserted table isn't  mangle!!!");
		//kfree(p);
		return -EINVAL;
	}
	//kfree(p);
	return 0;
}

static void packsan_mt_destroy(const struct xt_mtdtor_param *par)
{	
	const struct xt_packsan_mtinfo *info = par->matchinfo;
	pr_info ("Test for address %081X removed \n", info->src.ip);
}




//funzione che aggiunge in testa alla lista una nuova occorrenza.
//head e' il puntatore alla testa della lista, pos_ps_match e' la posizione nel testo della nuova occorrenza da aggiungere.
//ritorna la nuova testa della lista aggiornata con il nuovo valore.
/*
static ps_match* prepend(ps_match* head, int pos_occurrence){
  ps_match* new;
  if(head == NULL){
    head = (ps_match*)kmalloc(sizeof(occurrence), GFP_ATOMIC);
    head->pos_occurrence = pos_occurrence;
    head->next_occurrence = NULL;
  } else {
    new = (ps_match*)kmalloc(sizeof(occurrence), GFP_ATOMIC);
    new->pos_occurrence = pos_occurrence;
    new->next_occurrence = head;
    head = new;
  }
  return head;
}
*/

//dealloca l'intera lista delle occorrenze se diversa da NULL.
static void dealloc_all_list(ps_match* head){
  ps_match* last;
  //ridondante: la deallocazione viene richiesta solo se qualcosa è stato trovato ...
  /*if(head == NULL){
    return;
  }*/
  
  for(last = head; last != NULL; head = last){
    last = head->next;
    kfree(head);
  }
  //kfree(head);
  return;
}

//funzione ausiliaria dell'algoritmo KMP che precalcola l'array pi[] in base al pattern.
//p e' il pattern e p_length la sua lunghezza.
//pi puntatore a un array di interi precalcolati in base al pattern.
static void compute_prefix_function(char* p, int p_length, int* pi){
  int k;
  int q;
  pi[0]=0;
  k=0;  
  for(q=1; q<p_length; q++){
    while( k>0 && p[k]!=p[q] )
      k=pi[k];
    if( p[k] == p[q])
      k=k+1;
    pi[q] = k;
    
  }
}

//insert occurrences in correct order, with regard to the position field, and returns the new head of the list
static inline ps_match* insert_by_position(ps_match* head, ps_match* string_head) {
	
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

//Algoritmo KMP per ricerca stringhe in un testo.
//T puntatore al testo, T_length lunghezza del testo.
//P puntatore al pattern, P_length lunghezza del pattern.
//restituisce un puntatore alla lista delle correzze trovate oppure NULL se non ve ne sono.
//NOTA: la lista delle occorrenze e' ritornata in ordine inverso per il semplice motivo che aggiungere in testa alla lista
//ha un costo costante invece aggungere in coda no
static ps_match* KMP_Matcher(char* T, int T_length, char* P, int P_length, unsigned int string_index, int* matches) {
	int n = T_length;
	int m = P_length;
	int q=0;
	int i;
	int* pi = (int*)kmalloc(m * sizeof(int), GFP_ATOMIC);
	ps_match* last = NULL;
	ps_match* new_head = NULL;
	ps_match* new;
	
	//printk("KMP entering\n");
	compute_prefix_function(P, m, pi);
	for(i=0; i<n; i++){
  
    while(q>0 && P[q] != T[i]) {
		q = pi[q];
	}
    if( P[q] == T[i] ) {
		q = q+1;
	}
	
    if (q == m){
		//head = prepend(head, i-m+1);
		#ifdef LOG
		printk("KMP found!\n");
		#endif
		(*matches)++;
		new = ((ps_match*)(kmalloc(sizeof(struct match_occurrence), GFP_ATOMIC)));
		new->position = i-m+1;
		new->string_index = string_index;
		new->next = NULL;
		if(last == NULL) {
			//printk("new string!\n");
			new_head = new;
		} else {
			//printk("same string\n");
			last->next=new;
		}
		last = new;
		q = pi[q-1];
    }
  }
  
  kfree(pi);
  return new_head;
}

char* strings[] = {"carne","gelato"}; 
char* replacements[] = {"PASTICCIO","SALE"};


/* 
 * function to copy the data to the new area and replace the found occurences
 */
void inline varlen_replace(char* original, unsigned int original_len, char* new, ps_match* matches) {
	
	//original_index stores the actual position in the old area, new_index in the new one
	int original_index=0, new_index=0,index;
	
	do {
		
		//copy unmodified data
		for(;original_index < matches->position; original_index++) {
			*(new + new_index)=*(original + original_index);
			new_index++;
		}
		//new_index++;
		
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



static bool packsan_mt(struct sk_buff *skb, struct xt_action_param *par)
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
		
		index = new_payload_len - l4_payload_len;
		skb->tail += index;
		skb->len += index;
		l4_len += index;
		
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
		printk("new length is %d\n",new_payload_len + headers_len);		
		#endif
		
		//release new data
		kfree(new_skb_data);
		
		if(ip_head->protocol == IPPROTO_TCP) {
			//recalculate and store checksums
			tcp_head->check = 0;
			tcp_head->check = tcp_v4_check(l4_len, ip_head->saddr, ip_head->daddr, csum_partial((char *)tcp_head, l4_len, 0));
		} else if(udp_head->check != 0) {
			//for UDP: checksum is recalculated only if needed
			udp_head->check = 0;
			udp_head->check = csum_tcpudp_magic(ip_head->saddr,ip_head->daddr,l4_len,IPPROTO_UDP,csum_partial((char *)udp_head, l4_len, 0));
		}
		ip_head->tot_len = (__be16)(new_payload_len + headers_len);
		//ip_head->check = 0;
		//ip_head->check = ip_fast_csum(ip_head, (char*)skb->tail - (char*)ip_head);
		
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

