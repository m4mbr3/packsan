#include "xt_packsan.h"
//#include "xt_packsan_util.h"
#include <linux/module.h>
//#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/in.h>
//#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
//#include <net/dsfield.h>
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
#define LOG 1

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
/*	
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
	kfree(p);*/
	return 0;
}

static void packsan_mt_destroy(const struct xt_mtdtor_param *par)
{	
	const struct xt_packsan_mtinfo *info = par->matchinfo;
	pr_info ("Test for address %081X removed \n", info->src.ip);
}







//struttura che rappresenta un nodo nella lista delle occorrenze.
typedef struct occurrence{
    int pos_occurrence;
    struct occurrence *next_occurrence;
}occurrence;

//funzione che aggiunge in testa alla lista una nuova occorrenza.
//head e' il puntatore alla testa della lista, pos_occurrence e' la posizione nel testo della nuova occorrenza da aggiungere.
//ritorna la nuova testa della lista aggiornata con il nuovo valore.
static occurrence* prepend(occurrence* head, int pos_occurrence){
  occurrence* new;
  if(head == NULL){
    head = (occurrence*)kmalloc(sizeof(occurrence), GFP_ATOMIC);
    head->pos_occurrence = pos_occurrence;
    head->next_occurrence = NULL;
  } else {
    new = (occurrence*)kmalloc(sizeof(occurrence), GFP_ATOMIC);
    new->pos_occurrence = pos_occurrence;
    new->next_occurrence = head;
    head = new;
  }
  return head;
}

//dealloca l'intera lista delle occorrenze se diversa da NULL.
static void dealloc_all_list(occurrence* head){
  occurrence* next_occurrence;
  if(head == NULL){
    return;
  }
  for(;head->next_occurrence != NULL; head = next_occurrence){
    next_occurrence = head->next_occurrence;
    kfree(head);
  }
  kfree(head);
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

//Algoritmo KMP per ricerca stringhe in un testo.
//T puntatore al testo, T_length lunghezza del testo.
//P puntatore al pattern, P_length lunghezza del pattern.
//restituisce un puntatore alla lista delle correzze trovate oppure NULL se non ve ne sono.
//NOTA: la lista delle occorrenze e' ritornata in ordine inverso per il semplice motivo che aggiungere in testa alla lista
//ha un costo costante invece aggungere in coda no
static occurrence* KMP_Matcher(char* T, int T_length, char* P, int P_length){
  int n = T_length;
  int m = P_length;
  int q=0;
  int i;
  int* pi = (int*)kmalloc(m * sizeof(int), GFP_ATOMIC);
  occurrence *head = NULL;
  compute_prefix_function(P, m, pi);
  for(i=0; i<n; i++){
    while(q>0 && P[q] != T[i])
      q = pi[q];
    if( P[q] == T[i] )
      q = q+1;
    if ( q == m){
      head = prepend(head, i-m+1);
      q = pi[q-1];
    }  
  }
  kfree(pi);
  return head;
}












/* function to replace rep_len characters of original with rep_len replacement's ones.
 * Only same length replacement is available at the moment. 
 */
void inline replace(char* original, char* replacement, unsigned int rep_len) {
	int index;
	
	for(index=0; index < rep_len; index++) {
		*(original + index)=*(replacement + index);
	}
}

static bool packsan_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	// length of layer 4 payload
	unsigned int data_len;
	// beginning of layer 4 payload
	char *data_start;
	//index is only for various debug cycles
	int index;
	//length of string to replace
	unsigned int rep_len;
	//string to search
	char pattern[] = "carne";
	//string to replace
	char replacement[] = "PESCE";
	//if a match is found
	//bool found = false;
	//position of a match discover from payload beginning
	//unsigned int position = 0;
	//pointer to ip header inside skb
	struct iphdr *ip_head = ip_hdr(skb);
	//pointer to tcp header inside skb
	struct tcphdr *tcp_head = (struct tcphdr *)(skb->data + ip_hdrlen(skb));
	//pointer to udp header inside skb
	struct udphdr *udp_head = (struct udphdr *)(tcp_head);
	//transport area length: header + payload
	unsigned int transport_len = (char*)skb->tail - (char*)tcp_head;
	//testa della lista delle occorrenze
	occurrence* head;
	//transport header length, with inizialization
	__u8 transport_hdr_len;
	if(ip_head->protocol == IPPROTO_TCP) {
		
		#ifdef LOG
		printk("TCP\n");
		#endif /* LOG */
		
		//TCP header length: the very problem is endianess: network data are big endian, x86 is little endian: mercy!
		// DOFF_DISTANCE = 12 is the distance from the beginning of the 4-bit field data offset,
		//containing the tcp header dimension in 32-bit words and other optional bits: all big endian for our pleasure!
		// the correct value is found via bit shifting (need only the left 4 bits) and multiply
		transport_hdr_len = ((*((__u8*)tcp_head+DOFF_DISTANCE)) >> 4)*4;
	}  else {
		
		#ifdef LOG
		printk("UDP\n");
		#endif /* LOG */
		
		transport_hdr_len = sizeof(struct udphdr);
	}
	
	//printk("ip header len is %d\n",ip_hdrlen(skb));
	//printk("tcp header len is %d\n",tcpHdrLen);
		
	//calculate the payload beginning address
	data_start = skb->data + ip_hdrlen(skb) + transport_hdr_len;
	
	//calculate the payload length
	data_len = (char*)skb->tail - (char*)data_start;
	
	#ifdef LOG
	printk("received packet\n");
	printk("length is %d\n",data_len);
	//print the payload
	for(index = 0; index < data_len; index++) {
		printk("%c",*(data_start+index));
	}
	printk("\n");
	#endif /* LOG */
	
	//check the string and replace, several times until the whole payload has been checked
	rep_len = strlen(pattern);
	
	
	head = KMP_Matcher(data_start, data_len, pattern, rep_len);
	
	//if found some match, replace all
	if(head != NULL){
	  for(; head->next_occurrence !=NULL; head = head->next_occurrence)
	    replace(data_start + head->pos_occurrence, replacement, rep_len);
	  replace(data_start + head->pos_occurrence, replacement, rep_len);
	}
	
	//if found some match, recalculate checksums
	if(head != NULL) {
		if(ip_head->protocol == IPPROTO_TCP) {
		//recalculate and store checksums
		tcp_head->check = 0;
		tcp_head->check = tcp_v4_check(transport_len, ip_head->saddr, ip_head->daddr, csum_partial((char *)tcp_head, transport_len, 0));
		} else if(udp_head->check != 0) {
			//for UDP: checksum is recalculated only if needed
			udp_head->check = 0;
			udp_head->check = csum_tcpudp_magic(ip_head->saddr,ip_head->daddr,transport_len,IPPROTO_UDP,csum_partial((char *)udp_head, transport_len, 0));;
		}
		ip_head->check = 0;
		ip_head->check = ip_fast_csum(ip_head, (char*)skb->tail - (char*)ip_head);
	}
	
	dealloc_all_list(head);

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
