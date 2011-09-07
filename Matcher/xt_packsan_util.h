#ifndef _LINUX_NETFILTER_XT_PACKSAN_UTIL_H
#define _LINUX_NETFILTER_XT_PACKSAN_UTIL_H 1
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
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



#endif /*_LINUX_NETFILTER_XT_PACKSAN_UTIL_H */
