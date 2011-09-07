


#ifndef _LINUX_NETFILTER_XT_PACKSAN_H
#define _LINUX_NETFILTER_XT_PACKSAN_H 1
//#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>



    enum {
		XT_PACKSAN_LOCAL_IN	=	1 << 1,
		XT_PACKSAN_POST_ROUTING	=	1 << 4,
	};

	
    struct xt_packsan_mtinfo {
	char* string, replacer;
	__u8 flags;
	};
	
	
	//struttura che rappresenta un nodo nella lista delle occorrenze.
typedef struct ps_match_occurrence {
	//number of the string which has been found, in the hypothesis that
	//more strings are searched for
	unsigned int string_index;
    unsigned int position;
    struct ps_match_occurrence* next;
} ps_match;




// strings_number stores the number of strings to search
const unsigned int strings_number = 2;
const char* strings[] = {"carne","gelato"}; 
const char* var_len_replacements[] = {"PASTICCIOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB","SALE"};
// const_len_replacements strings MUST have the same length of those stored in strings,
// otherwise segment loss and connection block will happen with TCP protocol (trick in progress ...)
const char* const_len_replacements[] = {"PESCE","SALATO"};




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
static void compute_prefix_function(const char* p, int p_length, int* pi){
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
static ps_match* KMP_Matcher(char* T, int T_length, const char* P, int P_length, unsigned int string_index, int* matches) {
	int n = T_length;
	int m = P_length;
	int q=0;
	int i;
	int* pi = (int*)kmalloc(m * sizeof(int), GFP_ATOMIC);
	ps_match* last = NULL;
	ps_match* new_head = NULL;
	ps_match* new;
	
	compute_prefix_function(P, m, pi);
	for(i=0; i<n; i++){
  
    while(q>0 && P[q] != T[i]) {
		q = pi[q];
	}
    if( P[q] == T[i] ) {
		q = q+1;
	}
	
    if (q == m){
		#ifdef LOG
		#endif
		(*matches)++;
		new = ((ps_match*)(kmalloc(sizeof(struct ps_match_occurrence), GFP_ATOMIC)));
		new->position = i-m+1;
		new->string_index = string_index;
		new->next = NULL;
		if(last == NULL) {
			new_head = new;
		} else {
			last->next=new;
		}
		last = new;
		q = pi[q-1];
    }
  }
  
  kfree(pi);
  return new_head;
}

#endif /*_LINUX_NETFILTER_XT_PACKSAN_H */
