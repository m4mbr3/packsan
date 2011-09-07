#include <xtables.h>
#include <stdio.h>
#include <stdbool.h>
#include "xt_PACKSAN.h"

static const struct option_packsan_tg opts[]= {
  {NULL},
};

static int packsan_tg4_parse(int c, char **argv, int invert, unsigned int *flags, const void *entry, struct xt_entry_match **match){
  /* We have no extra-option then we no parse anything */
  return true;
}

static void packsan_tg_check(unsigned int flags)
{
    /* We have no extra-option then we no check anything*/
}

static void packsan_tg4_print(const void *entry,
					const struct xt_entry_match *match, int numeric)
{
  printf("\n[!] No option to print...\n");
}

static void packsan_tg_help(void){
  printf("\nPacksan match options:\n"
    "\n[!] At the momente, No option avaiable \n"
	    );
}

static struct xtables_target packsan_tg4_reg = {
  .version 		= XTABLES_VERSION,
  .name		= "PACKSAN",
  .revision 	= 0,
  .family 		= NFPROTO_IPV4,
  .size 		= XT_ALIGN(0),
  .userspacesize 	= XT_ALIGN(0),
  .help 		= packsan_tg_help,
  .parse 		= packsan_tg4_parse,
  .final_check 	= packsan_tg_check,
  .extra_opts	= packsan_tg_opts,
  .print		= packsan_tg4_print,
};

void _init(void)
{
  xtables_register_target(&packsan_tg4_reg);
}
