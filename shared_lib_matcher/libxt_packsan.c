#include <xtables.h>
#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>


static const struct option packsan_mt_opts[] = {
  {NULL},
  };

static int packsan_mt4_parse(int c, char **argv, int invert, unsigned int *flags, const void *entry, struct xt_entry_match **match){
  /* We have no extra-option then we no parse anything */
  return true;
}

static void packsan_mt_check(unsigned int flags)
{
  /*We have no extra-option then we no check anything*/
}


static void packsan_mt4_print(const void *entry,
			     const struct xt_entry_match *match, int numeric)
{
  printf("\n[!] No option to print...\n");
}


static void packsan_mt_help(void){
  printf("\nPacksan match options:\n"
	 "\n[!] At the moment, No option avaiable  \n"
	 );
}

static struct xtables_match packsan_mt4_reg = {
  .version 		= XTABLES_VERSION,
  .name 		= "packsan",
  .revision 	= 0,
  .family 		= NFPROTO_IPV4,
  .size 		= XT_ALIGN(0),
  .userspacesize 	= XT_ALIGN(0),
  .help 		= packsan_mt_help,
  .parse 		= packsan_mt4_parse,
  .final_check 	= packsan_mt_check,
  .extra_opts 	= packsan_mt_opts,
  .print 		= packsan_mt4_print,
};

void _init(void)
{
  xtables_register_match(&packsan_mt4_reg);
}
