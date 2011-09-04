//#include <linux/module.h>
//#include <linux/init.h>
//#include <linux/kernel.h>
//#include <linux/netfilter.h>
//#include <linux/inet.h>
//#include <linux/ip.h>
//#include <linux/ipv6.h>
#include <xtables.h>
//#include <net/dsfield.h>
//#include <linux/skbuff.h>
#include <stdio.h>
#include <stdbool.h>
#include "xt_PACKSAN.h"

static int packsan_tg4_parse(int c, char **argv, int invert, unsigned int *flags, const void *entry, struct xt_entry_match **match){
  return true;
}

static void packsan_tg_help(void){
  printf("DA COMPLETARE CON L'HELP");
}

static struct xtables_target packsan_tg4_reg = {
  .version = XTABLES_VERSION,
  .name = "PACKSAN",
  .revision = 0,
  .family = NFPROTO_IPV4,
  .size = XT_ALIGN(sizeof(struct xt_packsan_tginfo)),
  .userspacesize = XT_ALIGN(sizeof(struct xt_packsan_tginfo)),
  .help = packsan_tg_help,
  .parse = packsan_tg4_parse,
};

void _init(void)
{
  xtables_register_target(&packsan_tg4_reg);
}
