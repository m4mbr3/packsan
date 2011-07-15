#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <net/dsfield.h>
#include <linux/skbuff.h>

static int packsan_mt4_parse(int c, char **argv, int invert, unsigned int *flags, const void *entry, struct xt_entry_match **match){
  return true;
}

static void packsan_mt_help(void){
  printf("DA COMPLETARE CON L'HELP");
}

static struct xtables_match packsan_mt4_reg = {
  .version = XTABLES_VERSION,
  .name = "packsan",
  .revision = 0,
  .family = NFPROTO_IPV4,
  .size = XT_ALIGN(sizeof(struct xt_packsan_mtinfo)),
  .userspacesize = XT_ALIGN(sizeof(struct xt_packsan_mtinfo)),
  .help = packsan_mt_help,
  .parse = packsan_mt4_parse,
}

void _init(void)
{
  xtables_register_match(&packsan_mt4_reg);
}