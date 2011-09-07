/*! \file libxt_PACKSAN.c
 * \brief interface between user space and target module
 */

#include <xtables.h>
#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>


/*! \var struct option packsan_tg_opts[]
 * \brief list of parameters to be inserted from command line
 */
static const struct option packsan_tg_opts[]= {
  {NULL},
};

/*! \fn int packsan_tg_parse(int c, char **argv, int invert, unsigned int *flags, const void *entry, struct xt_entry_match **match)
 * \brief checks the parameters passed to the module
 * \param c character passed to identify the option
 * \param argv list of arguments
 * \param flags bitmask to compare with local parameters
 * \return 0 if some option is not correct, nonzero otherwise
 */
static int packsan_tg4_parse(int c, char **argv, int invert, unsigned int *flags, const void *entry, struct xt_entry_match **match)
{
  /* We have no extra-option then we don't parse anything */
  return true;
}

/*! \fn void packsan_tg_check(unsigned int flags)
 * \brief checks the passed flags
 * \param flags the flags passed by users
 */
static void packsan_tg_check(unsigned int flags)
{
    /* We have no extra-option then we don't check anything*/
}

/*! \fn void packsan_tg_print(const void *entry, const struct xt_entry_match *match, int numeric)
 * \brief prints a message once the rule has been inserted (like options or caveats)
 */
static void packsan_tg4_print(const void *entry,
					const struct xt_entry_match *match, int numeric)
{
  printf("\n[!] No option to print...\n");
}

/*! \fn void packsan_tg_help(void)
 * \brief prints a help message
 */
static void packsan_tg_help(void){
  printf("\nPacksan match options:\n"
    "\n[!] At the moment, No option avaiable \n"
	    );
}

/*! \var struct xtables_target packsan_tg_reg
 * \brief struct to register the plugin
 */
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

/*! \fn void _init(void)
 * \brief function called at the insertion to register the module.
 */
void _init(void)
{
  xtables_register_target(&packsan_tg4_reg);
}
