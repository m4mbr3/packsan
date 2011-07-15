#ifndef _LINUX_NETFILTER_XT_PACKSAN_UTIL_H
#define _LINUX_NETFILTER_XT_PACKSAN_UTIL_H 1
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

/* This Function is used for comparing two strings passed by parameter

   return: an int = 1 if the two strings are equal
           -1 if the two strings are different
   
   we use it for checking the name of table into check entry function

*/

__u32 str_cmp(__u8* s1, __u8* s2)
{
        __u32* i =(__u32*) kmalloc(sizeof(__u32),GFP_KERNEL);
        i=0;
        while(s1[*i] == s2[i] && s1[*i] != '\0' && s2[*i] != '\0') *i++;
        if (s1[*i] == '\0' && s2[*i] == '\0')
                {
                        kfree(i);
                        return 1;
                }
        else
                {
                        kfree(i);
                        return -1;
                }
}

#endif /*_LINUX_NETFILTER_XT_PACKSAN_UTIL_H */
