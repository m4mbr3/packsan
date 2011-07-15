
#ifndef _LINUX_NETFILTER_XT_PACKSAN_H
#define _LINUX_NETFILTER_XT_PACKSAN_H 1
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
    enum {
		XT_PACKSAN_LOCAL_IN_	=	1 << NF_IP_LOCAL_IN,
		XT_PACKSAN_POST_ROUTING	=	1 << NF_IP_POST_ROUTING,
	};

	
    struct xt_packsan_mtinfo {
	union nf_inet_addr src, dst;
	__u8 flags;
	};

#endif /*_LINUX_NETFILTER_XT_PACKSAN_H */
