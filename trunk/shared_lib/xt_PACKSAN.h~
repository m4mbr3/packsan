
#ifndef _LINUX_NETFILTER_XT_PACKSAN_H
#define _LINUX_NETFILTER_XT_PACKSAN_H 1
#include <linux/netfilter.h>
    enum {
		XT_PACKSAN_SRC 		=	1 << 0,
		XT_PACKSAN_DST		=	1 << 1,
		XT_PACKSAN_SRC_INV	= 	1 << 2,
		XT_PACKSAN_DST_INV	= 	1 << 3,
	};

	
    struct xt_packsan_tginfo {
	union nf_inet_addr src, dst;
	__u8 flags;
	};

#endif /*_LINUX_NETFILTER_XT_PACKSAN_H */
