/*
 * IPv4/v6 address functions.
 * Copyright (C) 2017 by Harald Welte <laforge@gnumonks.org>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

#include "../lib/in46_addr.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

/*! Return the address family of given \reff in46_addr argument */
int in46a_to_af(const struct in46_addr *in)
{
	switch (in->len) {
	case 4:
		return AF_INET;
	case 16:
		return AF_INET6;
	default:
		return -1;
	}
}

/*! Convert \ref in46_addr to sockaddr_storage */
int in46a_to_sas(struct sockaddr_storage *out, const struct in46_addr *in)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)out;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;

	switch (in->len) {
	case 4:
		sin->sin_family = AF_INET;
		sin->sin_addr = in->v4;
		break;
	case 16:
		sin6->sin6_family = AF_INET;
		sin6->sin6_addr = in->v6;
		break;
	default:
		return -1;
	}

	return 0;
}

/*! Convenience wrapper around inet_ntop() for \ref in46_addr */
const char *in46a_ntop(const struct in46_addr *in, char *dst, socklen_t dst_size)
{
	int af = in46a_to_af(in);
	if (af < 0)
		return NULL;

	return inet_ntop(af, (const void *) &in->v4, dst, dst_size);
}

/*! Determine if two in46_addr are equal or not
 *  \returns 1 in case they are equal; 0 otherwise */
int in46a_equal(const struct in46_addr *a, const struct in46_addr *b)
{
	if (a->len == b->len && !memcmp(&a->v6, &b->v6, a->len))
		return 1;
	else
		return 0;
}

/*! Match if IPv6 addr1 + addr2 are within same \a mask */
static int ipv6_within_mask(const struct in6_addr *addr1, const struct in6_addr *addr2,
			    const struct in6_addr *mask)
{
	struct in6_addr masked = *addr2;
#if defined(__linux__)
	masked.s6_addr32[0] &= mask->s6_addr32[0];
	masked.s6_addr32[1] &= mask->s6_addr32[1];
	masked.s6_addr32[2] &= mask->s6_addr32[2];
	masked.s6_addr32[3] &= mask->s6_addr32[3];
#else
	masked.__u6_addr.__u6_addr32[0] &= mask->__u6_addr.__u6_addr32[0];
	masked.__u6_addr.__u6_addr32[1] &= mask->__u6_addr.__u6_addr32[1];
	masked.__u6_addr.__u6_addr32[2] &= mask->__u6_addr.__u6_addr32[2];
	masked.__u6_addr.__u6_addr32[3] &= mask->__u6_addr.__u6_addr32[3];
#endif
	if (!memcmp(addr1, &masked, sizeof(struct in6_addr)))
		return 1;
	else
		return 0;
}

/*! Create an IPv6 netmask from the given prefix length */
static void create_ipv6_netmask(struct in6_addr *netmask, int prefixlen)
{
	uint32_t *p_netmask;
	memset(netmask, 0, sizeof(struct in6_addr));
	if (prefixlen < 0)
		prefixlen = 0;
	else if (128 < prefixlen)
		prefixlen = 128;

#if defined(__linux__)
	p_netmask = &netmask->s6_addr32[0];
#else
	p_netmask = &netmask->__u6_addr.__u6_addr32[0];
#endif
	while (32 < prefixlen) {
		*p_netmask = 0xffffffff;
		p_netmask++;
		prefixlen -= 32;
	}
	if (prefixlen != 0) {
		*p_netmask = htonl(0xFFFFFFFF << (32 - prefixlen));
	}
}

/*! Determine if given \a addr is within given \a net + \a prefixlen
 *  Builds the netmask from \a net + \a prefixlen and matches it to \a addr
 *  \returns 1 in case of a match, 0 otherwise */
int in46a_within_mask(const struct in46_addr *addr, const struct in46_addr *net, size_t prefixlen)
{
	struct in_addr netmask;
	struct in6_addr netmask6;

	if (addr->len != net->len)
		return 0;

	switch (addr->len) {
	case 4:
		netmask.s_addr = htonl(0xFFFFFFFF << (32 - prefixlen));
		if ((addr->v4.s_addr & netmask.s_addr) == net->v4.s_addr)
			return 1;
		else
			return 0;
	case 16:
		create_ipv6_netmask(&netmask6, prefixlen);
		return ipv6_within_mask(&addr->v6, &net->v6, &netmask6);
	default:
		return 0;
	}
}
