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
#include "../gtp/pdp.h"

#include <osmocom/core/utils.h>

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
#if defined(BUILD_IPv6)
	case 8:
	case 16:
		return AF_INET6;
#endif
	default:
		OSMO_ASSERT(0);
		return -1;
	}
}

/*! Convert \ref in46_addr to sockaddr_storage */
int in46a_to_sas(struct sockaddr_storage *out, const struct in46_addr *in)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)out;
#if defined(BUILD_IPv6)
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
#endif

	switch (in->len) {
	case 4:
		sin->sin_family = AF_INET;
		sin->sin_addr = in->v4;
		break;
#if defined(BUILD_IPv6)
	case 16:
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = in->v6;
		break;
#endif
	default:
		OSMO_ASSERT(0);
		return -1;
	}

	return 0;
}

/*! Convenience wrapper around inet_ntop() for \ref in46_addr */
const char *in46a_ntop(const struct in46_addr *in, char *dst, socklen_t dst_size)
{
	int af;

	if (!in || in->len == 0) {
		strncpy(dst, "UNDEFINED", dst_size);
		return dst;
	}

	af = in46a_to_af(in);
	if (af < 0)
		return NULL;

	return inet_ntop(af, (const void *) &in->v4, dst, dst_size);
}

/* like inet_ntoa() */
const char *in46a_ntoa(const struct in46_addr *in46)
{
	static char addrstr_buf[256];
	if (in46a_ntop(in46, addrstr_buf, sizeof(addrstr_buf)) < 0)
		return "INVALID";
	else
		return addrstr_buf;
}

const char *in46p_ntoa(const struct in46_prefix *in46p)
{
	static char addrstr_buf[256];
	snprintf(addrstr_buf, sizeof(addrstr_buf), "%s/%u", in46a_ntoa(&in46p->addr), in46p->prefixlen);
	return addrstr_buf;
}

/*! Determine if two in46_addr are equal or not
 *  \returns 1 in case they are equal; 0 otherwise */
int in46a_equal(const struct in46_addr *a, const struct in46_addr *b)
{
	if (a->len == b->len && !memcmp(&a->v4, &b->v4, a->len))
		return 1;
	else
		return 0;
}

/*! Determine if two in46_addr prefix are equal or not
 *  The prefix length is determined by the shortest of the prefixes of a and b
 *  \returns 1 in case the common prefix are equal; 0 otherwise */
int in46a_prefix_equal(const struct in46_addr *a, const struct in46_addr *b)
{
	unsigned int len;
	if (a->len > b->len)
		len = b->len;
	else
		len = a->len;

	if (!memcmp(&a->v4, &b->v4, len))
		return 1;
	else
		return 0;
}

#if defined(BUILD_IPv6)
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
#endif

/*! Determine if given \a addr is within given \a net + \a prefixlen
 *  Builds the netmask from \a net + \a prefixlen and matches it to \a addr
 *  \returns 1 in case of a match, 0 otherwise */
int in46a_within_mask(const struct in46_addr *addr, const struct in46_addr *net, size_t prefixlen)
{
	struct in_addr netmask;
#if defined(BUILD_IPv6)
	struct in6_addr netmask6;
#endif

	if (addr->len != net->len)
		return 0;

	switch (addr->len) {
	case 4:
		netmask.s_addr = htonl(0xFFFFFFFF << (32 - prefixlen));
		if ((addr->v4.s_addr & netmask.s_addr) == net->v4.s_addr)
			return 1;
		else
			return 0;
#if defined(BUILD_IPv6)
	case 16:
		create_ipv6_netmask(&netmask6, prefixlen);
		return ipv6_within_mask(&addr->v6, &net->v6, &netmask6);
#endif
	default:
		OSMO_ASSERT(0);
		return 0;
	}
}

static unsigned int ipv4_netmasklen(const struct in_addr *netmask)
{
	uint32_t bits = netmask->s_addr;
	uint8_t *b = (uint8_t*) &bits;
	unsigned int i, prefix = 0;

	for (i = 0; i < 4; i++) {
		while (b[i] & 0x80) {
			prefix++;
			b[i] = b[i] << 1;
		}
	}
	return prefix;
}

#if defined(BUILD_IPv6)
static unsigned int ipv6_netmasklen(const struct in6_addr *netmask)
{
	#if defined(__linux__)
		#define ADDRFIELD(i) s6_addr32[i]
	#else
		#define ADDRFIELD(i) __u6_addr.__u6_addr32[i]
	#endif

	unsigned int i, j, prefix = 0;

	for (j = 0; j < 4; j++) {
		uint32_t bits = netmask->ADDRFIELD(j);
		uint8_t *b = (uint8_t*) &bits;
		for (i = 0; i < 4; i++) {
			while (b[i] & 0x80) {
				prefix++;
				b[i] = b[i] << 1;
			}
		}
	}

	#undef ADDRFIELD

	return prefix;
}
#endif

/*! Convert netmask to prefix length representation
 *  \param[in] netmask in46_addr containing a netmask (consecutive list of 1-bit followed by consecutive list of 0-bit)
 *  \returns prefix length representation of the netmask (count of 1-bit from the start of the netmask)
 */
unsigned int in46a_netmasklen(const struct in46_addr *netmask)
{
	switch (netmask->len) {
	case 4:
		return ipv4_netmasklen(&netmask->v4);
#if defined(BUILD_IPv6)
	case 16:
		return ipv6_netmasklen(&netmask->v6);
#endif
	default:
		OSMO_ASSERT(0);
		return 0;
	}
}

/*! Convert given PDP End User Address to in46_addr
 *  \returns 0 on success; negative on error */
int in46a_to_eua(const struct in46_addr *src, struct ul66_t *eua)
{
	switch (src->len) {
	case 4:
		eua->l = 6;
		eua->v[0] = PDP_EUA_ORG_IETF;
		eua->v[1] = PDP_EUA_TYPE_v4;
		memcpy(&eua->v[2], &src->v4, 4);	/* Copy a 4 byte address */
		break;
#if defined(BUILD_IPv6)
	case 8:
	case 16:
		eua->l = 18;
		eua->v[0] = PDP_EUA_ORG_IETF;
		eua->v[1] = PDP_EUA_TYPE_v6;
		memcpy(&eua->v[2], &src->v6, 16);	/* Copy a 16 byte address */
		break;
#endif
	default:
		OSMO_ASSERT(0);
		return -1;
	}
	return 0;
}

/*! Convert given in46_addr to PDP End User Address
 *  \returns 0 on success; negative on error */
int in46a_from_eua(const struct ul66_t *eua, struct in46_addr *dst)
{
	if (eua->l < 2)
		goto default_to_dyn_v4;

	if (eua->v[0] != 0xf1)
		return -1;

	switch (eua->v[1]) {
	case PDP_EUA_TYPE_v4:
		dst->len = 4;
		if (eua->l >= 6)
			memcpy(&dst->v4, &eua->v[2], 4);	/* Copy a 4 byte address */
		else
			dst->v4.s_addr = 0;
		break;
#if defined(BUILD_IPv6)
	case PDP_EUA_TYPE_v6:
		dst->len = 16;
		if (eua->l >= 18)
			memcpy(&dst->v6, &eua->v[2], 16);	/* Copy a 16 byte address */
		else
			memset(&dst->v6, 0, 16);
		break;
#endif
	default:
		return -1;
	}
	return 0;

default_to_dyn_v4:
	/* assume dynamic IPv4 by default */
	dst->len = 4;
	dst->v4.s_addr = 0;
	return 0;
}
