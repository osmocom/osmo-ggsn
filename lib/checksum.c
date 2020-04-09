/*
 *
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IP/TCP/UDP checksumming routines
 *
 * Authors:	Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Tom May, <ftom@netcom.com>
 *		Andreas Schwab, <schwab@issan.informatik.uni-dortmund.de>
 *		Lots of code moved from tcp.c and ip.c; see those files
 *		for more names.
 *
 * 03/02/96	Jes Sorensen, Andreas Schwab, Roman Hodek:
 *		Fixed some nasty bugs, causing some horrible crashes.
 *		A: At some points, the sum (%0) was used as
 *		length-counter instead of the length counter
 *		(%1). Thanks to Roman Hodek for pointing this out.
 *		B: GCC seems to mess up if one uses too many
 *		data-registers to hold input values and one tries to
 *		specify d0 and d1 as scratch registers. Letting gcc
 *		choose these registers itself solves the problem.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

/* Revised by Kenneth Albanowski for m68knommu. Basic problem: unaligned access
 kills, so most of the assembly has to go. */

#if defined(__FreeBSD__)
#define _KERNEL	/* needed on FreeBSD 10.x for s6_addr32 */
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/endian.h>
#endif

#include "checksum.h"
#include <arpa/inet.h>

static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static unsigned int do_csum(const unsigned char *buff, int len)
{
	int odd;
	unsigned int result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
#if BYTE_ORDER == LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff + ((unsigned)len & ~3);
			unsigned int carry = 0;
			do {
				unsigned int w = *(unsigned int *) buff;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
#if BYTE_ORDER == LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 */
uint16_t ip_fast_csum(const void *iph, unsigned int ihl)
{
	return (uint16_t)~do_csum(iph, ihl*4);
}

/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 32-bit boundary
 */
uint32_t csum_partial(const void *buff, int len, uint32_t wsum)
{
	unsigned int sum = (unsigned int)wsum;
	unsigned int result = do_csum(buff, len);

	/* add in old sum, and carry.. */
	result += sum;
	if (sum > result)
		result += 1;
	return (uint32_t)result;
}

/*
 * this routine is used for miscellaneous IP-like checksums, mainly
 * in icmp.c
 */
uint16_t ip_compute_csum(const void *buff, int len)
{
	return (uint16_t)~do_csum(buff, len);
}

uint16_t csum_ipv6_magic(const struct in6_addr *saddr,
			const struct in6_addr *daddr,
			uint32_t len, uint8_t proto, uint32_t csum)
{
	int carry;
	uint32_t ulen;
	uint32_t uproto;
	uint32_t sum = (uint32_t)csum;

	sum += (uint32_t)saddr->s6_addr32[0];
	carry = (sum < (uint32_t)saddr->s6_addr32[0]);
	sum += carry;

	sum += (uint32_t)saddr->s6_addr32[1];
	carry = (sum < (uint32_t)saddr->s6_addr32[1]);
	sum += carry;

	sum += (uint32_t)saddr->s6_addr32[2];
	carry = (sum < (uint32_t)saddr->s6_addr32[2]);
	sum += carry;

	sum += (uint32_t)saddr->s6_addr32[3];
	carry = (sum < (uint32_t)saddr->s6_addr32[3]);
	sum += carry;

	sum += (uint32_t)daddr->s6_addr32[0];
	carry = (sum < (uint32_t)daddr->s6_addr32[0]);
	sum += carry;

	sum += (uint32_t)daddr->s6_addr32[1];
	carry = (sum < (uint32_t)daddr->s6_addr32[1]);
	sum += carry;

	sum += (uint32_t)daddr->s6_addr32[2];
	carry = (sum < (uint32_t)daddr->s6_addr32[2]);
	sum += carry;

	sum += (uint32_t)daddr->s6_addr32[3];
	carry = (sum < (uint32_t)daddr->s6_addr32[3]);
	sum += carry;

	ulen = (uint32_t)htonl((uint32_t) len);
	sum += ulen;
	carry = (sum < ulen);
	sum += carry;

	uproto = (uint32_t)htonl(proto);
	sum += uproto;
	carry = (sum < uproto);
	sum += carry;

	return csum_fold((uint32_t)sum);
}

/* fold a partial checksum */
uint16_t csum_fold(uint32_t csum)
{
	uint32_t sum = (uint32_t)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}
