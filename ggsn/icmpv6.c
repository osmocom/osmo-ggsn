/* Minimal ICMPv6 code for generating router advertisements as required by
 * relevant 3GPP specs for a GGSN with IPv6 PDP contexts */

/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#if defined(__FreeBSD__)
#include <sys/types.h>	/* FreeBSD 10.x needs this before ip6.h */
#include <sys/endian.h>
#endif
#include <netinet/ip6.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include "checksum.h"

#include "../gtp/gtp.h"
#include "../gtp/pdp.h"
#include "../lib/ippool.h"
#include "../lib/syserr.h"
#include "config.h"

/* 29.061 11.2.1.3.4 IPv6 Router Configuration Variables in GGSN */
#define GGSN_MaxRtrAdvInterval	21600		/* 6 hours */
#define GGSN_MinRtrAdvInterval 16200		/* 4.5 hours */
#define GGSN_AdvValidLifetime	0xffffffff	/* infinite */
#define GGSN_AdvPreferredLifetime 0xffffffff	/* infinite */

struct icmpv6_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t csum;
} __attribute__ ((packed));

/* RFC4861 Section 4.2 */
struct icmpv6_radv_hdr {
	struct icmpv6_hdr hdr;
	uint8_t cur_ho_limit;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t res:6,
		m:1,
		o:1;
#elif BYTE_ORDER == BIG_ENDIAN
	uint8_t m:1,
		o:1,
		res:6;
#else
# error	"Please fix <bits/endian.h>"
#endif
	uint16_t router_lifetime;
	uint32_t reachable_time;
	uint32_t retrans_timer;
	uint8_t options[0];
} __attribute__ ((packed));

/* RFC4861 Section 4.6 */
struct icmpv6_opt_hdr {
	uint8_t type;
	/* length in units of 8 octets, including type+len! */
	uint8_t len;
	uint8_t data[0];
} __attribute__ ((packed));

/* RFC4861 Section 4.6.2 */
struct icmpv6_opt_prefix {
	struct icmpv6_opt_hdr hdr;
	uint8_t prefix_len;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t res:6,
		a:1,
		l:1;
#elif BYTE_ORDER == BIG_ENDIAN
	uint8_t l:1,
		a:1,
		res:6;
#else
# error	"Please fix <bits/endian.h>"
#endif
	uint32_t valid_lifetime;
	uint32_t preferred_lifetime;
	uint32_t res2;
	uint8_t prefix[16];
} __attribute__ ((packed));


/*! construct a 3GPP 29.061 compliant router advertisement for a given prefix
 *  \param[in] saddr Source IPv6 address for router advertisement
 *  \param[in] daddr Destination IPv6 address for router advertisement IPv6 header
 *  \param[in] prefix The single prefix to be advertised (/64 implied!)
 *  \returns callee-allocated message buffer containing router advertisement */
struct msgb *icmpv6_construct_ra(const struct in6_addr *saddr,
				 const struct in6_addr *daddr,
				 const struct in6_addr *prefix)
{
	struct msgb *msg = msgb_alloc_headroom(512,128, "IPv6 RA");
	struct icmpv6_radv_hdr *ra;
	struct icmpv6_opt_prefix *ra_opt_pref;
	struct ip6_hdr *i6h;
	uint32_t len;
	uint16_t skb_csum;

	OSMO_ASSERT(msg);

	ra = (struct icmpv6_radv_hdr *) msgb_put(msg, sizeof(*ra));
	ra->hdr.type = 134;	/* see RFC4861 4.2 */
	ra->hdr.code = 0;	/* see RFC4861 4.2 */
	ra->hdr.csum = 0;	/* updated below */
	ra->cur_ho_limit = 64;	/* seems reasonable? */
	/* the GGSN shall leave the M-flag cleared in the Router
	 * Advertisement messages */
	ra->m = 0;
	/* The GGSN may set the O-flag if there are additional
	 * configuration parameters that need to be fetched by the MS */
	ra->o = 0;		/* no DHCPv6 */
	ra->res = 0;
	/* RFC4861 Default: 3 * MaxRtrAdvInterval */
	ra->router_lifetime = htons(3*GGSN_MaxRtrAdvInterval);
	ra->reachable_time = 0;	/* Unspecified */

	/* RFC4861 Section 4.6.2 */
	ra_opt_pref = (struct icmpv6_opt_prefix *) msgb_put(msg, sizeof(*ra_opt_pref));
	ra_opt_pref->hdr.type = 3;	/* RFC4861 4.6.2 */
	ra_opt_pref->hdr.len = 4;	/* RFC4861 4.6.2 */
	ra_opt_pref->prefix_len = 64;	/* only prefix length as per 3GPP */
	/* The Prefix is contained in the Prefix Information Option of
	 * the Router Advertisements and shall have the A-flag set
	 * and the L-flag cleared */
	ra_opt_pref->a = 1;
	ra_opt_pref->l = 0;
	ra_opt_pref->res = 0;
	/*  The lifetime of the prefix shall be set to infinity */
	ra_opt_pref->valid_lifetime = htonl(GGSN_AdvValidLifetime);
	ra_opt_pref->preferred_lifetime = htonl(GGSN_AdvPreferredLifetime);
	ra_opt_pref->res2 = 0;
	memcpy(ra_opt_pref->prefix, prefix, sizeof(ra_opt_pref->prefix));

	/* checksum */
	skb_csum = csum_partial(msgb_data(msg), msgb_length(msg), 0);
	len = msgb_length(msg);
	ra->hdr.csum = csum_ipv6_magic(saddr, daddr, len, IPPROTO_ICMPV6, skb_csum);

	/* Push IPv6 header in front of ICMPv6 packet */
	i6h = (struct ip6_hdr *) msgb_push(msg, sizeof(*i6h));
	/* 4 bits version, 8 bits TC, 20 bits flow-ID */
	i6h->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
	i6h->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(len);
	i6h->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_ICMPV6;
	i6h->ip6_ctlun.ip6_un1.ip6_un1_hlim = 255;
	i6h->ip6_src = *saddr;
	i6h->ip6_dst = *daddr;

	return msg;
}

/* Walidate an ICMPv6 router solicitation according to RFC4861 6.1.1 */
static bool icmpv6_validate_router_solicit(const uint8_t *pack, unsigned len)
{
	const struct ip6_hdr *ip6h = (struct ip6_hdr *)pack;
	//const struct icmpv6_hdr *ic6h = (struct icmpv6_hdr *) (pack + sizeof(*ip6h));

	/* Hop limit field must have 255 */
	if (ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim != 255)
		return false;
	/* FIXME: ICMP checksum is valid */
	/* ICMP length (derived from IP length) is 8 or more octets */
	if (ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen < 8)
		return false;
	/* FIXME: All included options have a length > 0 */
	/* FIXME: If IP source is unspecified, no source link-layer addr option */
	return true;
}

/* handle incoming packets to the all-routers multicast address */
int handle_router_mcast(struct gsn_t *gsn, struct pdp_t *pdp,
			const struct in6_addr *pdp_prefix,
			const struct in6_addr *own_ll_addr,
			const uint8_t *pack, unsigned len)
{
	const struct ip6_hdr *ip6h = (struct ip6_hdr *)pack;
	const struct icmpv6_hdr *ic6h = (struct icmpv6_hdr *) (pack + sizeof(*ip6h));
	struct msgb *msg;

	if (len < sizeof(*ip6h)) {
		LOGP(DICMP6, LOGL_NOTICE, "Packet too short: %u bytes\n", len);
		return -1;
	}

	/* we only treat ICMPv6 here */
	if (ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_ICMPV6) {
		LOGP(DICMP6, LOGL_DEBUG, "Ignoring non-ICMP to all-routers mcast\n");
		return 0;
	}

	if (len < sizeof(*ip6h) + sizeof(*ic6h)) {
		LOGP(DICMP6, LOGL_NOTICE, "Short ICMPv6 packet: %s\n", osmo_hexdump(pack, len));
		return -1;
	}

	switch (ic6h->type) {
	case 133:	/* router solicitation */
		if (ic6h->code != 0) {
			LOGP(DICMP6, LOGL_NOTICE, "ICMPv6 type 133 but code %d\n", ic6h->code);
			return -1;
		}
		if (!icmpv6_validate_router_solicit(pack, len)) {
			LOGP(DICMP6, LOGL_NOTICE, "Invalid Router Solicitation: %s\n",
				osmo_hexdump(pack, len));
			return -1;
		}
		/* Send router advertisement from GGSN link-local
		 * address to MS link-local address, including prefix
		 * allocated to this PDP context */
		msg = icmpv6_construct_ra(own_ll_addr, &ip6h->ip6_src, pdp_prefix);
		/* Send the constructed RA to the MS */
		gtp_data_req(gsn, pdp, msgb_data(msg), msgb_length(msg));
		msgb_free(msg);
		break;
	default:
		LOGP(DICMP6, LOGL_DEBUG, "Unknown ICMPv6 type %u\n", ic6h->type);
		break;
	}
	return 0;
}
