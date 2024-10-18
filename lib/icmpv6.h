#pragma once

#include <stdbool.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/endian.h>

#include <osmocom/gtp/gtp.h>
#include <osmocom/gtp/pdp.h>

#define ICMPv6_OPT_TYPE_PREFIX_INFO 0x03

#define foreach_icmpv6_opt(icmpv6_pkt, icmpv6_len, opt_hdr) \
		for (opt_hdr = (struct icmpv6_opt_hdr *)(icmpv6_pkt)->options; \
		     (uint8_t*)(opt_hdr) + sizeof(struct icmpv6_opt_hdr) <= (((uint8_t*)(icmpv6_pkt)) + (icmpv6_len)); \
		     opt_hdr = (struct icmpv6_opt_hdr*)((uint8_t*)(opt_hdr) + (opt_hdr)->len) \
		    )

struct icmpv6_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t csum;
} __attribute__ ((packed));

struct icmpv6_echo_hdr {
	struct icmpv6_hdr hdr;
	uint16_t ident;		/* Identifier */
	uint16_t seq;		/* Sequence number */
	uint8_t data[0];	/* Data */
} __attribute__ ((packed));

/* RFC4861 Section 4.1 */
struct icmpv6_rsol_hdr {
	struct icmpv6_hdr hdr;
	uint32_t reserved;
	uint8_t options[0];
} __attribute__ ((packed));

/* RFC4861 Section 4.2 */
struct icmpv6_radv_hdr {
	struct icmpv6_hdr hdr;
	uint8_t cur_ho_limit;
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t res:6,
		m:1,
		o:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t o:1, m:1, res:6;
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
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t res:6,
		a:1,
		l:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t l:1, a:1, res:6;
#endif
	uint32_t valid_lifetime;
	uint32_t preferred_lifetime;
	uint32_t res2;
	uint8_t prefix[16];
} __attribute__ ((packed));

/* RFC4861 Section 4.6.4 */
struct icmpv6_opt_mtu {
	struct icmpv6_opt_hdr hdr;
	uint16_t reserved;
	uint32_t mtu;
} __attribute__ ((packed));

uint16_t icmpv6_prepend_ip6hdr(struct msgb *msg, const struct in6_addr *saddr,
				  const struct in6_addr *daddr);

struct msgb *icmpv6_construct_rs(const struct in6_addr *saddr);

int handle_router_mcast(struct gsn_t *gsn, struct pdp_t *pdp,
			const struct in6_addr *pdp_prefix,
			const struct in6_addr *own_ll_addr,
			uint32_t mtu,
			const uint8_t *pack, unsigned len);

struct icmpv6_radv_hdr *icmpv6_validate_router_adv(const uint8_t *pack, unsigned len);


/* RFC3307 link-local scope multicast address */
extern const struct in6_addr all_router_mcast_addr;
