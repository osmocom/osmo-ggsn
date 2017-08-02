#pragma once
#include <stdint.h>
#include <netinet/in.h>

#include "../gtp/pdp.h"

/* a simple wrapper around an in6_addr to also contain the length of the address,
 * thereby implicitly indicating the address family of the address */
struct in46_addr {
	uint8_t len;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	};
};

extern int in46a_to_af(const struct in46_addr *in);
extern int in46a_to_sas(struct sockaddr_storage *out, const struct in46_addr *in);
extern const char *in46a_ntop(const struct in46_addr *in, char *dst, socklen_t dst_size);
extern int in46a_equal(const struct in46_addr *a, const struct in46_addr *b);
extern int in46a_within_mask(const struct in46_addr *addr, const struct in46_addr *net, size_t prefixlen);

int in46a_to_eua(const struct in46_addr *src, struct ul66_t *eua);
int in46a_from_eua(const struct ul66_t *eua, struct in46_addr *dst);
