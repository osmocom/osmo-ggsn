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

struct in46_prefix {
	struct in46_addr addr;
	uint8_t prefixlen;
};

extern int in46a_to_af(const struct in46_addr *in);
extern int in46a_to_sas(struct sockaddr_storage *out, const struct in46_addr *in);
extern const char *in46a_ntop(const struct in46_addr *in, char *dst, socklen_t dst_size);
extern const char *in46a_ntoa(const struct in46_addr *in46);
extern const char *in46p_ntoa(const struct in46_prefix *in46p);
extern int in46a_equal(const struct in46_addr *a, const struct in46_addr *b);
extern int in46a_prefix_equal(const struct in46_addr *a, const struct in46_addr *b);
extern int in46a_within_mask(const struct in46_addr *addr, const struct in46_addr *net, size_t prefixlen);
unsigned int in46a_netmasklen(const struct in46_addr *netmask);

int in46a_to_eua(const struct in46_addr *src, unsigned int size, struct ul66_t *eua);
int in46a_from_eua(const struct ul66_t *eua, struct in46_addr *dst);

static inline bool in46a_is_v6(const struct in46_addr *addr) {
	return addr->len == 8 || addr->len == 16;
}

static inline bool in46a_is_v4(const struct in46_addr *addr) {
	return addr->len == sizeof(struct in_addr);
}

void in46a_to_gsna(struct ul16_t *gsna, const struct in46_addr *src);
void in46a_from_gsna(const struct ul16_t *in, struct in46_addr *dst);
