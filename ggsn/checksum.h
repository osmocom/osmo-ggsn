#pragma once
#include <stdint.h>
#include <netinet/in.h>

uint16_t ip_fast_csum(const void *iph, unsigned int ihl);
uint32_t csum_partial(const void *buff, int len, uint32_t wsum);
uint16_t ip_compute_csum(const void *buff, int len);

uint16_t csum_ipv6_magic(const struct in6_addr *saddr,
			const struct in6_addr *daddr,
			uint32_t len, uint8_t proto, uint32_t csum);

uint16_t csum_fold(uint32_t csum);
