#pragma once

#include <stdint.h>

#include <osmocom/gtp/gtp.h>
#include <osmocom/gtp/pdp.h>

int handle_router_mcast(struct gsn_t *gsn, struct pdp_t *pdp,
			const struct in6_addr *pdp_prefix,
			const struct in6_addr *own_ll_addr,
			uint32_t mtu,
			const uint8_t *pack, unsigned len);
int handle_solicited_node_mcast(const uint8_t *pack, unsigned len);
