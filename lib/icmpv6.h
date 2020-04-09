#pragma once

#include "../gtp/gtp.h"
#include "../gtp/pdp.h"

int handle_router_mcast(struct gsn_t *gsn, struct pdp_t *pdp,
			const struct in6_addr *pdp_prefix,
			const struct in6_addr *own_ll_addr,
			const uint8_t *pack, unsigned len);
