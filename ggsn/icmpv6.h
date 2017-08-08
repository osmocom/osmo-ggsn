#pragma once

#include "../gtp/gtp.h"
#include "../gtp/pdp.h"

int handle_router_mcast(struct gsn_t *gsn, struct pdp_t *pdp, const uint8_t *pack, unsigned len);
