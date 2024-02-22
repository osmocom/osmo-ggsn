/*
 * misc helpers
 * Copyright 2019 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

#include <osmocom/gtp/pdp.h>

#include "ippool.h"
#include "in46_addr.h"

/*! Get the peer of pdp based on IP version used.
*  \param[in] pdp PDP context to select the peer from.
*  \param[in] v4v6 IP version to select. Valid values are 4 and 6.
*  \returns The selected peer matching the given IP version. NULL if not present.
*/
struct ippoolm_t *pdp_get_peer_ipv(struct pdp_t *pdp, bool is_ipv6) {
	uint8_t i;

	for (i = 0; i < 2; i++) {
		struct ippoolm_t * ippool = pdp->peer[i];
		if (!ippool)
			continue;
		if (is_ipv6 && in46a_is_v6(&ippool->addr))
			return ippool;
		else if (!is_ipv6 && in46a_is_v4(&ippool->addr))
			return ippool;
	}
	return NULL;
}
