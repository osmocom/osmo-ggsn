#pragma once
#include <osmocom/core/in46_addr.h>

void gtp_queue_timer_start(struct gsn_t *gsn);

struct gsn_internal {
	/* IP address of this gsn for signalling */
	bool gsnc_is_v6;
	struct in6_addr gsnc6;

	/* IP address of this gsn for user traffic */
	bool gsnu_is_v6;
	struct in6_addr gsnu6;
};
