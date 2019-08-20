#pragma once
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

#include <stdbool.h>

struct ippoolm_t;
struct pdp_t;

struct ippoolm_t *pdp_get_peer_ipv(struct pdp_t *pdp, bool is_ipv6);
