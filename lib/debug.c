/*
 * (C) 2014 by Holger Hans Peter Freyther
 */
#include "syserr.h"

#include <osmocom/core/utils.h>

static const struct log_info_cat default_categories[] = {
	[DIP] = {
		.name = "DIP",
		.description = "IP Pool and other groups",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DTUN] = {
		.name = "DTUN",
		.description = "Tunnel interface",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DGGSN] = {
		.name = "DGGSN",
		.description = "GGSN",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DSGSN] = {
		.name = "DSGSN",
		.description = "SGSN Emulator",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};
