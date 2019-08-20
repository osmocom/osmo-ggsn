/*
 * OsmoGGSN - Gateway GPRS Support Node
 * Copyright (C) 2002, 2003, 2004 Mondru AB.
 * Copyright (C) 2017-2019 by Harald Welte <laforge@gnumonks.org>
 * Copyright (C) 2019 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

#include "../config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <getopt.h>
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/utils.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_vty.h>
#include <osmocom/ctrl/ports.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/misc.h>

#include "ggsn.h"

void *tall_ggsn_ctx;

static int end = 0;
static int daemonize = 0;
struct ctrl_handle *g_ctrlh;

struct ul255_t qos;
struct ul255_t apn;

static char *config_file = "osmo-ggsn.cfg";

/* To exit gracefully. Used with GCC compilation flag -pg and gprof */
static void signal_handler(int s)
{
	LOGP(DGGSN, LOGL_NOTICE, "signal %d received\n", s);
	switch (s) {
	case SIGINT:
	case SIGTERM:
		LOGP(DGGSN, LOGL_NOTICE, "SIGINT received, shutting down\n");
		end = 1;
		break;
	case SIGABRT:
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_ggsn_ctx, stderr);
		break;
	case SIGUSR2:
		talloc_report_full(tall_vty_ctx, stderr);
		break;
	default:
		break;
	}
}

static void print_usage()
{
	printf("Usage: osmo-ggsn [-h] [-D] [-c configfile] [-V]\n");
}

static void print_help()
{
	printf(	"  Some useful help...\n"
		"  -h --help		This help text\n"
		"  -D --daemonize	Fork the process into a background daemon\n"
		"  -c --config-file	filename The config file to use\n"
		"  -V --version		Print the version of OsmoGGSN\n"
		);
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "daemonize", 0, 0, 'D' },
			{ "config-file", 1, 0, 'c' },
			{ "version", 0, 0, 'V' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hdc:V", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 'D':
			daemonize = 1;
			break;
		case 'c':
			config_file = optarg;
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		}
	}
}

int main(int argc, char **argv)
{
	struct ggsn_ctx *ggsn;
	int rc;

	tall_ggsn_ctx = talloc_named_const(NULL, 0, "OsmoGGSN");
	msgb_talloc_ctx_init(tall_ggsn_ctx, 0);
	g_vty_info.tall_ctx = tall_ggsn_ctx;

	/* Handle keyboard interrupt SIGINT */
	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);

	osmo_init_ignore_signals();
	osmo_init_logging2(tall_ggsn_ctx, &log_info);
	osmo_stats_init(tall_ggsn_ctx);

	vty_init(&g_vty_info);
	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();
	osmo_stats_vty_add_cmds();
	ggsn_vty_init();
	ctrl_vty_init(tall_ggsn_ctx);

	handle_options(argc, argv);

	rate_ctr_init(tall_ggsn_ctx);

	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to open config file: '%s'\n", config_file);
		exit(2);
	}

	rc = telnet_init_dynif(tall_ggsn_ctx, NULL, vty_get_bind_addr(), OSMO_VTY_PORT_GGSN);
	if (rc < 0)
		exit(1);

	g_ctrlh = ctrl_interface_setup_dynip(NULL, ctrl_vty_get_bind_addr(),
					     OSMO_CTRL_PORT_GGSN, NULL);
	if (!g_ctrlh) {
		LOGP(DGGSN, LOGL_ERROR, "Failed to create CTRL interface.\n");
		exit(1);
	}

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

#if 0
	/* qos                                                             */
	qos.l = 3;
	qos.v[2] = (args_info.qos_arg) & 0xff;
	qos.v[1] = ((args_info.qos_arg) >> 8) & 0xff;
	qos.v[0] = ((args_info.qos_arg) >> 16) & 0xff;
#endif

	/* Main select loop */
	while (!end) {
		osmo_select_main(0);
	}

	llist_for_each_entry(ggsn, &g_ggsn_list, list)
		ggsn_stop(ggsn);

	return 0;
}
