/*
 *  OsmoGGSN - Gateway GPRS Support Node
 *  Copyright (C) 2002, 2003, 2004 Mondru AB.
 *  Copyright (C) 2017 Harald Welte <laforge@gnumonks.org>
 *
 *  The contents of this file may be used under the terms of the GNU
 *  General Public License Version 2, provided that the above copyright
 *  notice and this permission notice is included in all copies or
 *  substantial portions of the software.
 *
 */

/*
 * sgsnemu.c
 *
 */

#include "config.h"

#ifdef __linux__
#define _GNU_SOURCE 1		/* strdup() prototype, broken arpa/inet.h */
#endif

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>

#include <ctype.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <time.h>

#if defined(__linux__)
#if defined(HAVE_IN6_ADDR_GEN_MODE_NONE)
#include <linux/if_link.h>
#endif // HAVE_IN6_ADDR_GEN_MODE_NONE
#endif

#include "../lib/tun.h"
#include "../lib/ippool.h"
#include "../lib/syserr.h"
#include "../lib/netns.h"
#include "../lib/icmpv6.h"
#include "../gtp/pdp.h"
#include "../gtp/gtp.h"
#include "cmdline.h"

#define IPADDRLEN 256		/* Character length of addresses */
#define MAXCONTEXTS 1024	/* Max number of allowed contexts */

/* HASH tables for IP address allocation */
struct pdp_peer_sgsnemu_ctx;
struct iphash_t {
	uint8_t inuse;		/* 0=free. 1=used by somebody */
	struct iphash_t *ipnext;
	struct pdp_peer_sgsnemu_ctx *ctx;
	struct in46_addr addr;
};
struct iphash_t *iphash[MAXCONTEXTS];

struct pdp_peer_sgsnemu_ctx {
	struct iphash_t hash_v4;
	struct iphash_t hash_v6_ll;
	struct iphash_t hash_v6_global;
	struct pdp_t *pdp;
};
struct pdp_peer_sgsnemu_ctx ctx_arr[MAXCONTEXTS];

/* State variable used for ping  */
/* 0: Idle                       */
/* 1: Wait_connect               */
/* 2: Connected                  */
/* 3: Done                       */
/* 4: Wait_disconnect            */
/* 5: Disconnected               */
volatile sig_atomic_t state = 0;

struct gsn_t *gsn = NULL;	/* GSN instance */
struct tun_t *tun = NULL;	/* TUN instance */
int maxfd = 0;			/* For select() */
int echoversion = 1;		/* First try this version */
void *tall_sgsnemu_ctx;		/* root talloc ctx */
#if defined(__linux__)
int netns = -1;			/* network namespace */
#endif

/* Struct with local versions of gengetopt options */
struct {
	int debug;		/* Print debug messages */
	int createif;		/* Create local network interface */
	char *tun_dev_name;
	char *netns;
	struct in46_addr netaddr;	/* Network interface  */
	size_t prefixlen;
	char *ipup, *ipdown;	/* Filename of scripts */
	int defaultroute;	/* Set up default route */
	struct in46_addr pinghost;	/* Remote ping host    */
	int pingrate;
	int pingsize;
	int pingcount;
	int pingquiet;
	struct in_addr listen;
	struct in_addr remote;
	struct in_addr dns;
	int contexts;		/* Number of contexts to create */
	int timelimit;		/* Number of seconds to be connected */
	char *statedir;
	uint64_t imsi;
	uint8_t nsapi;
	int gtpversion;
	struct ul255_t pco;
	struct ul255_t qos;
	uint16_t cch;
	struct ul255_t apn;
	uint8_t selmode;
	struct ul255_t rattype;
	int rattype_given;
	struct ul255_t userloc;
	int userloc_given;
	struct ul255_t rai;
	int rai_given;
	struct ul255_t mstz;
	int mstz_given;
	struct ul255_t imeisv;
	int imeisv_given;
	struct ul16_t msisdn;
	int norecovery_given;
	int tx_gpdu_seq;
	uint8_t pdp_type;
} options;

/* Definitions to use for PING. Most of the ping code was derived from */
/* the original ping program by Mike Muuss                             */

/* IP header and ICMP echo header */
#define CREATEPING_MAX  2048
#define CREATEPING_IP     20
#define CREATEPING_ICMP    8

struct ip_ping {
	uint8_t ipver;		/* Type and header length */
	uint8_t tos;		/* Type of Service */
	uint16_t length;	/* Total length */
	uint16_t fragid;	/* Identifier */
	uint16_t offset;	/* Flags and fragment offset */
	uint8_t ttl;		/* Time to live */
	uint8_t protocol;	/* Protocol */
	uint16_t ipcheck;	/* Header checksum */
	uint32_t src;		/* Source address */
	uint32_t dst;		/* Destination */
	uint8_t type;		/* Type and header length */
	uint8_t code;		/* Code */
	uint16_t checksum;	/* Header checksum */
	uint16_t ident;		/* Identifier */
	uint16_t seq;		/* Sequence number */
	uint8_t data[CREATEPING_MAX];	/* Data */
} __attribute__ ((packed));

struct ip6_ping {
	struct icmpv6_echo_hdr hdr;
	uint8_t data[CREATEPING_MAX];	/* Data */
} __attribute__ ((packed));

/* Statistical values for ping */
int nreceived = 0;
int ntreceived = 0;
int ntransmitted = 0;
int tmin = 999999999;
int tmax = 0;
int tsum = 0;
int pingseq = 0;		/* Ping sequence counter */
struct timeval firstping;

static void signal_handler(int signo)
{
	if (state == 2)
		state = 3;  /* Tell main loop to finish. */
}

static int ipset(struct iphash_t *ipaddr, struct in46_addr *addr)
{
	int hash = ippool_hash(addr) % MAXCONTEXTS;
	struct iphash_t *h;
	struct iphash_t *prev = NULL;

	printf("Adding IP to local pool: %s\n", in46a_ntoa(addr));

	ipaddr->ipnext = NULL;
	ipaddr->addr = *addr;
	for (h = iphash[hash]; h; h = h->ipnext)
		prev = h;
	if (!prev)
		iphash[hash] = ipaddr;
	else
		prev->ipnext = ipaddr;
	return 0;
}

static int ipdel(struct iphash_t *ipaddr)
{
	int hash = ippool_hash(&ipaddr->addr) % MAXCONTEXTS;
	struct iphash_t *h;
	struct iphash_t *prev = NULL;
	for (h = iphash[hash]; h; h = h->ipnext) {
		if (h == ipaddr) {
			if (!prev)
				iphash[hash] = h->ipnext;
			else
				prev->ipnext = h->ipnext;
			return 0;
		}
		prev = h;
	}
	return EOF;		/* End of linked list and not found */
}

static int ipget(struct iphash_t **ipaddr, struct in46_addr *addr)
{
	int hash = ippool_hash(addr) % MAXCONTEXTS;
	struct iphash_t *h;
	for (h = iphash[hash]; h; h = h->ipnext) {
		if (in46a_equal(&h->addr, addr)) {
			*ipaddr = h;
			return 0;
		}
	}
	return EOF;		/* End of linked list and not found */
}

/* Used to write process ID to file. Assume someone else will delete */
static void log_pid(char *pidfile)
{
	FILE *file;
	mode_t oldmask;

	oldmask = umask(022);
	file = fopen(pidfile, "w");
	umask(oldmask);
	if (!file)
		return;
	fprintf(file, "%d\n", (int)getpid());
	fclose(file);
}

static int process_options(int argc, char **argv)
{
	/* gengeopt declarations */
	struct gengetopt_args_info args_info;

	struct hostent *host;
	unsigned int n;
	uint16_t i;
	uint8_t a;
	uint8_t b;
	char *tmp;
	char *pch;
	char *type;
	char *mcc;
	char *mnc;
	char *tok, *apn;
	char *lac;
	int lac_d;
	char *rest;
	char *userloc_el[] = { "TYPE", "MCC", "MNC", "LAC", "REST" };
	char *rai_el[] = { "MCC", "MNC", "LAC", "RAC" };
	char *mstz_el[] = { "SIGN", "QUARTERS", "DST" };
	int sign;
	int nbquarters;
	int DST;

	if (cmdline_parser(argc, argv, &args_info) != 0)
		return -1;
	if (args_info.debug_flag) {
		if (args_info.remote_arg)
			printf("remote: %s\n", args_info.remote_arg);
		if (args_info.listen_arg)
			printf("listen: %s\n", args_info.listen_arg);
		if (args_info.conf_arg)
			printf("conf: %s\n", args_info.conf_arg);
		printf("debug: %d\n", args_info.debug_flag);
		if (args_info.imsi_arg)
			printf("imsi: %s\n", args_info.imsi_arg);
		printf("qos: %#08x\n", args_info.qos_arg);
		printf("qose1: %#0.16llx\n", args_info.qose1_arg);
		printf("qose2: %#04x\n", args_info.qose2_arg);
		printf("qose3: %#06x\n", args_info.qose3_arg);
		printf("qose4: %#06x\n", args_info.qose4_arg);
		printf("charging: %#04x\n", args_info.charging_arg);
		if (args_info.apn_arg)
			printf("apn: %s\n", args_info.apn_arg);
		if (args_info.msisdn_arg)
			printf("msisdn: %s\n", args_info.msisdn_arg);
		if (args_info.uid_arg)
			printf("uid: %s\n", args_info.uid_arg);
		if (args_info.pwd_arg)
			printf("pwd: %s\n", args_info.pwd_arg);
		if (args_info.pidfile_arg)
			printf("pidfile: %s\n", args_info.pidfile_arg);
		if (args_info.statedir_arg)
			printf("statedir: %s\n", args_info.statedir_arg);
		if (args_info.dns_arg)
			printf("dns: %s\n", args_info.dns_arg);
		printf("contexts: %d\n", args_info.contexts_arg);
		printf("timelimit: %d\n", args_info.timelimit_arg);
		printf("createif: %d\n", args_info.createif_flag);
		if (args_info.tun_device_arg)
			printf("tun-device: %s\n", args_info.tun_device_arg);
		if (args_info.netns_arg)
			printf("netns: %s\n", args_info.netns_arg);
		if (args_info.ipup_arg)
			printf("ipup: %s\n", args_info.ipup_arg);
		if (args_info.ipdown_arg)
			printf("ipdown: %s\n", args_info.ipdown_arg);
		printf("defaultroute: %d\n", args_info.defaultroute_flag);
		if (args_info.pinghost_arg)
			printf("pinghost: %s\n", args_info.pinghost_arg);
		printf("pingrate: %d\n", args_info.pingrate_arg);
		printf("pingsize: %d\n", args_info.pingsize_arg);
		printf("pingcount: %d\n", args_info.pingcount_arg);
		printf("pingquiet: %d\n", args_info.pingquiet_flag);
		printf("norecovery: %d\n", args_info.norecovery_flag);
		printf("no-tx-gpdu-seq: %d\n", args_info.no_tx_gpdu_seq_flag);
	}

	/* Try out our new parser */

	if (args_info.conf_arg) {
		if (cmdline_parser_configfile
		    (args_info.conf_arg, &args_info, 0, 0, 0) != 0)
			return -1;
		if (args_info.debug_flag) {
			printf("cmdline_parser_configfile\n");
			if (args_info.remote_arg)
				printf("remote: %s\n", args_info.remote_arg);
			if (args_info.listen_arg)
				printf("listen: %s\n", args_info.listen_arg);
			if (args_info.conf_arg)
				printf("conf: %s\n", args_info.conf_arg);
			printf("debug: %d\n", args_info.debug_flag);
			if (args_info.imsi_arg)
				printf("imsi: %s\n", args_info.imsi_arg);
			printf("qos: %#08x\n", args_info.qos_arg);
			printf("qose1: %#0.16llx\n", args_info.qose1_arg);
			printf("qose2: %#04x\n", args_info.qose2_arg);
			printf("qose3: %#06x\n", args_info.qose3_arg);
			printf("qose4: %#06x\n", args_info.qose4_arg);
			printf("charging: %#04x\n", args_info.charging_arg);
			if (args_info.apn_arg)
				printf("apn: %s\n", args_info.apn_arg);
			if (args_info.msisdn_arg)
				printf("msisdn: %s\n", args_info.msisdn_arg);
			if (args_info.uid_arg)
				printf("uid: %s\n", args_info.uid_arg);
			if (args_info.pwd_arg)
				printf("pwd: %s\n", args_info.pwd_arg);
			if (args_info.pidfile_arg)
				printf("pidfile: %s\n", args_info.pidfile_arg);
			if (args_info.statedir_arg)
				printf("statedir: %s\n",
				       args_info.statedir_arg);
			if (args_info.dns_arg)
				printf("dns: %s\n", args_info.dns_arg);
			printf("contexts: %d\n", args_info.contexts_arg);
			printf("timelimit: %d\n", args_info.timelimit_arg);
			printf("createif: %d\n", args_info.createif_flag);
			if (args_info.tun_device_arg)
				printf("tun-device: %s\n", args_info.tun_device_arg);
			if (args_info.netns_arg)
				printf("netns: %s\n", args_info.netns_arg);
			if (args_info.ipup_arg)
				printf("ipup: %s\n", args_info.ipup_arg);
			if (args_info.ipdown_arg)
				printf("ipdown: %s\n", args_info.ipdown_arg);
			printf("defaultroute: %d\n",
			       args_info.defaultroute_flag);
			if (args_info.pinghost_arg)
				printf("pinghost: %s\n",
				       args_info.pinghost_arg);
			printf("pingrate: %d\n", args_info.pingrate_arg);
			printf("pingsize: %d\n", args_info.pingsize_arg);
			printf("pingcount: %d\n", args_info.pingcount_arg);
			printf("pingquiet: %d\n", args_info.pingquiet_flag);
			printf("norecovery: %d\n", args_info.norecovery_flag);
			printf("no-tx-gpdu-seq: %d\n", args_info.no_tx_gpdu_seq_flag);
		}
	}

	/* Handle each option */

	/* foreground                                                   */
	/* If fg flag not given run as a daemon                         */
	/* Do not allow sgsnemu to run as deamon
	   if (!args_info.fg_flag)
	   {
	   closelog();
	   freopen("/dev/null", "w", stdout);
	   freopen("/dev/null", "w", stderr);
	   freopen("/dev/null", "r", stdin);
	   daemon(0, 0);
	   openlog(PACKAGE, LOG_PID, LOG_DAEMON);
	   }                                                             */

	/* debug                                                        */
	options.debug = args_info.debug_flag;

	/* pidfile */
	/* This has to be done after we have our final pid */
	if (args_info.pidfile_arg) {
		log_pid(args_info.pidfile_arg);
	}

	/* dns                                                          */
	/* If no dns option is given use system default                 */
	/* Do hostname lookup to translate hostname to IP address       */
	printf("\n");
	if (args_info.dns_arg) {
		if (!(host = gethostbyname(args_info.dns_arg))) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"Invalid DNS address: %s!", args_info.dns_arg);
			return -1;
		} else {
			memcpy(&options.dns.s_addr, host->h_addr,
			       host->h_length);
			_res.nscount = 1;
			_res.nsaddr_list[0].sin_addr = options.dns;
			printf("Using DNS server:      %s (%s)\n",
			       args_info.dns_arg, inet_ntoa(options.dns));
		}
	} else {
		options.dns.s_addr = 0;
		printf("Using default DNS server\n");
	}

	/* listen                                                       */
	/* If no listen option is specified listen to any local port    */
	/* Do hostname lookup to translate hostname to IP address       */
	if (args_info.listen_arg) {
		if (!(host = gethostbyname(args_info.listen_arg))) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"Invalid listening address: %s!",
				args_info.listen_arg);
			return -1;
		} else {
			memcpy(&options.listen.s_addr, host->h_addr,
			       host->h_length);
			printf("Local IP address is:   %s (%s)\n",
			       args_info.listen_arg, inet_ntoa(options.listen));
		}
	} else {
		SYS_ERR(DSGSN, LOGL_ERROR, 0,
			"Listening address must be specified!");
		return -1;
	}

	/* remote                                                       */
	/* If no remote option is specified terminate                   */
	/* Do hostname lookup to translate hostname to IP address       */
	if (args_info.remote_arg) {
		if (!(host = gethostbyname(args_info.remote_arg))) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"Invalid remote address: %s!",
				args_info.remote_arg);
			return -1;
		} else {
			memcpy(&options.remote.s_addr, host->h_addr,
			       host->h_length);
			printf("Remote IP address is:  %s (%s)\n",
			       args_info.remote_arg, inet_ntoa(options.remote));
		}
	} else {
		SYS_ERR(DSGSN, LOGL_ERROR, 0,
			"No remote address given!");
		return -1;
	}

	/* imsi                                                            */
	if (strlen(args_info.imsi_arg) < 6 || strlen(args_info.imsi_arg) > 15) {
		printf("Invalid IMSI\n");
		return -1;
	}

	options.imsi = imsi_str2gtp(args_info.imsi_arg);

	printf("IMSI is:               %s (%#08llx)\n",
	       args_info.imsi_arg, options.imsi);

	/* nsapi                                                           */
	if ((args_info.nsapi_arg > 15) || (args_info.nsapi_arg < 0)) {
		printf("Invalid NSAPI\n");
		return -1;
	}
	options.nsapi = args_info.nsapi_arg;
	printf("Using NSAPI:           %d\n", args_info.nsapi_arg);

	/* qos                                                             */
	options.qos.l = 4;
	options.qos.v[3] = (args_info.qos_arg) & 0xff;
	options.qos.v[2] = ((args_info.qos_arg) >> 8) & 0xff;
	options.qos.v[1] = ((args_info.qos_arg) >> 16) & 0xff;
	options.qos.v[0] = ((args_info.qos_arg) >> 24) & 0xff;
	/* Extensions according to 3GPP TS 24.008                          */
	if (args_info.qose1_given == 1) {
		options.qos.l = 12;
		options.qos.v[11] = (args_info.qose1_arg) & 0xff;
		options.qos.v[10] = ((args_info.qose1_arg) >> 8) & 0xff;
		options.qos.v[9] = ((args_info.qose1_arg) >> 16) & 0xff;
		options.qos.v[8] = ((args_info.qose1_arg) >> 24) & 0xff;
		options.qos.v[7] = ((args_info.qose1_arg) >> 32) & 0xff;
		options.qos.v[6] = ((args_info.qose1_arg) >> 40) & 0xff;
		options.qos.v[5] = ((args_info.qose1_arg) >> 48) & 0xff;
		options.qos.v[4] = ((args_info.qose1_arg) >> 56) & 0xff;
		if (args_info.qose2_given == 1) {
			options.qos.l = 13;
			options.qos.v[12] = (args_info.qose2_arg) & 0xff;
			if (args_info.qose3_given == 1) {
				options.qos.l = 15;
				options.qos.v[14] =
				    (args_info.qose3_arg) & 0xff;
				options.qos.v[13] =
				    ((args_info.qose3_arg) >> 8) & 0xff;
				if (args_info.qose4_given == 1) {
					options.qos.l = 17;
					options.qos.v[16] =
					    (args_info.qose4_arg) & 0xff;
					options.qos.v[15] =
					    ((args_info.qose4_arg) >> 8) & 0xff;
				}
			}
		}
	}

	/* charging                                                        */
	options.cch = args_info.charging_arg;

	/* contexts                                                        */
	if (args_info.contexts_arg > MAXCONTEXTS) {
		printf("Contexts has to be less than %d\n", MAXCONTEXTS);
		return -1;
	}
	options.contexts = args_info.contexts_arg;

	/* Timelimit                                                       */
	options.timelimit = args_info.timelimit_arg;

	/* gtpversion                                                      */
	if ((args_info.gtpversion_arg > 1) || (args_info.gtpversion_arg < 0)) {
		printf("Invalid GTP version\n");
		return -1;
	}
	options.gtpversion = args_info.gtpversion_arg;
	printf("Using GTP version:     %d\n", args_info.gtpversion_arg);

	/* apn                                                             */
	if (strlen(args_info.apn_arg) > (sizeof(options.apn.v) - 1)) {
		printf("Invalid APN\n");
		return -1;
	}
	options.apn.l = strlen(args_info.apn_arg) + 1;

	apn = (char *)options.apn.v;
	for (tok = strtok(args_info.apn_arg, ".");
	     tok != NULL;
	     tok = strtok(NULL, ".")) {
		     size_t len = strlen(tok);

		     *apn++ = (char)len;
		     strncpy(apn, tok, len);
		     apn += len;
	     }

	printf("Using APN:             %s\n", args_info.apn_arg);

	/* selmode */
	options.selmode = args_info.selmode_arg;
	printf("Using selection mode:  %d\n", args_info.selmode_arg);

	/* rattype */
	if (args_info.rattype_given == 1) {
		options.rattype_given = 1;
		options.rattype.l = 1;
		options.rattype.v[0] = args_info.rattype_arg;
		printf("Using RAT Type:  %d\n", args_info.rattype_arg);
	}

	/* userloc */
	if (args_info.userloc_given == 1) {
		printf("Using User Location Information:  %s\n",
		       args_info.userloc_arg);
		tmp = args_info.userloc_arg;
		n = 0;
		pch = strtok(tmp, ".");
		while (pch != NULL) {
			userloc_el[n] = pch;
			pch = strtok(NULL, ".");
			n++;
		}

		options.userloc_given = 1;
		options.userloc.l = 8;

		/* 3GPP Geographic Location Type t0 / t1 / t2 */
		type = userloc_el[0];
		printf("->type : %c\n", type[0]);
		if ((strlen(type) != 1) || (!isdigit(type[0]))) {
			printf("Invalid type \n");
			return -1;
		}
		/* options.userloc.v[0] = 0x00 */
		options.userloc.v[0] = type[0] - 48;

		/* MCC */
		mcc = userloc_el[1];
		printf("->mcc : %s\n", mcc);
		if (strlen(mcc) != 3) {
			printf("Invalid MCC length\n");
			return -1;
		}

		/* MNC */
		mnc = userloc_el[2];
		printf("->mnc : %s\n", mnc);

		/* octet 5 - MCC Digit 2 - MCC Digit 1 */
		/* options.userloc.v[1] = 0x52 */
		a = (uint8_t) (mcc[0] - 48);
		b = (uint8_t) (mcc[1] - 48);
		options.userloc.v[1] = 16 * b + a;

		/* octet 6 - MNC Digit 3 - MCC Digit 3 */
		/* options.userloc.v[2] = 0xf0 */
		a = (uint8_t) (mcc[2] - 48);

		if ((strlen(mnc) > 3) || (strlen(mnc) < 2)) {
			printf("Invalid MNC length\n");
			return -1;
		}
		if (strlen(mnc) == 2) {
			b = 15;
		}
		if (strlen(mnc) == 3) {
			b = (uint8_t) (mnc[2] - 48);
		}
		options.userloc.v[2] = 16 * b + a;

		/* octet 7 - MNC Digit 2 - MNC Digit 1 */
		/* options.userloc.v[3] = 0x99 */
		a = (uint8_t) (mnc[0] - 48);
		b = (uint8_t) (mnc[1] - 48);
		options.userloc.v[3] = 16 * b + a;

		/* LAC */
		lac = userloc_el[3];
		/*options.userloc.v[4] = 0x12 ;  */
		/*options.userloc.v[5] = 0x10 ;  */
		printf("->LAC: %s\n", lac);
		lac_d = atoi(lac);
		if (lac_d > 65535 || lac_d < 1) {
			printf("Invalid LAC\n");
			return -1;
		}
		i = lac_d >> 8;
		options.userloc.v[4] = i;	/* octet 8 - LAC */
		options.userloc.v[5] = lac_d;	/* octet 9 - LAC */

		/* CI/SAC/RAC */
		rest = userloc_el[4];
		printf("->CI/SAC/RAC : %s\n", rest);
		lac_d = atoi(rest);
		if (lac_d > 65535 || lac_d < 1) {
			printf("Invalid CI/SAC/RAC\n");
			return -1;
		}
		/*options.userloc.v[6] = 0x04 ; */
		/*options.userloc.v[7] = 0xb7 ; */
		i = lac_d >> 8;
		options.userloc.v[6] = i;	/* octet 10 - t0,CI / t1,SAC / t2,RAC  */
		options.userloc.v[7] = lac_d;	/* octet 11 - t0,CI / t1,SAC / t2,RAC  */
	}

	/* RAI */
	if (args_info.rai_given == 1) {
		printf("Using RAI:  %s\n", args_info.rai_arg);
		tmp = args_info.rai_arg;
		n = 0;
		pch = strtok(tmp, ".");
		while (pch != NULL) {
			rai_el[n] = pch;
			pch = strtok(NULL, ".");
			n++;
		}

		options.rai_given = 1;
		options.rai.l = 6;

		/* MCC */
		mcc = rai_el[0];
		printf("->mcc : %s\n", mcc);
		if (strlen(mcc) != 3) {
			printf("Invalid MCC length\n");
			return -1;
		}

		/* MNC */
		mnc = rai_el[1];
		printf("->mnc : %s\n", mnc);

		a = (uint8_t) (mcc[0] - 48);
		b = (uint8_t) (mcc[1] - 48);
		options.rai.v[0] = 16 * b + a;

		/* octet 3 - MNC Digit 3 - MCC Digit 3 */
		a = (uint8_t) (mcc[2] - 48);

		if ((strlen(mnc) > 3) || (strlen(mnc) < 2)) {
			printf("Invalid MNC length\n");
			return -1;
		}
		if (strlen(mnc) == 2) {
			b = 15;
		}
		if (strlen(mnc) == 3) {
			b = (uint8_t) (mnc[2] - 48);
		}
		options.rai.v[1] = 16 * b + a;

		/* octet 4 - MNC Digit 2 - MNC Digit 1 */
		a = (uint8_t) (mnc[0] - 48);
		b = (uint8_t) (mnc[1] - 48);
		options.rai.v[2] = 16 * b + a;

		/* LAC */
		lac = rai_el[2];
		printf("->LAC: %s\n", lac);
		lac_d = atoi(lac);
		if (lac_d > 65535 || lac_d < 1) {
			printf("Invalid LAC\n");
			return -1;
		}
		i = lac_d >> 8;
		options.rai.v[3] = i;	/* octet 5 - LAC */
		options.rai.v[4] = lac_d;	/* octet 6 - LAC */

		/* RAC */
		rest = rai_el[3];
		printf("->RAC : %s\n", rest);
		lac_d = atoi(rest);
		if (lac_d > 255 || lac_d < 1) {
			printf("Invalid RAC\n");
			return -1;
		}
		options.rai.v[5] = lac_d;	/* octet 7 - RAC  */
	}

	/* mstz */
	if (args_info.mstz_given == 1) {
		options.mstz_given = 1;
		options.mstz.l = 2;

		printf("Using MS Time Zone:  %s\n", args_info.mstz_arg);
		tmp = args_info.mstz_arg;
		n = 0;
		pch = strtok(tmp, ".");
		while (pch != NULL) {
			mstz_el[n] = pch;
			pch = strtok(NULL, ".");
			n++;
		}

		/* sign */
		sign = atoi(mstz_el[0]);
		printf("->Sign (0=+ / 1=-): %d\n", sign);
		if (sign != 0 && sign != 1) {
			printf("Invalid Sign \n");
			return -1;
		}
		/* nbquarters */
		nbquarters = atoi(mstz_el[1]);
		printf("->Number of Quarters of an Hour : %d\n", nbquarters);
		if (nbquarters < 0 || nbquarters > 79) {
			printf("Invalid Number of Quarters \n");
			return -1;
		}
		/* DST */
		DST = atoi(mstz_el[2]);
		printf("->Daylight Saving Time Adjustment : %d\n", DST);
		if (DST < 0 || DST > 3) {
			printf("Invalid DST Adjustment \n");
			return -1;
		}
		/* 12345678
		   bits 123 = unit of # of quarters of an hour
		   bits 678 = # of quarters of an hour / 10
		   bit 5 = sign
		 */
		i = nbquarters % 10;
		i = i << 4;
		i = i + nbquarters / 10 + 8 * sign;
		/* options.mstz.v[0] = 0x69 ; */
		/* options.mstz.v[1] = 0x01 ; */
		options.mstz.v[0] = i;
		options.mstz.v[1] = DST;
		n = (i & 0x08) ? '-' : '+';
		printf
		    ("->Human Readable MS Time Zone  : GMT %c %d hours %d minutes\n",
		     n, nbquarters / 4, nbquarters % 4 * 15);
	}

	/* imeisv */
	if (args_info.imeisv_given == 1) {
		options.imeisv_given = 1;
		if (strlen(args_info.imeisv_arg) != 16) {
			printf("Invalid IMEI(SV)\n");
			return -1;
		}
		options.imeisv.l = 8;
		for (n = 0; n < 8; n++) {
			a = (uint8_t) (args_info.imeisv_arg[2 * n] - 48);
			b = (uint8_t) (args_info.imeisv_arg[2 * n + 1] - 48);
			options.imeisv.v[n] = 16 * b + a;
		}
		printf("Using IMEI(SV):  %s\n", args_info.imeisv_arg);
	}

	/* msisdn                                                          */
	if (strlen(args_info.msisdn_arg) > (sizeof(options.msisdn.v) - 1)) {
		printf("Invalid MSISDN\n");
		return -1;
	}
	options.msisdn.l = 1;
	options.msisdn.v[0] = 0x91;	/* International format */
	for (n = 0; n < strlen(args_info.msisdn_arg); n++) {
		if ((n % 2) == 0) {
			options.msisdn.v[((int)n / 2) + 1] =
			    args_info.msisdn_arg[n] - 48 + 0xf0;
			options.msisdn.l += 1;
		} else {
			options.msisdn.v[((int)n / 2) + 1] =
			    (options.msisdn.v[((int)n / 2) + 1] & 0x0f) +
			    (args_info.msisdn_arg[n] - 48) * 16;
		}
	}
	printf("Using MSISDN:          %s\n", args_info.msisdn_arg);

	/* UID and PWD */
	/* Might need to also insert stuff like DNS etc. */
	if ((strlen(args_info.uid_arg) + strlen(args_info.pwd_arg) + 10) >
	    (sizeof(options.pco.v) - 1)) {
		printf("invalid UID and PWD\n");
		return -1;
	}
	options.pco.l =
	    strlen(args_info.uid_arg) + strlen(args_info.pwd_arg) + 10;
	options.pco.v[0] = 0x80;	/* PPP */
	options.pco.v[1] = 0xc0;	/* PAP */
	options.pco.v[2] = 0x23;
	options.pco.v[3] =
	    strlen(args_info.uid_arg) + strlen(args_info.pwd_arg) + 6;
	options.pco.v[4] = 0x01;	/* Authenticate request */
	options.pco.v[5] = 0x01;
	options.pco.v[6] = 0x00;	/* MSB of length */
	options.pco.v[7] =
	    strlen(args_info.uid_arg) + strlen(args_info.pwd_arg) + 6;
	options.pco.v[8] = strlen(args_info.uid_arg);
	memcpy(&options.pco.v[9], args_info.uid_arg, strlen(args_info.uid_arg));
	options.pco.v[9 + strlen(args_info.uid_arg)] =
	    strlen(args_info.pwd_arg);
	memcpy(&options.pco.v[10 + strlen(args_info.uid_arg)],
	       args_info.pwd_arg, strlen(args_info.pwd_arg));

	/* createif */
	options.createif = args_info.createif_flag;
	options.tun_dev_name = args_info.tun_device_arg;
	options.netns = args_info.netns_arg;

	/* net                                                          */
	/* Store net as in_addr net and mask                            */
	if (args_info.net_arg) {
		if (ippool_aton
		    (&options.netaddr, &options.prefixlen, args_info.net_arg, 0)) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"Invalid network address: %s!",
				args_info.net_arg);
			exit(1);
		}
	} else {
		options.prefixlen = 0;
		memset(&options.netaddr, 0, sizeof(options.netaddr));
	}

	/* ipup */
	options.ipup = args_info.ipup_arg;

	/* ipdown */
	options.ipdown = args_info.ipdown_arg;

	/* statedir */
	options.statedir = args_info.statedir_arg;

	/* defaultroute */
	options.defaultroute = args_info.defaultroute_flag;

	/* PDP Type */
	if (!strcmp(args_info.pdp_type_arg, "v6"))
		options.pdp_type = PDP_EUA_TYPE_v6;
	else if (!strcmp(args_info.pdp_type_arg, "v4"))
		options.pdp_type = PDP_EUA_TYPE_v4;
	else {
		SYS_ERR(DSGSN, LOGL_ERROR, 0, "Unsupported/unknown PDP Type '%s'\n",
			args_info.pdp_type_arg);
		return -1;
	}

	/* pinghost                                                     */
	/* Store ping host as in_addr                                   */
	if (args_info.pinghost_arg) {
		struct addrinfo hints;
		struct addrinfo *result;
		memset(&hints, 0, sizeof(struct addrinfo));
		switch (options.pdp_type) {
		case PDP_EUA_TYPE_v4:
			hints.ai_family = AF_INET;
			break;
		case PDP_EUA_TYPE_v6:
			hints.ai_family = AF_INET6;
			break;
		default:
			SYS_ERR(DSGSN, LOGL_ERROR, 0, "lookup(AF_UNSPEC) %d", options.pdp_type);
			hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
		}
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = 0;
		hints.ai_protocol = 0;
		hints.ai_canonname = NULL;
		hints.ai_addr = NULL;
		hints.ai_next = NULL;
		if ((i = getaddrinfo(args_info.pinghost_arg, NULL, &hints, &result)) != 0) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"Invalid ping host '%s': %s",
				args_info.pinghost_arg, gai_strerror(i));
			return -1;
		} else {
			switch (result->ai_family) {
			case AF_INET:
				options.pinghost.len = sizeof(struct in_addr);
				options.pinghost.v4 = ((struct sockaddr_in*)result->ai_addr)->sin_addr;
				SYS_ERR(DSGSN, LOGL_ERROR, 0, 	"AF_INET %d", options.pinghost.len);
				break;
			case AF_INET6:
				options.pinghost.len = sizeof(struct in6_addr);
				options.pinghost.v6 = ((struct sockaddr_in6*)result->ai_addr)->sin6_addr;
				break;
			}
			printf("Using ping host:       %s (%s)\n",
			       args_info.pinghost_arg,
			       in46a_ntoa(&options.pinghost));
			freeaddrinfo(result);
		}
	}

	/* Other ping parameters                                        */
	options.pingrate = args_info.pingrate_arg;
	options.pingsize = args_info.pingsize_arg;
	options.pingcount = args_info.pingcount_arg;
	options.pingquiet = args_info.pingquiet_flag;

	/* norecovery */
	options.norecovery_given = args_info.norecovery_flag;

	if (args_info.no_tx_gpdu_seq_flag)
		options.tx_gpdu_seq = 0;
	else
		options.tx_gpdu_seq = 1;

	return 0;

}

/* write a single value to a /proc file */
static int proc_write(const char *path, const char *value)
{
        int ret;
        FILE *f;

        f = fopen(path, "w");
        if (!f) {
                SYS_ERR(DSGSN, LOGL_ERROR, 0, "fopen(%s) failed!\n", path);
                return -1;
        }

        if ((ret = fputs(value, f)) < 0) {
                SYS_ERR(DSGSN, LOGL_ERROR, 0, "proc_write(%s, %s) failed!\n", path, value);
        } else {
                ret = 0;
        }
        fclose(f);
        return ret;
}

/* Write value of to /proc/sys/net/ipv6/conf file for given device.
 * Memory is dynamically allocated, caller must free it later. */
static int proc_ipv6_conf_write(const char *dev, const char *file, const char *value)
{
        const char *fmt = "/proc/sys/net/ipv6/conf/%s/%s";
        char path[strlen(fmt) + strlen(dev) + strlen(file)+1];
        snprintf(path, sizeof(path), fmt, dev, file);
        return proc_write(path, value);
}

static char *print_ipprot(int t)
{
	struct protoent *pe = getprotobynumber(t);

	if (!pe)
		return "Unknown";
	else
		return pe->p_name;
}

static char *print_icmptype(int t)
{
	static char *ttab[] = {
		"Echo Reply",
		"ICMP 1",
		"ICMP 2",
		"Dest Unreachable",
		"Source Quench",
		"Redirect",
		"ICMP 6",
		"ICMP 7",
		"Echo",
		"ICMP 9",
		"ICMP 10",
		"Time Exceeded",
		"Parameter Problem",
		"Timestamp",
		"Timestamp Reply",
		"Info Request",
		"Info Reply"
	};
	if (t < 0 || t > 16)
		return ("OUT-OF-RANGE");
	return (ttab[t]);
}

static int msisdn_add(struct ul16_t *src, struct ul16_t *dst, int add)
{
	unsigned int n;
	uint64_t i64 = 0;
	uint8_t msa[sizeof(i64) * 3];	/* Allocate 3 digits per octet (0..255) */
	unsigned int msalen = 0;

	/* Convert to uint64_t from ul16_t format (most significant digit first) */
	/* ul16_t format always starts with 0x91 to indicate international format */
	/* In ul16_t format 0x0f/0xf0 indicates that digit is not used */
	for (n = 0; n < src->l; n++) {
		if ((src->v[n] & 0x0f) != 0x0f) {
			i64 *= 10;
			i64 += src->v[n] & 0x0f;
		}
		if ((src->v[n] & 0xf0) != 0xf0) {
			i64 *= 10;
			i64 += (src->v[n] & 0xf0) >> 4;
		}
	}

	i64 += add;

	/* Generate array with least significant digit in first octet */
	while (i64) {
		msa[msalen++] = i64 % 10;
		i64 = i64 / 10;
	}

	/* Convert back to ul16_t format */
	for (n = 0; n < msalen; n++) {
		if ((n % 2) == 0) {
			dst->v[((int)n / 2)] = msa[msalen - n - 1] + 0xf0;
			dst->l += 1;
		} else {
			dst->v[((int)n / 2)] = (dst->v[((int)n / 2)] & 0x0f) +
			    msa[msalen - n - 1] * 16;
		}
	}

	return 0;

}

static int imsi_add(uint64_t src, uint64_t * dst, int add)
{
	/* TODO: big endian / small endian ??? */
	uint64_t i64 = 0;

	/* Convert from uint64_t bcd to uint64_t integer format */
	/* The resulting integer format is multiplied by 10 */
	while (src) {
		if ((src & 0x0f) != 0x0f) {
			i64 *= 10;
			i64 += (src & 0x0f);
		}
		if ((src & 0xf0) != 0xf0) {
			i64 *= 10;
			i64 += (src & 0xf0) >> 4;
		}
		src = src >> 8;
	}

	i64 += add * 10;

	*dst = 0;
	while (i64) {
		*dst = *dst << 4;
		*dst += (i64 % 10);
		i64 = i64 / 10;
	}

	*dst |= 0xf000000000000000ull;

	return 0;

}

/* Calculate time left until we have to send off next ping packet */
static int ping_timeout(struct timeval *tp)
{
	struct timezone tz;
	struct timeval tv;
	int diff;
	if ((options.pinghost.len) && (2 == state) &&
	    ((pingseq < options.pingcount) || (options.pingcount == 0))) {
		gettimeofday(&tv, &tz);
		diff = 1000000 / options.pingrate * pingseq - 1000000 * (tv.tv_sec - firstping.tv_sec) - (tv.tv_usec - firstping.tv_usec);	/* Microseconds safe up to 500 sec */
		tp->tv_sec = 0;
		if (diff > 0)
			tp->tv_usec = diff;
		else {
			/* For some reason we get packet loss if set to zero */
			tp->tv_usec = 100000 / options.pingrate;	/* 10 times pingrate */
			tp->tv_usec = 0;
		}
	}
	return 0;
}

/* Print out statistics when at the end of ping sequence */
static int ping_finish()
{
	struct timezone tz;
	struct timeval tv;
	int elapsed;
	gettimeofday(&tv, &tz);
	elapsed = 1000000 * (tv.tv_sec - firstping.tv_sec) + (tv.tv_usec - firstping.tv_usec);	/* Microseconds */
	printf("\n");
	printf("\n----%s PING Statistics----\n", in46a_ntoa(&options.pinghost));
	printf("%d packets transmitted in %.3f seconds, ", ntransmitted,
	       elapsed / 1000000.0);
	printf("%d packets received, ", nreceived);
	if (ntransmitted) {
		if (nreceived > ntransmitted)
			printf("-- somebody's printing up packets!");
		else
			printf("%d%% packet loss",
			       (int)(((ntransmitted - nreceived) * 100) /
				     ntransmitted));
	}
	printf("\n");
	if (options.debug)
		printf("%d packets received in total\n", ntreceived);
	if (nreceived && tsum)
		printf("round-trip (ms)  min/avg/max = %.3f/%.3f/%.3f\n\n",
		       tmin / 1000.0, tsum / 1000.0 / nreceived, tmax / 1000.0);
	printf("%d packets transmitted \n", ntransmitted);

	ntransmitted = 0;
	return 0;
}

static int encaps_ping4(struct pdp_t *pdp, void *pack, unsigned len)
{
	struct timeval tv;
	struct timeval *tp;
	struct ip_ping *pingpack = pack;
	struct in_addr src;
	int triptime;

	src.s_addr = pingpack->src;

	if (len < CREATEPING_IP + CREATEPING_ICMP) {
		printf("packet too short (%d bytes) from %s\n", len,
		       inet_ntoa(src));
		return 0;
	}

	if (pingpack->protocol != 1) {
		if (!options.pingquiet)
			printf("%d bytes from %s: ip_protocol=%d (%s)\n",
			       len, inet_ntoa(src), pingpack->protocol,
			       print_ipprot(pingpack->protocol));
		return 0;
	}

	if (pingpack->type != 0) {
		if (!options.pingquiet)
			printf
			    ("%d bytes from %s: icmp_type=%d (%s) icmp_code=%d\n",
			     len, inet_ntoa(src), pingpack->type,
			     print_icmptype(pingpack->type), pingpack->code);
		return 0;
	}

	nreceived++;
	if (!options.pingquiet)
		printf("%d bytes from %s: icmp_seq=%d", len,
		       inet_ntoa(src), ntohs(pingpack->seq));

	if (len >= sizeof(struct timeval) + CREATEPING_IP + CREATEPING_ICMP) {
		gettimeofday(&tv, NULL);
		tp = (struct timeval *)pingpack->data;
		if ((tv.tv_usec -= tp->tv_usec) < 0) {
			tv.tv_sec--;
			tv.tv_usec += 1000000;
		}
		tv.tv_sec -= tp->tv_sec;

		triptime = tv.tv_sec * 1000000 + (tv.tv_usec);
		tsum += triptime;
		if (triptime < tmin)
			tmin = triptime;
		if (triptime > tmax)
			tmax = triptime;

		if (!options.pingquiet)
			printf(" time=%.3f ms\n", triptime / 1000.0);

	} else if (!options.pingquiet)
		printf("\n");
	return 0;
}

static int encaps_ping6(struct pdp_t *pdp, struct ip6_hdr *ip6h, unsigned len)
{
	const struct icmpv6_echo_hdr *ic6h = (struct icmpv6_echo_hdr *) ((uint8_t*)ip6h + sizeof(*ip6h));
	struct timeval tv;
	struct timeval tp;
	int triptime;
	char straddr[128];

	if (len < sizeof(struct ip6_hdr)) {
		SYS_ERR(DSGSN, LOGL_ERROR, 0, "Packet len too small to contain IPv6 header (%d)", len);
		return 0;
	}

	if (ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_ICMPV6) {
		if (!options.pingquiet)
			printf("%d bytes from %s: ip6_protocol=%d (%s)\n", len,
			       inet_ntop(AF_INET6, &ip6h->ip6_src, straddr, sizeof(straddr)),
			       ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt,
			       print_ipprot(ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt));
		return 0;
	}

	if (len < sizeof(struct ip6_hdr) + sizeof(struct icmpv6_echo_hdr)) {
		LOGP(DSGSN, LOGL_ERROR, "Packet len too small to contain ICMPv6 echo header (%d)\n", len);
		return 0;
	}

	if (ic6h->hdr.type != 129 || ic6h->hdr.code != 0) {
		if (!options.pingquiet)
			printf
			    ("%d bytes from %s: icmp_type=%d icmp_code=%d\n", len,
			    inet_ntop(AF_INET6, &ip6h->ip6_src, straddr, sizeof(straddr)),
			    ic6h->hdr.type, ic6h->hdr.code);
		return 0;
	}

	nreceived++;
	if (!options.pingquiet)
		printf("%d bytes from %s: icmp_seq=%d", len,
		       inet_ntop(AF_INET6, &ip6h->ip6_src, straddr, sizeof(straddr)),
		       ntohs(ic6h->seq));

	if (len >= sizeof(struct ip6_hdr) + sizeof(struct icmpv6_echo_hdr) + sizeof(struct timeval)) {
		gettimeofday(&tv, NULL);
		memcpy(&tp, ic6h->data, sizeof(struct timeval));
		if ((tv.tv_usec -= tp.tv_usec) < 0) {
			tv.tv_sec--;
			tv.tv_usec += 1000000;
		}
		tv.tv_sec -= tp.tv_sec;

		triptime = tv.tv_sec * 1000000 + (tv.tv_usec);
		tsum += triptime;
		if (triptime < tmin)
			tmin = triptime;
		if (triptime > tmax)
			tmax = triptime;

		if (!options.pingquiet)
			printf(" time=%.3f ms\n", triptime / 1000.0);

	} else if (!options.pingquiet)
		printf("\n");
	return 0;
}

/* Handle a received ping packet. Print out line and update statistics. */
static int encaps_ping(struct pdp_t *pdp, void *pack, unsigned len)
{
	struct iphdr *iph = (struct iphdr *)pack;
	struct timeval tv;


	gettimeofday(&tv, NULL);
	if (options.debug)
		printf("%d.%6d ", (int)tv.tv_sec, (int)tv.tv_usec);

	ntreceived++;

	if (len < sizeof(struct iphdr)) {
		SYS_ERR(DSGSN, LOGL_ERROR, 0, "Packet len too small to contain ip header (%d)", len);
		return -1;
	}
	switch(iph->version) {
	case 4:
		return encaps_ping4(pdp, pack, len);
	case 6:
		return encaps_ping6(pdp, (struct ip6_hdr *)pack, len);
	default:
		SYS_ERR(DSGSN, LOGL_ERROR, 0, "Unknown ip header version %d", iph->version);
		return -1;
	}
}

static int create_ping4(void *gsn, struct pdp_t *pdp, struct in46_addr *src,
			struct in46_addr *dst, int seq, unsigned int datasize)
{
	struct ip_ping pack;
	uint16_t v16;
	uint8_t *p8 = (uint8_t *) & pack;
	unsigned int n;
	long int sum = 0;
	int count = 0;

	struct timezone tz;
	struct timeval *tp =
	    (struct timeval *)&p8[CREATEPING_IP + CREATEPING_ICMP];

	pack.ipver = 0x45;
	pack.tos = 0x00;
	pack.length = htons(CREATEPING_IP + CREATEPING_ICMP + datasize);
	pack.fragid = 0x0000;
	pack.offset = 0x0040;
	pack.ttl = 0x40;
	pack.protocol = 0x01;
	pack.ipcheck = 0x0000;
	pack.src = src->v4.s_addr;
	pack.dst = dst->v4.s_addr;
	pack.type = 0x08;
	pack.code = 0x00;
	pack.checksum = 0x0000;
	pack.ident = 0x0000;
	pack.seq = htons(seq);

	/* Generate ICMP payload */
	p8 = (uint8_t *) &pack + CREATEPING_IP + CREATEPING_ICMP;
	for (n = 0; n < (datasize); n++)
		p8[n] = n;

	if (datasize >= sizeof(struct timeval))
		gettimeofday(tp, &tz);

	/* Calculate IP header checksum */
	p8 = (uint8_t *) &pack;
	count = CREATEPING_IP;
	sum = 0;
	while (count > 1) {
		memcpy(&v16, p8, 2);
		sum += v16;
		p8 += 2;
		count -= 2;
	}
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	pack.ipcheck = ~sum;

	/* Calculate ICMP checksum */
	count = CREATEPING_ICMP + datasize;	/* Length of ICMP message */
	sum = 0;
	p8 = (uint8_t *) &pack;
	p8 += CREATEPING_IP;
	while (count > 1) {
		memcpy(&v16, p8, 2);
		sum += v16;
		p8 += 2;
		count -= 2;
	}
	if (count > 0)
		sum += *(unsigned char *)p8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	pack.checksum = ~sum;

	ntransmitted++;
	return gtp_data_req(gsn, pdp, &pack, 28 + datasize);
}

static int create_ping6(void *gsn, struct pdp_t *pdp, struct in46_addr *src,
			struct in46_addr *dst, int seq, unsigned int datasize)
{
	struct ip6_ping *pack;
	uint8_t *p8;
	unsigned int n;
	struct timezone tz;
	struct timeval *tp;

	struct msgb *msg = msgb_alloc_headroom(sizeof(struct ip6_ping) + 128,128, "ICMPv6 echo");
	OSMO_ASSERT(msg);
	pack = (struct ip6_ping *) msgb_put(msg, sizeof(struct icmpv6_echo_hdr) + datasize);
	pack->hdr.hdr.type = 128;
	pack->hdr.hdr.code = 0;
	pack->hdr.hdr.csum = 0;  /* updated below */
	pack->hdr.ident = 0x0000;
	pack->hdr.seq = htons(seq);

	p8 = pack->data;
	for (n = 0; n < (datasize); n++)
		p8[n] = n;

	if (datasize >= sizeof(struct timeval)) {
		tp = (struct timeval *)pack->data;
		gettimeofday(tp, &tz);
	}

	pack->hdr.hdr.csum = icmpv6_prepend_ip6hdr(msg, &src->v6, &dst->v6);

	ntransmitted++;
	return gtp_data_req(gsn, pdp, msgb_data(msg), msgb_length(msg));
}

/* Create a new ping packet and send it off to peer. */
static int create_ping(void *gsn, struct pdp_t *pdp,
			struct in46_addr *dst, int seq, unsigned int datasize)
{
	int num_addr;
	struct in46_addr addr[2];
	struct in46_addr *src;

	if (datasize > CREATEPING_MAX) {
		SYS_ERR(DSGSN, LOGL_ERROR, 0,
			"Ping size to large: %d!", datasize);
		return -1;
	}

	if ((num_addr = in46a_from_eua(&pdp->eua, addr)) < 1) {
		SYS_ERR(DSGSN, LOGL_ERROR, 0,
			"in46a_from_eua() failed! %d", num_addr);
		return -1;
	}
	if (dst->len == addr[0].len) {
		src = &addr[0];
	} else if (num_addr > 1 && dst->len == addr[1].len) {
		src = &addr[1];
	} else {
		SYS_ERR(DSGSN, LOGL_ERROR, 0,
			"Mismaching source and destination IP addr types (%d vs %d)", dst->len, addr[0].len);
		return -1;
	}
	if (in46a_is_v4(dst))
		return create_ping4(gsn, pdp, src, dst, seq, datasize);
	else
		return create_ping6(gsn, pdp, src, dst, seq, datasize);
}

static int delete_context(struct pdp_t *pdp)
{
	int rc;

	if (tun && options.ipdown) {
#if defined(__linux__)
		sigset_t oldmask;

		if ((options.netns)) {
			if ((rc = switch_ns(netns, &oldmask)) < 0) {
				SYS_ERR(DSGSN, LOGL_ERROR, 0,
					"Failed to switch to netns %s: %s\n",
					options.netns, strerror(-rc));
			}
		}
#endif
		tun_runscript(tun, options.ipdown);

#if defined(__linux__)
		if ((options.netns)) {
			if ((rc = restore_ns(&oldmask)) < 0) {
				SYS_ERR(DSGSN, LOGL_ERROR, 0,
					"Failed to switch to original netns: %s\n",
					strerror(-rc));
			}
		}
#endif
	}

	ipdel((struct iphash_t *)pdp->peer[0]);
	memset(pdp->peer[0], 0, sizeof(struct iphash_t));	/* To be sure */

	if (1 == options.contexts)
		state = 5;	/* Disconnected */

	return 0;
}

/* Link-Local address  prefix fe80::/64 */
static const uint8_t ll_prefix[] = { 0xfe,0x80, 0,0, 0,0, 0,0 };

/* Callback for receiving messages from tun */
static int cb_tun_ind(struct tun_t *tun, void *pack, unsigned len)
{
	struct iphash_t *ipm;
	struct in46_addr src;
	struct iphdr *iph = (struct iphdr *)pack;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)pack;

	if (iph->version == 4) {
		if (len < sizeof(*iph) || len < 4*iph->ihl) {
			printf("Dropping packet with too short IP header\n");
			return 0;
		}
		src.len = 4;
		src.v4.s_addr = iph->saddr;
	} else if (iph->version == 6) {
		src.len = 16;
		src.v6 = ip6h->ip6_src;
	} else {
		printf("Dropping packet with invalid IP version %u\n", iph->version);
		return 0;
	}

	if (ipget(&ipm, &src)) {
		printf("Dropping packet from invalid source address: %s\n",
		       in46a_ntoa(&src));
		return 0;
	}

	if (ipm->ctx->pdp)		/* Check if a peer protocol is defined */
		gtp_data_req(gsn, ipm->ctx->pdp, pack, len);
	return 0;
}

static int create_pdp_conf(struct pdp_t *pdp, void *cbp, int cause)
{
	int rc, i, num_addr;
	struct in46_addr addr[2];
#if defined(__linux__)
	sigset_t oldmask;
#endif

	struct pdp_peer_sgsnemu_ctx *ctx = (struct pdp_peer_sgsnemu_ctx *) cbp;

	if (cause < 0) {
		printf("Create PDP Context Request timed out\n");
		if (ctx->pdp->version == 1) {
			printf("Retrying with version 0\n");
			ctx->pdp->version = 0;
			gtp_create_context_req(gsn, ctx->pdp, ctx);
			return 0;
		} else {
			state = 0;
			pdp_freepdp(ctx->pdp);
			ctx->pdp = NULL;
			return EOF;
		}
	}

	if (cause != 128) {
		printf
		    ("Received create PDP context response. Cause value: %d\n",
		     cause);
		state = 0;
		pdp_freepdp(ctx->pdp);
		ctx->pdp = NULL;
		return EOF;	/* Not what we expected */
	}

	if ((num_addr = in46a_from_eua(&pdp->eua, addr)) < 1) {
		printf
		    ("Received create PDP context response. Cause value: %d\n",
		     cause);
		pdp_freepdp(ctx->pdp);
		ctx->pdp = NULL;
		state = 0;
		return EOF;	/* Not a valid IP address */
	}

	printf("Received create PDP context response.\n");

#if defined(__linux__)
	if ((options.createif) && (options.netns)) {
		if ((rc = switch_ns(netns, &oldmask)) < 0) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"Failed to switch to netns %s: %s\n",
				options.netns, strerror(-rc));
		}
	}
#endif

	for (i = 0; i < num_addr; i++) {
		printf("PDP ctx: received EUA with IP address: %s\n",  in46a_ntoa(&addr[i]));

		switch (addr[i].len) {
		case 16: /* IPv6 */
			/* Convert address to link local using the lower 64bits
			   of the allocated EUA as Interface-Identifier to
			   send router solicitation, as per 3GPP TS 29.061
			   Section 11.2.1.3.2 */
			memcpy(addr[i].v6.s6_addr, ll_prefix, sizeof(ll_prefix));
			printf("Derived IPv6 link-local address: %s\n", in46a_ntoa(&addr[i]));
			ctx->hash_v6_ll.inuse = 1;
			ipset(&ctx->hash_v6_ll, &addr[i]);
			break;
		case 4: /* IPv4 */
			ctx->hash_v4.inuse = 1;
			ipset(&ctx->hash_v4, &addr[i]);
			break;
		}

		if ((options.createif) && (!options.netaddr.len)) {
			size_t prefixlen = 32;
			if (addr[i].len == 16)
				prefixlen = 64;
			/* printf("Setting up interface and routing\n"); */
			tun_addaddr(tun, &addr[i], NULL, prefixlen);
			if (options.defaultroute) {
				if (in46a_is_v4(&addr[i])) {
					struct in_addr rm;
					rm.s_addr = 0;
					if (netdev_addroute4(&rm, &addr[i].v4, &rm) < 0) {
						SYS_ERR(DSGSN, LOGL_ERROR, 0, "Failed adding default route to %s", in46a_ntoa(&addr[i]));
					}
				} /* else: route will be set up once we have a global link address (Router Advertisement) */
			}
			if (options.ipup)
				tun_runscript(tun, options.ipup);
		}
	}

	if (options.createif && options.pdp_type == PDP_EUA_TYPE_v6) {
		struct in6_addr *saddr6;
		struct msgb *msg;
		if (in46a_is_v6(&addr[0])) {
			saddr6 = &addr[0].v6;
		} else if (num_addr > 1 && in46a_is_v6(&addr[1])) {
			saddr6 = &addr[1].v6;
		} else {
			SYS_ERR(DSGSN, LOGL_ERROR, 0, "Failed to find IPv6 EUA on IPv6 APN");
			return EOF;	/* Not a valid IP address */
		}
		SYS_ERR(DSGSN, LOGL_INFO, 0, "Sending ICMPv6 Router Soliciation to GGSN...");
		msg = icmpv6_construct_rs(saddr6);
		gtp_data_req(gsn, ctx->pdp, msgb_data(msg), msgb_length(msg));
		msgb_free(msg);
	}

#if defined(__linux__)
	if ((options.createif) && (options.netns)) {
		if ((rc = restore_ns(&oldmask)) < 0) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0, "Failed to switch to original netns: %s\n",
				strerror(-rc));
		}
	}
#endif


	state = 2;		/* Connected */

	return 0;
}

static int delete_pdp_conf(struct pdp_t *pdp, int cause)
{
	printf("Received delete PDP context response. Cause value: %d\n",
	       cause);
	if (pdp)
		pdp_freepdp(pdp);
	return 0;
}

static int echo_conf(int recovery)
{

	if (recovery < 0) {
		printf("Echo Request timed out\n");
		if (echoversion == 1) {
			printf("Retrying with version 0\n");
			echoversion = 0;
			gtp_echo_req(gsn, echoversion, NULL, &options.remote);
			return 0;
		} else {
			state = 0;
			return EOF;
		}
	} else {
		printf("Received echo response\n");
		if (!options.contexts)
			state = 5;
	}
	return 0;
}

static int _gtp_cb_conf(int type, int cause, struct pdp_t *pdp, void *cbp)
{
	/* if (cause < 0) return 0; Some error occurred. We don't care */
	switch (type) {
	case GTP_ECHO_REQ:
		return echo_conf(cause);
	case GTP_CREATE_PDP_REQ:
		return create_pdp_conf(pdp, cbp, cause);
	case GTP_DELETE_PDP_REQ:
		return delete_pdp_conf(pdp, cause);
	default:
		return 0;
	}
}

static void handle_router_adv(struct pdp_t *pdp, struct ip6_hdr *ip6h, struct icmpv6_radv_hdr *ra, size_t ra_len)
{
	struct pdp_peer_sgsnemu_ctx* ctx = (struct pdp_peer_sgsnemu_ctx*)pdp->peer[0];
	struct icmpv6_opt_hdr *opt_hdr;
	struct icmpv6_opt_prefix *opt_prefix;
	int rc;
	sigset_t oldmask;
	struct in6_addr rm;
	char ip6strbuf[200];
	memset(&rm, 0, sizeof(rm));

	SYS_ERR(DSGSN, LOGL_INFO, 0, "Received ICMPv6 Router Advertisement");

	foreach_icmpv6_opt(ra, ra_len, opt_hdr) {
		if (opt_hdr->type == ICMPv6_OPT_TYPE_PREFIX_INFO) {
			opt_prefix = (struct icmpv6_opt_prefix *)opt_hdr;
			size_t prefix_len_bytes = (opt_prefix->prefix_len + 7)/8;
			SYS_ERR(DSGSN, LOGL_INFO, 0, "Parsing OPT Prefix info (prefix_len=%u): %s",
				opt_prefix->prefix_len,
				osmo_hexdump((const unsigned char *)opt_prefix->prefix, prefix_len_bytes));
			if ((options.createif) && (!options.netaddr.len)) {
				struct in46_addr addr;
				addr.len = 16;
				memcpy(addr.v6.s6_addr, opt_prefix->prefix, prefix_len_bytes);
				memset(&addr.v6.s6_addr[prefix_len_bytes], 0, 16 - prefix_len_bytes);
				addr.v6.s6_addr[15] = 0x02;
				SYS_ERR(DSGSN, LOGL_INFO, 0, "Adding addr %s to tun %s",
					in46a_ntoa(&addr), tun->devname);
				if (!ctx->hash_v6_global.inuse) {
					ctx->hash_v6_global.inuse = 1;
					ipset(&ctx->hash_v6_global, &addr);
				} else {
					SYS_ERR(DSGSN, LOGL_ERROR, 0, "First v6 global address in hash already in use!");
				}

#if defined(__linux__)
				if ((options.netns)) {
					if ((rc = switch_ns(netns, &oldmask)) < 0) {
						SYS_ERR(DSGSN, LOGL_ERROR, 0,
							"Failed to switch to netns %s: %s",
							options.netns, strerror(-rc));
					}
				}
#endif
				rc = tun_addaddr(tun, &addr, NULL, opt_prefix->prefix_len);
				if (rc < 0) {
					SYS_ERR(DSGSN, LOGL_ERROR, 0, "Failed to add addr %s to tun %s",
						in46a_ntoa(&addr), tun->devname);
				}

				struct in6_addr rm;
				memset(&rm, 0, sizeof(rm));
				if (netdev_addroute6(&rm, &ip6h->ip6_src, 0, tun->devname) < 0) {
					SYS_ERR(DSGSN, LOGL_ERROR, 0, "Failed adding default route to %s", inet_ntop(AF_INET6, &ip6h->ip6_src, ip6strbuf, sizeof(ip6strbuf)));
				}

#if defined(__linux__)
				if ((options.netns)) {
					if ((rc = restore_ns(&oldmask)) < 0) {
						SYS_ERR(DSGSN, LOGL_ERROR, 0,
							"Failed to switch to original netns: %s",
							strerror(-rc));
					}
				}
#endif
			}
		}
	}
}

static int encaps_tun(struct pdp_t *pdp, void *pack, unsigned len)
{
	struct iphdr *iph = (struct iphdr *)pack;
	struct icmpv6_radv_hdr *ra;
	switch (iph->version) {
	case 6:
		if ((ra = icmpv6_validate_router_adv(pack, len))) {
			size_t ra_len = (uint8_t*)ra - (uint8_t*)pack;
			handle_router_adv(pdp, (struct ip6_hdr *)pack, ra, ra_len);
			return 0;
		}
	break;
	}

	/*  printf("encaps_tun. Packet received: forwarding to tun\n"); */
	return tun_encaps((struct tun_t *)pdp->ipif, pack, len);
}

int main(int argc, char **argv)
{
	fd_set fds;		/* For select() */
	struct timeval idleTime;	/* How long to select() */
	struct pdp_t *pdp;
	int n, rc;
	int starttime = time(NULL);	/* Time program was started */
	int stoptime = 0;	/* Time to exit */
	int pingtimeout = 0;	/* Time to print ping statistics */
	int signal_received;	/* If select() on fd_set is interrupted by signal. */

	struct timezone tz;	/* Used for calculating ping times */
	struct timeval tv;
	int diff;
#if defined(__linux__)
	char buf[10];
	sigset_t oldmask;
#endif

	signal(SIGTERM, signal_handler);
	signal(SIGHUP,  signal_handler);
	signal(SIGINT,  signal_handler);

	tall_sgsnemu_ctx = talloc_named_const(NULL, 0, "sgsnemu");
	msgb_talloc_ctx_init(tall_sgsnemu_ctx, 0);
	osmo_init_logging2(tall_sgsnemu_ctx, &log_info);

#if defined(__linux__)
	if ((rc = init_netns()) < 0) {
		SYS_ERR(DSGSN, LOGL_ERROR, 0, "Failed to initialize netns: %s", strerror(-rc));
		exit(1);
	}
#endif

	/* Process options given in configuration file and command line */
	if (process_options(argc, argv))
		exit(1);

	printf("\nInitialising GTP library\n");
	if (gtp_new(&gsn, options.statedir, &options.listen, GTP_MODE_SGSN)) {
		SYS_ERR(DSGSN, LOGL_ERROR, 0, "Failed to create gtp");
		exit(1);
	}
	if (gsn->fd0 > maxfd)
		maxfd = gsn->fd0;
	if (gsn->fd1c > maxfd)
		maxfd = gsn->fd1c;
	if (gsn->fd1u > maxfd)
		maxfd = gsn->fd1u;

	gtp_set_cb_delete_context(gsn, delete_context);
	gtp_set_cb_conf(gsn, _gtp_cb_conf);
	if (options.createif)
		gtp_set_cb_data_ind(gsn, encaps_tun);
	else
		gtp_set_cb_data_ind(gsn, encaps_ping);

#if defined(__linux__)
	if ((options.createif) && (options.netns)) {
		if ((netns = get_nsfd(options.netns)) < 0) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0, "Failed to obtain fd for netns %s: %s\n",
				options.netns, strerror(-netns));
			exit(1);
		}
		if ((rc = switch_ns(netns, &oldmask)) < 0) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0, "Failed to switch to netns %s: %s\n",
				options.netns, strerror(-rc));
			exit(1);
		}
	}
#endif

	if (options.createif) {
		printf("Setting up interface\n");
		/* Create a tunnel interface */
		if (tun_new((struct tun_t **)&tun, options.tun_dev_name, false, -1, -1)) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"Failed to create tun");
			exit(1);
		}

#if defined(__linux__) && defined(HAVE_IN6_ADDR_GEN_MODE_NONE)
		/* Avoid tunnel setting its own link-local addr automatically,
		   we don't need it. Don't exit on error since this sysctl is
		   only available starting with linux 4.11. */
		snprintf(buf, sizeof(buf), "%u", IN6_ADDR_GEN_MODE_NONE);
		if (proc_ipv6_conf_write(tun->devname, "addr_gen_mode", buf) < 0) {
			SYS_ERR(DSGSN, LOGL_ERROR, errno,
				"Failed to disable addr_gen_mode on %s, an extra link-local "
				"ip address will appear on the tun device.\n",
				tun->devname);
		}
#endif

		tun_set_cb_ind(tun, cb_tun_ind);
		if (tun->fd > maxfd)
			maxfd = tun->fd;

		if (proc_ipv6_conf_write(tun->devname, "accept_ra", "0") < 0) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"Failed to disable IPv6 SLAAC on %s\n", tun->devname);
			exit(1);
		}
	}

	if ((options.createif) && (options.netaddr.len)) {
		tun_addaddr(tun, &options.netaddr, NULL, options.prefixlen);
		if (options.defaultroute) {
			if (in46a_is_v4(&options.netaddr)) {
				struct in_addr rm;
				rm.s_addr = 0;
				netdev_addroute4(&rm, &options.netaddr.v4, &rm);
			} else {
				struct in6_addr rm;
				memset(&rm, 0, sizeof(rm));
				netdev_addroute6(&rm, &options.netaddr.v6, 0, tun->devname);
			}
		}
		if (options.ipup)
			tun_runscript(tun, options.ipup);
	}

#if defined(__linux__)
	if ((options.createif) && (options.netns)) {
		if ((rc = restore_ns(&oldmask)) < 0) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0, "Failed to switch to original netns: %s\n",
				strerror(-rc));
			exit(1);
		}
	}
#endif

	/* Initialise hash tables */
	memset(&iphash, 0, sizeof(iphash));
	memset(&ctx_arr, 0, sizeof(ctx_arr));

	printf("Done initialising GTP library\n\n");

	/* See if anybody is there */
	printf("Sending off echo request\n");
	echoversion = options.gtpversion;
	gtp_echo_req(gsn, echoversion, NULL, &options.remote);	/* Is remote alive? */

	for (n = 0; n < options.contexts; n++) {
		uint64_t myimsi;
		printf("Setting up PDP context #%d\n", n);

		imsi_add(options.imsi, &myimsi, n);

		/* Allocated here. */
		/* If create context failes we have to deallocate ourselves. */
		/* Otherwise it is deallocated by gtplib */
		gtp_pdp_newpdp(gsn, &pdp, myimsi, options.nsapi, NULL);

		pdp->peer[0] = &ctx_arr[n];
		pdp->ipif = tun;	/* TODO */
		ctx_arr[n].pdp = pdp;
		ctx_arr[n].hash_v4.ctx = &ctx_arr[n];
		ctx_arr[n].hash_v6_ll.ctx = &ctx_arr[n];
		ctx_arr[n].hash_v6_global.ctx = &ctx_arr[n];

		if (options.gtpversion == 0) {
			if (options.qos.l - 1 > sizeof(pdp->qos_req0)) {
				SYS_ERR(DSGSN, LOGL_ERROR, 0,
					"QoS length too big");
				exit(1);
			} else {
				memcpy(pdp->qos_req0, options.qos.v,
				       options.qos.l);
			}
		}

		pdp->qos_req.l = options.qos.l;
		memcpy(pdp->qos_req.v, options.qos.v, options.qos.l);

		pdp->selmode = options.selmode;

		pdp->rattype.l = options.rattype.l;
		memcpy(pdp->rattype.v, options.rattype.v, options.rattype.l);
		pdp->rattype_given = options.rattype_given;

		pdp->userloc.l = options.userloc.l;
		memcpy(pdp->userloc.v, options.userloc.v, options.userloc.l);
		pdp->userloc_given = options.userloc_given;

		pdp->rai.l = options.rai.l;
		memcpy(pdp->rai.v, options.rai.v, options.rai.l);
		pdp->rai_given = options.rai_given;

		pdp->mstz.l = options.mstz.l;
		memcpy(pdp->mstz.v, options.mstz.v, options.mstz.l);
		pdp->mstz_given = options.mstz_given;

		pdp->imeisv.l = options.imeisv.l;
		memcpy(pdp->imeisv.v, options.imeisv.v, options.imeisv.l);
		pdp->imeisv_given = options.imeisv_given;

		pdp->norecovery_given = options.norecovery_given;

		if (options.apn.l > sizeof(pdp->apn_use.v)) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"APN length too big");
			exit(1);
		} else {
			pdp->apn_use.l = options.apn.l;
			memcpy(pdp->apn_use.v, options.apn.v, options.apn.l);
		}

		pdp->gsnlc.l = sizeof(options.listen);
		memcpy(pdp->gsnlc.v, &options.listen, sizeof(options.listen));
		pdp->gsnlu.l = sizeof(options.listen);
		memcpy(pdp->gsnlu.v, &options.listen, sizeof(options.listen));

		if (options.msisdn.l > sizeof(pdp->msisdn.v)) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"MSISDN length too big");
			exit(1);
		} else {
			msisdn_add(&options.msisdn, &pdp->msisdn, n);
		}

		/* Request dynamic IP address */
		pdp->eua.v[0] = PDP_EUA_ORG_IETF;
		pdp->eua.v[1] = options.pdp_type;
		pdp->eua.l = 2;

		if (options.pco.l > sizeof(pdp->pco_req.v)) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"PCO length too big");
			exit(1);
		} else {
			pdp->pco_req.l = options.pco.l;
			memcpy(pdp->pco_req.v, options.pco.v, options.pco.l);
		}

		pdp->version = options.gtpversion;

		pdp->hisaddr0 = options.remote;
		pdp->hisaddr1 = options.remote;

		pdp->cch_pdp = options.cch;	/* 2048 = Normal, 1024 = Prepaid,
						   512 = Flat rate, 256 = Hot billing */

		pdp->tx_gpdu_seq = options.tx_gpdu_seq;

		/* Create context */
		/* We send this of once. Retransmissions are handled by gtplib */
		gtp_create_context_req(gsn, pdp, &ctx_arr[n]);
	}

	state = 1;		/* Enter wait_connection state */

	printf("Waiting for response from ggsn........\n\n");

  /******************************************************************/
	/* Main select loop                                               */
  /******************************************************************/

	while ((0 != state) && (5 != state)) {

		/* Take down client after timeout after disconnect */
		if ((4 == state) && ((stoptime) <= time(NULL))) {
			state = 5;
		}

		/* Take down client after timelimit timeout */
		if ((2 == state) && (options.timelimit) &&
		    ((starttime + options.timelimit) <= time(NULL))) {
			state = 3;
		}

		/* Take down client after ping timeout */
		if ((2 == state) && (pingtimeout)
		    && (pingtimeout <= time(NULL))) {
			state = 3;
		}

		/* Set pingtimeout for later disconnection */
		if (options.pingcount && ntransmitted >= options.pingcount) {
			pingtimeout = time(NULL) + 5;	/* Extra seconds */
		}

		/* Print statistics if no more ping packets are missing */
		if (ntransmitted && options.pingcount
		    && nreceived >= options.pingcount) {
			ping_finish();
			if (!options.createif)
				state = 3;
		}

		/* Send off disconnect */
		if (3 == state) {
			state = 4;
			stoptime = time(NULL) + 5;	/* Extra seconds to allow disconnect */
			for (n = 0; n < options.contexts; n++) {
				/* Delete context */
				printf("Disconnecting PDP context #%d\n", n);
				gtp_delete_context_req2(gsn, ctx_arr[n].pdp, NULL, 1);
				if ((options.pinghost.len)
				    && ntransmitted)
					ping_finish();
			}
		}

		/* Send of ping packets */
		diff = 0;
		while ((diff <= 0) &&
		       /* Send off an ICMP ping packet */
		       /*if ( */ (options.pinghost.len) && (2 == state) &&
		       ((pingseq < options.pingcount)
			|| (options.pingcount == 0))) {
			if (!pingseq)
				gettimeofday(&firstping, &tz);	/* Set time of first ping */
			gettimeofday(&tv, &tz);
			diff = 1000000 / options.pingrate * pingseq - 1000000 * (tv.tv_sec - firstping.tv_sec) - (tv.tv_usec - firstping.tv_usec);	/* Microseconds safe up to 500 sec */
			if (diff <= 0) {
				if (options.debug)
					printf("Create_ping %d\n", diff);
				create_ping(gsn,
					    ctx_arr[pingseq %
						  options.contexts].pdp,
					    &options.pinghost, pingseq,
					    options.pingsize);
				pingseq++;
			}
		}

		FD_ZERO(&fds);
		if (tun)
			FD_SET(tun->fd, &fds);
		FD_SET(gsn->fd0, &fds);
		FD_SET(gsn->fd1c, &fds);
		FD_SET(gsn->fd1u, &fds);

		idleTime.tv_sec = 10;
		idleTime.tv_usec = 0;
		ping_timeout(&idleTime);

		if (options.debug)
			printf("idletime.tv_sec %d, idleTime.tv_usec %d\n",
			       (int)idleTime.tv_sec, (int)idleTime.tv_usec);

		signal_received = 0;
		switch (select(maxfd + 1, &fds, NULL, NULL, &idleTime)) {
		case -1:
			if (errno == EINTR)
				signal_received = 1;
			else
				SYS_ERR(DSGSN, LOGL_ERROR, 0,
					"Select returned -1");
			break;
		default:
			break;
		}

		if (!signal_received) {

			if ((tun) && FD_ISSET(tun->fd, &fds) && tun_decaps(tun) < 0) {
				SYS_ERR(DSGSN, LOGL_ERROR, 0,
					"TUN decaps failed");
			}

			if (FD_ISSET(gsn->fd0, &fds))
				gtp_decaps0(gsn);

			if (FD_ISSET(gsn->fd1c, &fds))
				gtp_decaps1c(gsn);

			if (FD_ISSET(gsn->fd1u, &fds))
				gtp_decaps1u(gsn);

		}
	}

	gtp_free(gsn);		/* Clean up the gsn instance */

	if (options.createif)
		tun_free(tun);

	if (0 == state)
		exit(1);	/* Indicate error */

	return 0;
}
