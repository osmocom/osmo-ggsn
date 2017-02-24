/* 
 *  OpenGGSN - Gateway GPRS Support Node
 *  Copyright (C) 2002, 2003, 2004 Mondru AB.
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

#ifdef __linux__
#define _GNU_SOURCE 1		/* strdup() prototype, broken arpa/inet.h */
#endif

#include <osmocom/core/application.h>

#include <ctype.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
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

#include "config.h"
#include "../lib/tun.h"
#include "../lib/ippool.h"
#include "../lib/syserr.h"
#include "../gtp/pdp.h"
#include "../gtp/gtp.h"
#include "cmdline.h"

#define IPADDRLEN 256		/* Character length of addresses */
#define MAXCONTEXTS 1024	/* Max number of allowed contexts */

/* HASH tables for IP address allocation */
struct iphash_t {
	uint8_t inuse;		/* 0=free. 1=used by somebody */
	struct iphash_t *ipnext;
	struct pdp_t *pdp;
	struct in_addr addr;
};
struct iphash_t iparr[MAXCONTEXTS];
struct iphash_t *iphash[MAXCONTEXTS];

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

/* Struct with local versions of gengetopt options */
struct {
	int debug;		/* Print debug messages */
	int createif;		/* Create local network interface */
	struct in_addr netaddr, destaddr, net, mask;	/* Network interface  */
	char *ipup, *ipdown;	/* Filename of scripts */
	int defaultroute;	/* Set up default route */
	struct in_addr pinghost;	/* Remote ping host    */
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

/* Statistical values for ping */
int nreceived = 0;
int ntreceived = 0;
int ntransmitted = 0;
int tmin = 999999999;
int tmax = 0;
int tsum = 0;
int pingseq = 0;		/* Ping sequence counter */
struct timeval firstping;

void signal_handler(int signo)
{
	if (state == 2)
		state = 3;  /* Tell main loop to finish. */
}

int ipset(struct iphash_t *ipaddr, struct in_addr *addr)
{
	int hash = ippool_hash4(addr) % MAXCONTEXTS;
	struct iphash_t *h;
	struct iphash_t *prev = NULL;
	ipaddr->ipnext = NULL;
	ipaddr->addr.s_addr = addr->s_addr;
	for (h = iphash[hash]; h; h = h->ipnext)
		prev = h;
	if (!prev)
		iphash[hash] = ipaddr;
	else
		prev->ipnext = ipaddr;
	return 0;
}

int ipdel(struct iphash_t *ipaddr)
{
	int hash = ippool_hash4(&ipaddr->addr) % MAXCONTEXTS;
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

int ipget(struct iphash_t **ipaddr, struct in_addr *addr)
{
	int hash = ippool_hash4(addr) % MAXCONTEXTS;
	struct iphash_t *h;
	for (h = iphash[hash]; h; h = h->ipnext) {
		if ((h->addr.s_addr == addr->s_addr)) {
			*ipaddr = h;
			return 0;
		}
	}
	return EOF;		/* End of linked list and not found */
}

/* Used to write process ID to file. Assume someone else will delete */
void log_pid(char *pidfile)
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

int process_options(int argc, char **argv)
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
			"Listening address must be specified: %s!",
			args_info.listen_arg);
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
	if (strlen(args_info.imsi_arg) != 15) {
		printf("Invalid IMSI\n");
		return -1;
	}

	options.imsi = 0xf000000000000000ull;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[0] - 48));
	options.imsi |= ((uint64_t) (args_info.imsi_arg[1] - 48)) << 4;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[2] - 48)) << 8;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[3] - 48)) << 12;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[4] - 48)) << 16;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[5] - 48)) << 20;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[6] - 48)) << 24;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[7] - 48)) << 28;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[8] - 48)) << 32;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[9] - 48)) << 36;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[10] - 48)) << 40;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[11] - 48)) << 44;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[12] - 48)) << 48;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[13] - 48)) << 52;
	options.imsi |= ((uint64_t) (args_info.imsi_arg[14] - 48)) << 56;

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
		options.rattype.l = strlen(args_info.rattype_arg);
		options.rattype.v[0] = atoi(args_info.rattype_arg);
		printf("Using RAT Type:  %s\n", args_info.rattype_arg);
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

	/* net                                                          */
	/* Store net as in_addr net and mask                            */
	if (args_info.net_arg) {
		if (ippool_aton
		    (&options.net, &options.mask, args_info.net_arg, 0)) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"Invalid network address: %s!",
				args_info.net_arg);
			exit(1);
		}
#if defined (__sun__)
		options.netaddr.s_addr = htonl(ntohl(options.net.s_addr) + 1);
		options.destaddr.s_addr = htonl(ntohl(options.net.s_addr) + 1);
#else
		options.netaddr.s_addr = options.net.s_addr;
		options.destaddr.s_addr = options.net.s_addr;
#endif

	} else {
		options.net.s_addr = 0;
		options.mask.s_addr = 0;
		options.netaddr.s_addr = 0;
		options.destaddr.s_addr = 0;
	}

	/* ipup */
	options.ipup = args_info.ipup_arg;

	/* ipdown */
	options.ipdown = args_info.ipdown_arg;

	/* statedir */
	options.statedir = args_info.statedir_arg;

	/* defaultroute */
	options.defaultroute = args_info.defaultroute_flag;

	/* pinghost                                                     */
	/* Store ping host as in_addr                                   */
	if (args_info.pinghost_arg) {
		if (!(host = gethostbyname(args_info.pinghost_arg))) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"Invalid ping host: %s!",
				args_info.pinghost_arg);
			return -1;
		} else {
			memcpy(&options.pinghost.s_addr, host->h_addr,
			       host->h_length);
			printf("Using ping host:       %s (%s)\n",
			       args_info.pinghost_arg,
			       inet_ntoa(options.pinghost));
		}
	}

	/* Other ping parameters                                        */
	options.pingrate = args_info.pingrate_arg;
	options.pingsize = args_info.pingsize_arg;
	options.pingcount = args_info.pingcount_arg;
	options.pingquiet = args_info.pingquiet_flag;

	/* norecovery */
	options.norecovery_given = args_info.norecovery_flag;

	return 0;

}

int encaps_printf(struct pdp_t *pdp, void *pack, unsigned len)
{
	unsigned int i;
	printf("The packet looks like this:\n");
	for (i = 0; i < len; i++) {
		printf("%02x ", (unsigned char)*(char *)(pack + i));
		if (!((i + 1) % 16))
			printf("\n");
	};
	printf("\n");
	return 0;
}

char *print_ipprot(int t)
{
	switch (t) {
	case 1:
		return "ICMP";
	case 6:
		return "TCP";
	case 17:
		return "UDP";
	default:
		return "Unknown";
	};
}

char *print_icmptype(int t)
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

int msisdn_add(struct ul16_t *src, struct ul16_t *dst, int add)
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

int imsi_add(uint64_t src, uint64_t * dst, int add)
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
int ping_timeout(struct timeval *tp)
{
	struct timezone tz;
	struct timeval tv;
	int diff;
	if ((options.pinghost.s_addr) && (2 == state) &&
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
int ping_finish()
{
	struct timezone tz;
	struct timeval tv;
	int elapsed;
	gettimeofday(&tv, &tz);
	elapsed = 1000000 * (tv.tv_sec - firstping.tv_sec) + (tv.tv_usec - firstping.tv_usec);	/* Microseconds */
	printf("\n");
	printf("\n----%s PING Statistics----\n", inet_ntoa(options.pinghost));
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
	printf("%d packets transmitted \n", ntreceived);

	ntransmitted = 0;
	return 0;
}

/* Handle a received ping packet. Print out line and update statistics. */
int encaps_ping(struct pdp_t *pdp, void *pack, unsigned len)
{
	struct timezone tz;
	struct timeval tv;
	struct timeval *tp;
	struct ip_ping *pingpack = pack;
	struct in_addr src;
	int triptime;

	src.s_addr = pingpack->src;

	gettimeofday(&tv, &tz);
	if (options.debug)
		printf("%d.%6d ", (int)tv.tv_sec, (int)tv.tv_usec);

	if (len < CREATEPING_IP + CREATEPING_ICMP) {
		printf("packet too short (%d bytes) from %s\n", len,
		       inet_ntoa(src));
		return 0;
	}

	ntreceived++;
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
		gettimeofday(&tv, &tz);
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

/* Create a new ping packet and send it off to peer. */
int create_ping(void *gsn, struct pdp_t *pdp,
		struct in_addr *dst, int seq, unsigned int datasize)
{

	struct ip_ping pack;
	uint16_t *p = (uint16_t *) & pack;
	uint8_t *p8 = (uint8_t *) & pack;
	struct in_addr src;
	unsigned int n;
	long int sum = 0;
	int count = 0;

	struct timezone tz;
	struct timeval *tp =
	    (struct timeval *)&p8[CREATEPING_IP + CREATEPING_ICMP];

	if (datasize > CREATEPING_MAX) {
		SYS_ERR(DSGSN, LOGL_ERROR, 0,
			"Ping size to large: %d!", datasize);
		return -1;
	}

	memcpy(&src, &(pdp->eua.v[2]), 4);	/* Copy a 4 byte address */

	pack.ipver = 0x45;
	pack.tos = 0x00;
	pack.length = htons(CREATEPING_IP + CREATEPING_ICMP + datasize);
	pack.fragid = 0x0000;
	pack.offset = 0x0040;
	pack.ttl = 0x40;
	pack.protocol = 0x01;
	pack.ipcheck = 0x0000;
	pack.src = src.s_addr;
	pack.dst = dst->s_addr;
	pack.type = 0x08;
	pack.code = 0x00;
	pack.checksum = 0x0000;
	pack.ident = 0x0000;
	pack.seq = htons(seq);

	/* Generate ICMP payload */
	p8 = (uint8_t *) & pack + CREATEPING_IP + CREATEPING_ICMP;
	for (n = 0; n < (datasize); n++)
		p8[n] = n;

	if (datasize >= sizeof(struct timeval))
		gettimeofday(tp, &tz);

	/* Calculate IP header checksum */
	p = (uint16_t *) & pack;
	count = CREATEPING_IP;
	sum = 0;
	while (count > 1) {
		sum += *p++;
		count -= 2;
	}
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	pack.ipcheck = ~sum;

	/* Calculate ICMP checksum */
	count = CREATEPING_ICMP + datasize;	/* Length of ICMP message */
	sum = 0;
	p = (uint16_t *) & pack;
	p += CREATEPING_IP / 2;
	while (count > 1) {
		sum += *p++;
		count -= 2;
	}
	if (count > 0)
		sum += *(unsigned char *)p;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	pack.checksum = ~sum;

	ntransmitted++;
	return gtp_data_req(gsn, pdp, &pack, 28 + datasize);
}

int delete_context(struct pdp_t *pdp)
{

	if (tun && options.ipdown)
		tun_runscript(tun, options.ipdown);

	ipdel((struct iphash_t *)pdp->peer);
	memset(pdp->peer, 0, sizeof(struct iphash_t));	/* To be sure */

	if (1 == options.contexts)
		state = 5;	/* Disconnected */

	return 0;
}

/* Callback for receiving messages from tun */
int cb_tun_ind(struct tun_t *tun, void *pack, unsigned len)
{
	struct iphash_t *ipm;
	struct in_addr src;
	struct tun_packet_t *iph = (struct tun_packet_t *)pack;

	src.s_addr = iph->src;

	if (ipget(&ipm, &src)) {
		printf("Dropping packet from invalid source address: %s\n",
		       inet_ntoa(src));
		return 0;
	}

	if (ipm->pdp)		/* Check if a peer protocol is defined */
		gtp_data_req(gsn, ipm->pdp, pack, len);
	return 0;
}

int create_pdp_conf(struct pdp_t *pdp, void *cbp, int cause)
{
	struct in_addr addr;

	struct iphash_t *iph = (struct iphash_t *)cbp;

	if (cause < 0) {
		printf("Create PDP Context Request timed out\n");
		if (iph->pdp->version == 1) {
			printf("Retrying with version 0\n");
			iph->pdp->version = 0;
			gtp_create_context_req(gsn, iph->pdp, iph);
			return 0;
		} else {
			state = 0;
			pdp_freepdp(iph->pdp);
			iph->pdp = NULL;
			return EOF;
		}
	}

	if (cause != 128) {
		printf
		    ("Received create PDP context response. Cause value: %d\n",
		     cause);
		state = 0;
		pdp_freepdp(iph->pdp);
		iph->pdp = NULL;
		return EOF;	/* Not what we expected */
	}

	if (pdp_euaton(&pdp->eua, &addr)) {
		printf
		    ("Received create PDP context response. Cause value: %d\n",
		     cause);
		pdp_freepdp(iph->pdp);
		iph->pdp = NULL;
		state = 0;
		return EOF;	/* Not a valid IP address */
	}

	printf("Received create PDP context response. IP address: %s\n",
	       inet_ntoa(addr));

	if ((options.createif) && (!options.net.s_addr)) {
		struct in_addr m;
#ifdef HAVE_INET_ATON
		inet_aton("255.255.255.255", &m);
#else
		m.s_addr = -1;
#endif
		/* printf("Setting up interface and routing\n"); */
		tun_addaddr(tun, &addr, &addr, &m);
		if (options.defaultroute) {
			struct in_addr rm;
			rm.s_addr = 0;
			tun_addroute(tun, &rm, &addr, &rm);
		}
		if (options.ipup)
			tun_runscript(tun, options.ipup);
	}

	ipset((struct iphash_t *)pdp->peer, &addr);

	state = 2;		/* Connected */

	return 0;
}

int delete_pdp_conf(struct pdp_t *pdp, int cause)
{
	printf("Received delete PDP context response. Cause value: %d\n",
	       cause);
	return 0;
}

int echo_conf(int recovery)
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

int conf(int type, int cause, struct pdp_t *pdp, void *cbp)
{
	/* if (cause < 0) return 0; Some error occurred. We don't care */
	switch (type) {
	case GTP_ECHO_REQ:
		return echo_conf(cause);
	case GTP_CREATE_PDP_REQ:
		return create_pdp_conf(pdp, cbp, cause);
	case GTP_DELETE_PDP_REQ:
		if (cause != 128)
			return 0;	/* Request not accepted. We don't care */
		return delete_pdp_conf(pdp, cause);
	default:
		return 0;
	}
}

int encaps_tun(struct pdp_t *pdp, void *pack, unsigned len)
{
	/*  printf("encaps_tun. Packet received: forwarding to tun\n"); */
	return tun_encaps((struct tun_t *)pdp->ipif, pack, len);
}

int main(int argc, char **argv)
{
	fd_set fds;		/* For select() */
	struct timeval idleTime;	/* How long to select() */
	struct pdp_t *pdp;
	int n;
	int starttime = time(NULL);	/* Time program was started */
	int stoptime = 0;	/* Time to exit */
	int pingtimeout = 0;	/* Time to print ping statistics */
	int signal_received;	/* If select() on fd_set is interrupted by signal. */

	struct timezone tz;	/* Used for calculating ping times */
	struct timeval tv;
	int diff;

	signal(SIGTERM, signal_handler);
	signal(SIGHUP,  signal_handler);
	signal(SIGINT,  signal_handler);

	osmo_init_logging(&log_info);

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
	gtp_set_cb_conf(gsn, conf);
	if (options.createif)
		gtp_set_cb_data_ind(gsn, encaps_tun);
	else
		gtp_set_cb_data_ind(gsn, encaps_ping);

	if (options.createif) {
		printf("Setting up interface\n");
		/* Create a tunnel interface */
		if (tun_new((struct tun_t **)&tun)) {
			SYS_ERR(DSGSN, LOGL_ERROR, 0,
				"Failed to create tun");
			exit(1);
		}
		tun_set_cb_ind(tun, cb_tun_ind);
		if (tun->fd > maxfd)
			maxfd = tun->fd;
	}

	if ((options.createif) && (options.net.s_addr)) {
		/* printf("Setting up interface and routing\n"); */
		tun_addaddr(tun, &options.netaddr, &options.destaddr,
			    &options.mask);
		if (options.defaultroute) {
			struct in_addr rm;
			rm.s_addr = 0;
			tun_addroute(tun, &rm, &options.destaddr, &rm);
		}
		if (options.ipup)
			tun_runscript(tun, options.ipup);
	}

	/* Initialise hash tables */
	memset(&iphash, 0, sizeof(iphash));
	memset(&iparr, 0, sizeof(iparr));

	printf("Done initialising GTP library\n\n");

	/* See if anybody is there */
	printf("Sending off echo request\n");
	echoversion = options.gtpversion;
	gtp_echo_req(gsn, echoversion, NULL, &options.remote);	/* Is remote alive? */

	for (n = 0; n < options.contexts; n++) {
		uint64_t myimsi;
		printf("Setting up PDP context #%d\n", n);
		iparr[n].inuse = 1;	/* TODO */

		imsi_add(options.imsi, &myimsi, n);

		/* Allocated here. */
		/* If create context failes we have to deallocate ourselves. */
		/* Otherwise it is deallocated by gtplib */
		pdp_newpdp(&pdp, myimsi, options.nsapi, NULL);

		pdp->peer = &iparr[n];
		pdp->ipif = tun;	/* TODO */
		iparr[n].pdp = pdp;

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

		ipv42eua(&pdp->eua, NULL);	/* Request dynamic IP address */

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

		/* Create context */
		/* We send this of once. Retransmissions are handled by gtplib */
		gtp_create_context_req(gsn, pdp, &iparr[n]);
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
				gtp_delete_context_req(gsn, iparr[n].pdp, NULL,
						       1);
				if ((options.pinghost.s_addr != 0)
				    && ntransmitted)
					ping_finish();
			}
		}

		/* Send of ping packets */
		diff = 0;
		while ((diff <= 0) &&
		       /* Send off an ICMP ping packet */
		       /*if ( */ (options.pinghost.s_addr) && (2 == state) &&
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
					    iparr[pingseq %
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

		gtp_retranstimeout(gsn, &idleTime);
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
		case 0:
			gtp_retrans(gsn);	/* Only retransmit if nothing else */
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
