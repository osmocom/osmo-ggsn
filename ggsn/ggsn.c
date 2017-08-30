/* 
 * OpenGGSN - Gateway GPRS Support Node
 * Copyright (C) 2002, 2003, 2004 Mondru AB.
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

/* ggsn.c
 *
 */

#ifdef __linux__
#define _GNU_SOURCE 1		/* strdup() prototype, broken arpa/inet.h */
#endif

#include "../config.h"

#include <osmocom/core/application.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

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
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if.h>

#include <errno.h>

#include <time.h>

#include <osmocom/core/select.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/ports.h>

#include "../lib/tun.h"
#include "../lib/ippool.h"
#include "../lib/syserr.h"
#include "../lib/in46_addr.h"
#include "../gtp/pdp.h"
#include "../gtp/gtp.h"
#include "cmdline.h"
#include "gtp-kernel.h"
#include "icmpv6.h"

int end = 0;
int maxfd = 0;			/* For select()            */

struct in_addr listen_;
struct in46_addr netaddr, destaddr, net;	/* Network interface       */
size_t prefixlen;
struct in46_addr dns1, dns2;	/* PCO DNS address         */
char *ipup, *ipdown;		/* Filename of scripts     */
int debug;			/* Print debug output      */
struct ul255_t pco;
struct ul255_t qos;
struct ul255_t apn;

struct gsn_t *gsn;		/* GSN instance            */
struct tun_t *tun;		/* TUN instance            */
struct ippool_t *ippool;	/* Pool of IP addresses    */

/* To exit gracefully. Used with GCC compilation flag -pg and gprof */
void signal_handler(int s)
{
	DEBUGP(DGGSN, "Received signal %d, exiting.\n", s);
	end = 1;
}

/* Used to write process ID to file. Assume someone else will delete */
void log_pid(char *pidfile)
{
	FILE *file;
	mode_t oldmask;

	oldmask = umask(022);
	file = fopen(pidfile, "w");
	umask(oldmask);
	if (!file) {
		SYS_ERR(DGGSN, LOGL_ERROR, 0,
			"Failed to create process ID file: %s!", pidfile);
		return;
	}
	fprintf(file, "%d\n", (int)getpid());
	fclose(file);
}

#if defined(__sun__)
int daemon(int nochdir, int noclose)
{
	int fd;

	switch (fork()) {
	case -1:
		return (-1);
	case 0:
		break;
	default:
		_exit(0);
	}

	if (setsid() == -1)
		return (-1);

	if (!nochdir)
		chdir("/");

	if (!noclose && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > 2)
			close(fd);
	}
	return (0);
}
#endif

static bool send_trap(const struct gsn_t *gsn, const struct pdp_t *pdp, const struct ippoolm_t *member, const char *var)
{
	char addrbuf[256];
	char val[NAMESIZE];

	const char *addrstr = in46a_ntop(&member->addr, addrbuf, sizeof(addrbuf));

	snprintf(val, sizeof(val), "%s,%s", imsi_gtp2str(&pdp->imsi), addrstr);

	if (ctrl_cmd_send_trap(gsn->ctrl, var, val) < 0) {
		LOGP(DGGSN, LOGL_ERROR, "Failed to create and send TRAP for IMSI %" PRIu64 " [%s].\n", pdp->imsi, var);
		return false;
	}
	return true;
}

int delete_context(struct pdp_t *pdp)
{
	DEBUGP(DGGSN, "Deleting PDP context\n");
	struct ippoolm_t *member = pdp->peer;

	if (pdp->peer) {
		send_trap(gsn, pdp, member, "imsi-rem-ip"); /* TRAP with IP removal */
		ippool_freeip(ippool, (struct ippoolm_t *)pdp->peer);
	} else
		SYS_ERR(DGGSN, LOGL_ERROR, 0, "Peer not defined!");

	if (gtp_kernel_tunnel_del(pdp)) {
		SYS_ERR(DGGSN, LOGL_ERROR, 0,
			"Cannot delete tunnel from kernel: %s\n",
			strerror(errno));
	}

	return 0;
}

#include <osmocom/gsm/tlv.h>

/* 3GPP TS 24.008 10.6.5.3 */
enum pco_protocols {
	PCO_P_LCP		= 0xC021,
	PCO_P_PAP		= 0xC023,
	PCO_P_CHAP		= 0xC223,
	PCO_P_IPCP		= 0x8021,
	PCO_P_PCSCF_ADDR	= 0x0001,
	PCO_P_IM_CN_SS_F	= 0x0002,
	PCO_P_DNS_IPv6_ADDR	= 0x0003,
	PCO_P_POLICY_CTRL_REJ	= 0x0004,	/* only in Network->MS */
	PCO_P_MS_SUP_NETREQ_BCI	= 0x0005,
	/* reserved */
	PCO_P_DSMIPv6_HA_ADDR	= 0x0007,
	PCO_P_DSMIPv6_HN_PREF	= 0x0008,
	PCO_P_DSMIPv6_v4_HA_ADDR= 0x0009,
	PCO_P_IP_ADDR_VIA_NAS	= 0x000a,	/* only MS->Network */
	PCO_P_IPv4_ADDR_VIA_DHCP= 0x000b,	/* only MS->Netowrk */
	PCO_P_PCSCF_IPv4_ADDR	= 0x000c,
	PCO_P_DNS_IPv4_ADDR	= 0x000d,
	PCO_P_MSISDN		= 0x000e,
	PCO_P_IFOM_SUPPORT	= 0x000f,
	PCO_P_IPv4_LINK_MTU	= 0x0010,
	PCO_P_MS_SUPP_LOC_A_TFT	= 0x0011,
	PCO_P_PCSCF_RESEL_SUP	= 0x0012,	/* only MS->Network */
	PCO_P_NBIFOM_REQ	= 0x0013,
	PCO_P_NBIFOM_MODE	= 0x0014,
	PCO_P_NONIP_LINK_MTU	= 0x0015,
	PCO_P_APN_RATE_CTRL_SUP	= 0x0016,
	PCO_P_PS_DATA_OFF_UE	= 0x0017,
	PCO_P_REL_DATA_SVC	= 0x0018,
};

/* determine if PCO contains given protocol */
static bool pco_contains_proto(struct ul255_t *pco, uint16_t prot)
{
	uint8_t *cur = pco->v + 1;

	/* iterate over PCO and check if protocol contained */
	while (cur + 3 <= pco->v + pco->l) {
		uint16_t cur_prot = osmo_load16be(cur);
		uint8_t cur_len = cur[2];
		if (cur_prot == prot)
			return true;
		if (cur_len == 0)
			break;
		cur += cur_len + 3;
	}
	return false;
}

/* determine if PDP context has IPv6 support */
static bool pdp_has_v4(struct pdp_t *pdp)
{
	if (pdp->eua.l == 4+2)
		return true;
	else
		return false;
}

/* process one PCO request from a MS/UE, putting together the proper responses */
static void process_pco(struct pdp_t *pdp)
{
	struct msgb *msg = msgb_alloc(256, "PCO");
	msgb_put_u8(msg, 0x80); /* ext-bit + configuration protocol byte */

	/* FIXME: also check if primary / secondary DNS was requested */
	if (pdp_has_v4(pdp) && pco_contains_proto(&pdp->pco_req, PCO_P_IPCP)) {
		/* FIXME: properly implement this for IPCP */
		uint8_t *cur = msgb_put(msg, pco.l-1);
		memcpy(cur, pco.v+1, pco.l-1);
	}

	if (pco_contains_proto(&pdp->pco_req, PCO_P_DNS_IPv6_ADDR)) {
		if (dns1.len == 16)
			msgb_t16lv_put(msg, PCO_P_DNS_IPv6_ADDR, dns1.len, dns1.v6.s6_addr);
		if (dns2.len == 16)
			msgb_t16lv_put(msg, PCO_P_DNS_IPv6_ADDR, dns2.len, dns2.v6.s6_addr);
	}

	if (pco_contains_proto(&pdp->pco_req, PCO_P_DNS_IPv4_ADDR)) {
		if (dns1.len == 4)
			msgb_t16lv_put(msg, PCO_P_DNS_IPv4_ADDR, dns1.len, (uint8_t *)&dns1.v4);
		if (dns2.len == 4)
			msgb_t16lv_put(msg, PCO_P_DNS_IPv4_ADDR, dns2.len, (uint8_t *)&dns2.v4);
	}

	if (msgb_length(msg) > 1) {
		memcpy(pdp->pco_neg.v, msgb_data(msg), msgb_length(msg));
		pdp->pco_neg.l = msgb_length(msg);
	} else
		pdp->pco_neg.l = 0;

	msgb_free(msg);
}

int create_context_ind(struct pdp_t *pdp)
{
	struct in46_addr addr;
	struct ippoolm_t *member;
	int rc;

	DEBUGP(DGGSN, "Received create PDP context request\n");

	/* FIXME: we manually force all context requests to dynamic here! */
	if (pdp->eua.l > 2)
		pdp->eua.l = 2;

	memcpy(pdp->qos_neg0, pdp->qos_req0, sizeof(pdp->qos_req0));

	memcpy(pdp->qos_neg.v, pdp->qos_req.v, pdp->qos_req.l);	/* TODO */
	pdp->qos_neg.l = pdp->qos_req.l;

	if (in46a_from_eua(&pdp->eua, &addr)) {
		SYS_ERR(DGGSN, LOGL_ERROR, 0, "Cannot decode EUA from MS/SGSN: %s",
			osmo_hexdump(pdp->eua.v, pdp->eua.l));
		gtp_create_context_resp(gsn, pdp, GTPCAUSE_UNKNOWN_PDP);
		return 0;
	}

	rc = ippool_newip(ippool, &member, &addr, 0);
	if (rc < 0) {
		SYS_ERR(DGGSN, LOGL_ERROR, 0, "Cannot allocate IP address in pool\n");
		gtp_create_context_resp(gsn, pdp, -rc);
		return 0;	/* Allready in use, or no more available */
	}

	if (addr.len == sizeof(struct in6_addr)) {
		struct in46_addr tmp;
		/* IPv6 doesn't really send the real/allocated address at this point, but just
		 * the link-identifier which the MS shall use for router solicitation */
		tmp.len = addr.len;
		/* initialize upper 64 bits to prefix, they are discarded by MS anyway */
		memcpy(tmp.v6.s6_addr, &member->addr.v6, 8);
		/* use allocated 64bit prefix as lower 64bit, used as link id by MS */
		memcpy(tmp.v6.s6_addr+8, &member->addr.v6, 8);
		in46a_to_eua(&tmp, &pdp->eua);
	} else
		in46a_to_eua(&member->addr, &pdp->eua);
	pdp->peer = member;
	pdp->ipif = tun;	/* TODO */
	member->peer = pdp;

	/* TODO: In IPv6, EUA doesn't contain the actual IP addr/prefix! */
	if (gtp_kernel_tunnel_add(pdp) < 0) {
		SYS_ERR(DGGSN, LOGL_ERROR, 0,
			"Cannot add tunnel to kernel: %s\n", strerror(errno));
		gtp_create_context_resp(gsn, pdp, GTPCAUSE_SYS_FAIL);
		return 0;
	}

	if (!send_trap(gsn, pdp, member, "imsi-ass-ip")) { /* TRAP with IP assignment */
		gtp_create_context_resp(gsn, pdp, GTPCAUSE_NO_RESOURCES);
		return 0;
	}

	process_pco(pdp);

	gtp_create_context_resp(gsn, pdp, GTPCAUSE_ACC_REQ);
	return 0;		/* Success */
}

/* Callback for receiving messages from tun */
int cb_tun_ind(struct tun_t *tun, void *pack, unsigned len)
{
	struct ippoolm_t *ipm;
	struct in46_addr dst;
	struct iphdr *iph = (struct iphdr *)pack;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)pack;

	if (iph->version == 4) {
		if (len < sizeof(*iph) || len < 4*iph->ihl)
			return -1;
		dst.len = 4;
		dst.v4.s_addr = iph->daddr;
	} else if (iph->version == 6) {
		/* Due to the fact that 3GPP requires an allocation of a
		 * /64 prefix to each MS, we must instruct
		 * ippool_getip() below to match only the leading /64
		 * prefix, i.e. the first 8 bytes of the address */
		dst.len = 8;
		dst.v6 = ip6h->ip6_dst;
	} else {
		LOGP(DGGSN, LOGL_NOTICE, "non-IPv packet received from tun\n");
		return -1;
	}

	DEBUGP(DGGSN, "Received packet from tun!\n");

	if (ippool_getip(ippool, &ipm, &dst)) {
		DEBUGP(DGGSN, "Received packet with no destination!!!\n");
		return 0;
	}

	if (ipm->peer)		/* Check if a peer protocol is defined */
		gtp_data_req(gsn, (struct pdp_t *)ipm->peer, pack, len);
	return 0;
}

/* RFC3307 link-local scope multicast address */
static const struct in6_addr all_router_mcast_addr = {
	.s6_addr = { 0xff,0x02,0,0,  0,0,0,0, 0,0,0,0,  0,0,0,2 }
};

int encaps_tun(struct pdp_t *pdp, void *pack, unsigned len)
{
	struct iphdr *iph = (struct iphdr *)pack;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)pack;

	DEBUGP(DGGSN, "encaps_tun. Packet received: forwarding to tun\n");

	switch (iph->version) {
	case 6:
		/* daddr: all-routers multicast addr */
		if (IN6_ARE_ADDR_EQUAL(&ip6h->ip6_dst, &all_router_mcast_addr))
			return handle_router_mcast(gsn, pdp, pack, len);
		break;
	case 4:
		break;
	default:
		LOGP(DGGSN, LOGL_ERROR, "Packet from MS is neither IPv4 nor IPv6\n");
		return -1;
	}
	return tun_encaps((struct tun_t *)pdp->ipif, pack, len);
}

int main(int argc, char **argv)
{
	/* gengeopt declarations */
	struct gengetopt_args_info args_info;

	struct hostent *host;

	/* Handle keyboard interrupt SIGINT */
	struct sigaction s;
	s.sa_handler = (void *)signal_handler;
	if ((0 != sigemptyset(&s.sa_mask)) && debug)
		printf("sigemptyset failed.\n");
	s.sa_flags = SA_RESETHAND;
	if ((sigaction(SIGINT, &s, NULL) != 0) && debug)
		printf("Could not register SIGINT signal handler.\n");

	fd_set fds;		/* For select() */
	struct timeval idleTime;	/* How long to select() */

	int timelimit;		/* Number of seconds to be connected */
	int starttime;		/* Time program was started */

	osmo_init_logging(&log_info);

	if (cmdline_parser(argc, argv, &args_info) != 0)
		exit(1);
	if (args_info.debug_flag) {
		printf("listen: %s\n", args_info.listen_arg);
		if (args_info.conf_arg)
			printf("conf: %s\n", args_info.conf_arg);
		printf("fg: %d\n", args_info.fg_flag);
		printf("debug: %d\n", args_info.debug_flag);
		printf("qos: %#08x\n", args_info.qos_arg);
		if (args_info.apn_arg)
			printf("apn: %s\n", args_info.apn_arg);
		if (args_info.net_arg)
			printf("net: %s\n", args_info.net_arg);
		if (args_info.dynip_arg)
			printf("dynip: %s\n", args_info.dynip_arg);
		if (args_info.statip_arg)
			printf("statip: %s\n", args_info.statip_arg);
		if (args_info.ipup_arg)
			printf("ipup: %s\n", args_info.ipup_arg);
		if (args_info.ipdown_arg)
			printf("ipdown: %s\n", args_info.ipdown_arg);
		if (args_info.pidfile_arg)
			printf("pidfile: %s\n", args_info.pidfile_arg);
		if (args_info.statedir_arg)
			printf("statedir: %s\n", args_info.statedir_arg);
		if (args_info.gtp_linux_flag)
			printf("gtp_linux: %d\n", args_info.gtp_linux_flag);
		printf("timelimit: %d\n", args_info.timelimit_arg);
	}

	/* Try out our new parser */

	if (cmdline_parser_configfile(args_info.conf_arg, &args_info, 0, 0, 0)
	    != 0)
		exit(1);

	/* Open a log file */
	if (args_info.logfile_arg) {
		struct log_target *tgt;
		int lvl;

		tgt = log_target_find(LOG_TGT_TYPE_FILE, args_info.logfile_arg);
		if (!tgt) {
			tgt = log_target_create_file(args_info.logfile_arg);
			if (!tgt) {
				LOGP(DGGSN, LOGL_ERROR,
					"Failed to create logfile: %s\n",
					args_info.logfile_arg);
				exit(1);
			}
			log_add_target(tgt);
		}
		log_set_all_filter(tgt, 1);
		log_set_use_color(tgt, 0);

		if (args_info.loglevel_arg) {
			lvl = log_parse_level(args_info.loglevel_arg);
			log_set_log_level(tgt, lvl);
			LOGP(DGGSN, LOGL_NOTICE,
				"Set file log level to %s\n",
				log_level_str(lvl));
		}
	}

	if (args_info.debug_flag) {
		printf("cmdline_parser_configfile\n");
		printf("listen: %s\n", args_info.listen_arg);
		printf("conf: %s\n", args_info.conf_arg);
		printf("fg: %d\n", args_info.fg_flag);
		printf("debug: %d\n", args_info.debug_flag);
		printf("qos: %#08x\n", args_info.qos_arg);
		if (args_info.apn_arg)
			printf("apn: %s\n", args_info.apn_arg);
		if (args_info.net_arg)
			printf("net: %s\n", args_info.net_arg);
		if (args_info.dynip_arg)
			printf("dynip: %s\n", args_info.dynip_arg);
		if (args_info.statip_arg)
			printf("statip: %s\n", args_info.statip_arg);
		if (args_info.ipup_arg)
			printf("ipup: %s\n", args_info.ipup_arg);
		if (args_info.ipdown_arg)
			printf("ipdown: %s\n", args_info.ipdown_arg);
		if (args_info.pidfile_arg)
			printf("pidfile: %s\n", args_info.pidfile_arg);
		if (args_info.statedir_arg)
			printf("statedir: %s\n", args_info.statedir_arg);
		if (args_info.gtp_linux_flag)
			printf("gtp-linux: %d\n", args_info.gtp_linux_flag);
		printf("timelimit: %d\n", args_info.timelimit_arg);
	}

	/* Handle each option */

	/* debug                                                        */
	debug = args_info.debug_flag;

	/* listen                                                       */
	/* Do hostname lookup to translate hostname to IP address       */
	/* Any port listening is not possible as a valid address is     */
	/* required for create_pdp_context_response messages            */
	if (args_info.listen_arg) {
		if (!(host = gethostbyname(args_info.listen_arg))) {
			SYS_ERR(DGGSN, LOGL_ERROR, 0,
				"Invalid listening address: %s!",
				args_info.listen_arg);
			exit(1);
		} else {
			memcpy(&listen_.s_addr, host->h_addr, host->h_length);
		}
	} else {
		SYS_ERR(DGGSN, LOGL_ERROR, 0,
			"Listening address must be specified! "
			"Please use command line option --listen or "
			"edit %s configuration file\n", args_info.conf_arg);
		exit(1);
	}

	/* net                                                          */
	/* Store net as in_addr net and mask                            */
	if (args_info.net_arg) {
		if (ippool_aton(&net, &prefixlen, args_info.net_arg, 0)) {
			SYS_ERR(DGGSN, LOGL_ERROR, 0,
				"Invalid network address: %s!",
				args_info.net_arg);
			exit(1);
		}
		/* default for network + destination address = net + 1 */
		netaddr = net;
		in46a_inc(&netaddr);
		destaddr = netaddr;
	} else {
		SYS_ERR(DGGSN, LOGL_ERROR, 0,
			"Network address must be specified: %s!",
			args_info.net_arg);
		exit(1);
	}

	/* dynip                                                        */
	if (!args_info.dynip_arg) {
		if (ippool_new(&ippool, args_info.net_arg, NULL, 1, 0,
			       IPPOOL_NONETWORK | IPPOOL_NOGATEWAY |
			       IPPOOL_NOBROADCAST)) {
			SYS_ERR(DGGSN, LOGL_ERROR, 0,
				"Failed to allocate IP pool!");
			exit(1);
		}
	} else {
		if (ippool_new(&ippool, args_info.dynip_arg, NULL, 1, 0,
			       IPPOOL_NONETWORK | IPPOOL_NOGATEWAY |
			       IPPOOL_NOBROADCAST)) {
			SYS_ERR(DGGSN, LOGL_ERROR, 0,
				"Failed to allocate IP pool!");
			exit(1);
		}
	}

	/* DNS1 and DNS2 */
	memset(&dns1, 0, sizeof(dns1));
	if (args_info.pcodns1_arg) {
		size_t tmp;
		if (ippool_aton(&dns1, &tmp, args_info.pcodns1_arg, 0) != 0) {
			SYS_ERR(DGGSN, LOGL_ERROR, 0,
				"Failed to convert pcodns1!");
			exit(1);
		}
	}
	memset(&dns2, 0, sizeof(dns2));
	if (args_info.pcodns2_arg) {
		size_t tmp;
		if (ippool_aton(&dns2, &tmp, args_info.pcodns2_arg, 0) != 0) {
			SYS_ERR(DGGSN, LOGL_ERROR, 0,
				"Failed to convert pcodns2!");
			exit(1);
		}
	}

	unsigned int cur = 0;
	pco.v[cur++] = 0x80;	/* x0000yyy x=1, yyy=000: PPP */
	pco.v[cur++] = 0x80;	/* IPCP */
	pco.v[cur++] = 0x21;
	pco.v[cur++] = 0xFF;	/* Length of contents */
	pco.v[cur++] = 0x02;	/* ACK */
	pco.v[cur++] = 0x00;	/* ID: Need to match request */
	pco.v[cur++] = 0x00;	/* Length */
	pco.v[cur++] = 0xFF;	/* overwritten  */
	if (dns1.len == 4) {
		pco.v[cur++] = 0x81;	/* DNS 1 */
		pco.v[cur++] = 2 + dns1.len;
		if (dns1.len == 4)
			memcpy(&pco.v[cur], &dns1.v4, dns1.len);
		else
			memcpy(&pco.v[cur], &dns1.v6, dns1.len);
		cur += dns1.len;
	}
	if (dns2.len == 4) {
		pco.v[cur++] = 0x83;
		pco.v[cur++] = 2 + dns2.len;	/* DNS 2 */
		if (dns2.len == 4)
			memcpy(&pco.v[cur], &dns2.v4, dns2.len);
		else
			memcpy(&pco.v[cur], &dns2.v6, dns2.len);
		cur += dns2.len;
	}
	pco.l = cur;
	/* patch in length values */
	pco.v[3] = pco.l - 4;
	pco.v[7] = pco.l - 4;

	/* ipup */
	ipup = args_info.ipup_arg;

	/* ipdown */
	ipdown = args_info.ipdown_arg;

	/* Timelimit                                                       */
	timelimit = args_info.timelimit_arg;
	starttime = time(NULL);

	/* qos                                                             */
	qos.l = 3;
	qos.v[2] = (args_info.qos_arg) & 0xff;
	qos.v[1] = ((args_info.qos_arg) >> 8) & 0xff;
	qos.v[0] = ((args_info.qos_arg) >> 16) & 0xff;

	/* apn                                                             */
	if (strlen(args_info.apn_arg) > (sizeof(apn.v) - 1)) {
		LOGP(DGGSN, LOGL_ERROR, "Invalid APN\n");
		return -1;
	}
	apn.l = strlen(args_info.apn_arg) + 1;
	apn.v[0] = (char)strlen(args_info.apn_arg);
	strncpy((char *)&apn.v[1], args_info.apn_arg, sizeof(apn.v) - 1);

	/* foreground                                                   */
	/* If flag not given run as a daemon                            */
	if (!args_info.fg_flag) {
		FILE *f;
		int rc;
		/* Close the standard file descriptors. */
		/* Is this really needed ? */
		f = freopen("/dev/null", "w", stdout);
		if (f == NULL) {
			SYS_ERR(DGGSN, LOGL_NOTICE, 0,
				"Could not redirect stdout to /dev/null");
		}
		f = freopen("/dev/null", "w", stderr);
		if (f == NULL) {
			SYS_ERR(DGGSN, LOGL_NOTICE, 0,
				"Could not redirect stderr to /dev/null");
		}
		f = freopen("/dev/null", "r", stdin);
		if (f == NULL) {
			SYS_ERR(DGGSN, LOGL_NOTICE, 0,
				"Could not redirect stdin to /dev/null");
		}
		rc = daemon(0, 0);
		if (rc != 0) {
			SYS_ERR(DGGSN, LOGL_ERROR, rc,
				"Could not daemonize");
			exit(1);
		}
	}

	/* pidfile */
	/* This has to be done after we have our final pid */
	if (args_info.pidfile_arg) {
		log_pid(args_info.pidfile_arg);
	}

	DEBUGP(DGGSN, "gtpclient: Initialising GTP tunnel\n");

	if (gtp_new(&gsn, args_info.statedir_arg, &listen_, GTP_MODE_GGSN)) {
		SYS_ERR(DGGSN, LOGL_ERROR, 0, "Failed to create gtp");
		exit(1);
	}
	if (gsn->fd0 > maxfd)
		maxfd = gsn->fd0;
	if (gsn->fd1c > maxfd)
		maxfd = gsn->fd1c;
	if (gsn->fd1u > maxfd)
		maxfd = gsn->fd1u;

	/* use GTP kernel module for data packet encapsulation */
	if (gtp_kernel_init(gsn, &net.v4, prefixlen, &args_info) < 0)
		goto err;

	gtp_set_cb_data_ind(gsn, encaps_tun);
	gtp_set_cb_delete_context(gsn, delete_context);
	gtp_set_cb_create_context_ind(gsn, create_context_ind);

	gsn->ctrl = ctrl_interface_setup(NULL, OSMO_CTRL_PORT_GGSN, NULL);
	if (!gsn->ctrl) {
		LOGP(DGGSN, LOGL_ERROR, "Failed to create CTRL interface.\n");
		exit(1);
	}

	/* skip the configuration of the tun0 if we're using the gtp0 device */
	if (gtp_kernel_enabled())
		goto skip_tun;

	/* Create a tunnel interface */
	DEBUGP(DGGSN, "Creating tun interface\n");
	if (tun_new((struct tun_t **)&tun)) {
		SYS_ERR(DGGSN, LOGL_ERROR, 0, "Failed to create tun");
		exit(1);
	}

	DEBUGP(DGGSN, "Setting tun IP address\n");
	if (tun_setaddr(tun, &netaddr, &destaddr, prefixlen)) {
		SYS_ERR(DGGSN, LOGL_ERROR, 0, "Failed to set tun IP address");
		exit(1);
	}

	tun_set_cb_ind(tun, cb_tun_ind);
	if (tun->fd > maxfd)
		maxfd = tun->fd;

	if (ipup)
		tun_runscript(tun, ipup);

skip_tun:

  /******************************************************************/
	/* Main select loop                                               */
  /******************************************************************/

	while ((((starttime + timelimit) > time(NULL)) || (0 == timelimit))
	       && (!end)) {

		FD_ZERO(&fds);
		if (tun)
			FD_SET(tun->fd, &fds);
		FD_SET(gsn->fd0, &fds);
		FD_SET(gsn->fd1c, &fds);
		FD_SET(gsn->fd1u, &fds);

		gtp_retranstimeout(gsn, &idleTime);
		switch (select(maxfd + 1, &fds, NULL, NULL, &idleTime)) {
		case -1:	/* errno == EINTR : unblocked signal */
			SYS_ERR(DGGSN, LOGL_ERROR, 0,
				"select() returned -1");
			/* On error, select returns without modifying fds */
			FD_ZERO(&fds);
			break;
		case 0:
			/* printf("Select returned 0\n"); */
			gtp_retrans(gsn);	/* Only retransmit if nothing else */
			break;
		default:
			break;
		}

		if (tun && tun->fd != -1 && FD_ISSET(tun->fd, &fds) &&
		    tun_decaps(tun) < 0) {
			SYS_ERR(DGGSN, LOGL_ERROR, 0,
				"TUN read failed (fd)=(%d)", tun->fd);
		}

		if (FD_ISSET(gsn->fd0, &fds))
			gtp_decaps0(gsn);

		if (FD_ISSET(gsn->fd1c, &fds))
			gtp_decaps1c(gsn);

		if (FD_ISSET(gsn->fd1u, &fds))
			gtp_decaps1u(gsn);

		osmo_select_main(1);
	}
err:
	gtp_kernel_stop();
	cmdline_parser_free(&args_info);
	ippool_free(ippool);
	gtp_free(gsn);
	if (tun)
		tun_free(tun);

	return 1;

}
