#ifdef __linux__
#define _GNU_SOURCE 1		/* strdup() prototype, broken arpa/inet.h */
#endif

#include "../config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <libgtpnl/gtp.h>
#include <libgtpnl/gtpnl.h>

#include <errno.h>

#include <time.h>

#include "../lib/tun.h"
#include "../lib/syserr.h"
#include "../lib/util.h"
#include "../lib/ippool.h"
#include "../gtp/pdp.h"
#include "../gtp/gtp.h"

#include "gtp-kernel.h"

static void pdp_debug(const char *prefix, const char *devname, struct pdp_t *pdp)
{
	char buf4[INET_ADDRSTRLEN], buf6[INET6_ADDRSTRLEN];
	struct ippoolm_t *peer;
	struct in_addr ia;

	buf4[0] = '\0';
	if ((peer = pdp_get_peer_ipv(pdp, false)))
		in46a_ntop(&peer->addr, buf4, sizeof(buf4));
	buf6[0] = '\0';
	if ((peer = pdp_get_peer_ipv(pdp, true)))
		in46a_ntop(&peer->addr, buf6, sizeof(buf6));

	gsna2in_addr(&ia, &pdp->gsnrc);

	LOGPDPX(DGGSN, LOGL_DEBUG, pdp, "%s %s v%u TEID %"PRIx64" EUA=(%s,%s) SGSN=%s\n", prefix,
		devname, pdp->version,
		pdp->version == 0 ? pdp_gettid(pdp->imsi, pdp->nsapi) : pdp->teid_gn,
		buf4, buf6, inet_ntoa(ia));
}

static struct {
	int			genl_id;
	struct mnl_socket	*nl;
} gtp_nl;

static int gtp_kernel_init_once(void)
{
	/* only initialize once */
	if (gtp_nl.nl)
		return 0;

	gtp_nl.nl = genl_socket_open();
	if (gtp_nl.nl == NULL) {
		LOGP(DGGSN, LOGL_ERROR, "cannot create genetlink socket\n");
		return -1;
	}
	gtp_nl.genl_id = genl_lookup_family(gtp_nl.nl, "gtp");
	if (gtp_nl.genl_id < 0) {
		LOGP(DGGSN, LOGL_ERROR, "cannot lookup GTP genetlink ID\n");
		genl_socket_close(gtp_nl.nl);
		gtp_nl.nl = NULL;
		return -1;
	}
	LOGP(DGGSN, LOGL_NOTICE, "Initialized GTP kernel mode (genl ID is %d)\n", gtp_nl.genl_id);

	return 0;
}

int gtp_kernel_create(int dest_ns, const char *devname, int fd0, int fd1u)
{
	if (gtp_kernel_init_once() < 0)
		return -1;

	return gtp_dev_create(dest_ns, devname, fd0, fd1u);
}

int gtp_kernel_create_sgsn(int dest_ns, const char *devname, int fd0, int fd1u)
{
	if (gtp_kernel_init_once() < 0)
		return -1;

	return gtp_dev_create_sgsn(dest_ns, devname, fd0, fd1u);
}

void gtp_kernel_stop(const char *devname)
{
	gtp_dev_destroy(devname);
}

int gtp_kernel_tunnel_add(struct pdp_t *pdp, const char *devname)
{
	int ms_addr_count;
	struct in46_addr ms[2];
	struct in46_addr sgsn;
	struct gtp_tunnel *t;
	int ret;

	pdp_debug(__func__, devname, pdp);

	in46a_from_gsna(&pdp->gsnrc, &sgsn);

	ms_addr_count = in46a_from_eua(&pdp->eua, ms);

	for (int i = 0; i < ms_addr_count; i++) {
		t = gtp_tunnel_alloc();
		if (t == NULL)
			return -1;

		gtp_tunnel_set_ifidx(t, if_nametoindex(devname));
		gtp_tunnel_set_version(t, pdp->version);

		if (in46a_to_af(&ms[i]) == AF_INET)
			gtp_tunnel_set_ms_ip4(t, &ms[i].v4);
		else {
			/* In IPv6, EUA doesn't contain the actual IP
			 * addr/prefix. Set higher bits to 0 to get the 64 bit
			 * netmask. */
			memset(((void *)&ms[i].v6) + 8, 0, 8);
			gtp_tunnel_set_ms_ip6(t, &ms[i].v6);
		}

		if (in46a_to_af(&sgsn) == AF_INET)
			gtp_tunnel_set_sgsn_ip4(t, &sgsn.v4);
		else
			gtp_tunnel_set_sgsn_ip6(t, &sgsn.v6);

		if (pdp->version == 0) {
			gtp_tunnel_set_tid(t, pdp_gettid(pdp->imsi, pdp->nsapi));
			gtp_tunnel_set_flowid(t, pdp->flru);
		} else {
			gtp_tunnel_set_i_tei(t, pdp->teid_own);
			/* use the TEI advertised by SGSN when sending packets
			 * towards the SGSN */
			gtp_tunnel_set_o_tei(t, pdp->teid_gn);
		}

		ret = gtp_add_tunnel(gtp_nl.genl_id, gtp_nl.nl, t);
		gtp_tunnel_free(t);

		if (ret != 0)
			break;
	}

	return ret;
}

int gtp_kernel_tunnel_del(struct pdp_t *pdp, const char *devname)
{
	int ms_addr_count;
	struct in46_addr ms[2];
	struct gtp_tunnel *t;
	int ret;

	pdp_debug(__func__, devname, pdp);

	ms_addr_count = in46a_from_eua(&pdp->eua, ms);

	for (int i = 0; i < ms_addr_count; i++) {
		t = gtp_tunnel_alloc();
		if (t == NULL)
			return -1;

		gtp_tunnel_set_ifidx(t, if_nametoindex(devname));
		gtp_tunnel_set_family(t, in46a_to_af(&ms[i]));
		gtp_tunnel_set_version(t, pdp->version);
		if (pdp->version == 0) {
			gtp_tunnel_set_tid(t, pdp_gettid(pdp->imsi, pdp->nsapi));
			gtp_tunnel_set_flowid(t, pdp->flru);
		} else {
			gtp_tunnel_set_i_tei(t, pdp->teid_own);
		}

		ret = gtp_del_tunnel(gtp_nl.genl_id, gtp_nl.nl, t);
		gtp_tunnel_free(t);

		if (ret != 0)
			break;
	}

	return ret;
}
