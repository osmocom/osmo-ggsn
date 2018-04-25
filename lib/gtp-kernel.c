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
#include <libmnl/libmnl.h>

#include <errno.h>

#include <time.h>

#include "../lib/tun.h"
#include "../lib/syserr.h"
#include "../gtp/pdp.h"
#include "../gtp/gtp.h"

#include <libgtpnl/gtp.h>
#include <libgtpnl/gtpnl.h>
#include <libmnl/libmnl.h>

#include "gtp-kernel.h"

static void pdp_debug(const char *prefix, const char *devname, struct pdp_t *pdp)
{
	struct in46_addr ia46;
	struct in_addr ia;

	in46a_from_eua(&pdp->eua, &ia46);
	gsna2in_addr(&ia, &pdp->gsnrc);

	LOGPDPX(DGGSN, LOGL_DEBUG, pdp, "%s %s v%u TEID %"PRIx64" EUA=%s SGSN=%s\n", prefix,
		devname, pdp->version,
		pdp->version == 0 ? pdp_gettid(pdp->imsi, pdp->nsapi) : pdp->teid_gn,
		in46a_ntoa(&ia46), inet_ntoa(ia));
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
	struct in_addr ms, sgsn;
	struct gtp_tunnel *t;
	int ret;

	pdp_debug(__func__, devname, pdp);

	t = gtp_tunnel_alloc();
	if (t == NULL)
		return -1;

	memcpy(&ms, &pdp->eua.v[2], sizeof(struct in_addr));
	memcpy(&sgsn, &pdp->gsnrc.v[0], sizeof(struct in_addr));

	gtp_tunnel_set_ifidx(t, if_nametoindex(devname));
	gtp_tunnel_set_version(t, pdp->version);
	gtp_tunnel_set_ms_ip4(t, &ms);
	gtp_tunnel_set_sgsn_ip4(t, &sgsn);
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

	return ret;
}

int gtp_kernel_tunnel_del(struct pdp_t *pdp, const char *devname)
{
	struct gtp_tunnel *t;
	int ret;

	pdp_debug(__func__, devname, pdp);

	t = gtp_tunnel_alloc();
	if (t == NULL)
		return -1;

	gtp_tunnel_set_ifidx(t, if_nametoindex(devname));
	gtp_tunnel_set_version(t, pdp->version);
	if (pdp->version == 0) {
		gtp_tunnel_set_tid(t, pdp_gettid(pdp->imsi, pdp->nsapi));
		gtp_tunnel_set_flowid(t, pdp->flru);
	} else {
		gtp_tunnel_set_i_tei(t, pdp->teid_own);
	}

	ret = gtp_del_tunnel(gtp_nl.genl_id, gtp_nl.nl, t);
	gtp_tunnel_free(t);

	return ret;
}
