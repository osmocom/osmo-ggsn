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

static void pdp_debug(struct pdp_t *pdp)
{
	struct in46_addr ia46;
	struct in_addr ia;

	in46a_from_eua(&pdp->eua, &ia46);
	gsna2in_addr(&ia, &pdp->gsnrc);

	LOGPDPX(DGGSN, LOGL_DEBUG, pdp, "v%u TEID %"PRIu64"x EUA=%s SGSN=%s\n", pdp->version,
		pdp->version == 0 ? pdp_gettid(pdp->imsi, pdp->nsapi) : pdp->teid_gn,
		in46a_ntoa(&ia46), inet_ntoa(ia));
}

static struct {
	int			genl_id;
	struct mnl_socket	*nl;
	bool			enabled;
} gtp_nl;

/* Always forces the kernel to allocate gtp0. If it exists it hits EEXIST */
#define GTP_DEVNAME	"gtp0"

int gtp_kernel_init(struct gsn_t *gsn, struct in_addr *net,
		    size_t prefixlen, const char *net_arg)
{
	if (gtp_dev_create(-1, GTP_DEVNAME, gsn->fd0, gsn->fd1u) < 0) {
		SYS_ERR(DGGSN, LOGL_ERROR, 0,
			"cannot create GTP tunnel device: %s\n",
			strerror(errno));
		return -1;
	}
	gtp_nl.enabled = true;

	gtp_nl.nl = genl_socket_open();
	if (gtp_nl.nl == NULL) {
		SYS_ERR(DGGSN, LOGL_ERROR, 0,
			"cannot create genetlink socket\n");
		return -1;
	}
	gtp_nl.genl_id = genl_lookup_family(gtp_nl.nl, "gtp");
	if (gtp_nl.genl_id < 0) {
		SYS_ERR(DGGSN, LOGL_ERROR, 0,
			"cannot lookup GTP genetlink ID\n");
		return -1;
	}
	SYS_ERR(DGGSN, LOGL_DEBUG, 0,
		"Using the GTP kernel mode (genl ID is %d)\n", gtp_nl.genl_id);

	DEBUGP(DGGSN, "Setting route to reach %s via %s\n",
	       net_arg, GTP_DEVNAME);

	if (gtp_dev_config(GTP_DEVNAME, net, prefixlen) < 0) {
		SYS_ERR(DGGSN, LOGL_ERROR, 0,
			"Cannot add route to reach network %s\n",
			net_arg);
	}

	/* launch script if it is set to bring up the route to reach
	 * the MS, eg. ip ro add 10.0.0.0/8 dev gtp0. Better add this
	 * using native rtnetlink interface given that we know the
	 * MS network mask, later.
	 */
	if (ipup) {
		char cmd[1024];
		int err;

		/* eg. /home/ggsn/ipup gtp0 10.0.0.0/8 */
		snprintf(cmd, sizeof(cmd), "%s %s %s",
			 ipup, GTP_DEVNAME, net_arg);
		cmd[sizeof(cmd)-1] = '\0';

		err = system(cmd);
		if (err < 0) {
			SYS_ERR(DGGSN, LOGL_ERROR, 0,
				"Failed to launch script `%s'", ipup);
			return -1;
		}
	}
	SYS_ERR(DGGSN, LOGL_NOTICE, 0, "GTP kernel configured\n");

	return 0;
}

void gtp_kernel_stop(void)
{
	if (!gtp_nl.enabled)
		return;

	gtp_dev_destroy(GTP_DEVNAME);
}

int gtp_kernel_tunnel_add(struct pdp_t *pdp)
{
	struct in_addr ms, sgsn;
	struct gtp_tunnel *t;
	int ret;

	if (!gtp_nl.enabled)
		return 0;

	pdp_debug(pdp);

	t = gtp_tunnel_alloc();
	if (t == NULL)
		return -1;

	memcpy(&ms, &pdp->eua.v[2], sizeof(struct in_addr));
	memcpy(&sgsn, &pdp->gsnrc.v[0], sizeof(struct in_addr));

	gtp_tunnel_set_ifidx(t, if_nametoindex(GTP_DEVNAME));
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

int gtp_kernel_tunnel_del(struct pdp_t *pdp)
{
	struct gtp_tunnel *t;
	int ret;

	if (!gtp_nl.enabled)
		return 0;

	pdp_debug(pdp);

	t = gtp_tunnel_alloc();
	if (t == NULL)
		return -1;

	gtp_tunnel_set_ifidx(t, if_nametoindex(GTP_DEVNAME));
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

int gtp_kernel_enabled(void)
{
	return gtp_nl.enabled;
}
