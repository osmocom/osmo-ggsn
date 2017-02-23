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
#include "cmdline.h"

#include <libgtpnl/gtp.h>
#include <libgtpnl/gtpnl.h>
#include <libmnl/libmnl.h>

#include "gtp-kernel.h"

static void pdp_debug(struct pdp_t *pdp)
{
	int i;
	uint64_t teid;

	if (!debug)
		return;

	printf("version %u\n", pdp->version);
	if (pdp->version == 0) {
		teid = pdp_gettid(pdp->imsi, pdp->nsapi);
		printf("flowid %u\n", pdp->flru);
	} else {
		teid = pdp->teid_gn; /* GTPIE_TEI_DI */
	}

	printf("teid %llx\n", teid);
	printf("address (%u)\n", pdp->eua.l);

	/* Byte 0: 0xf1 == IETF */
	/* Byte 1: 0x21 == IPv4 */
	/* Byte 2-6: IPv4 address */

	for (i = 0; i < 6; i++)
		printf("%x ", pdp->eua.v[i] & 0xff); /* GTPIE_EUA */

	printf("\n");
	printf("sgsn-addr (%u)\n", pdp->gsnrc.l);

	for (i = 0; i < 4; i++)
		printf("%x ", pdp->gsnrc.v[i] & 0xff); /* GTPIE_GSN_ADDR */

	printf("\n");
}

static int mask2prefix(struct in_addr *mask)
{
	uint32_t tmp = ntohl(mask->s_addr);
	int k;

	for (k=0; tmp > 0; k++)
		tmp = (tmp << 1);

	return k;
}

static struct {
	int			genl_id;
	struct mnl_socket	*nl;
	bool			enabled;
} gtp_nl;

/* Always forces the kernel to allocate gtp0. If it exists it hits EEXIST */
#define GTP_DEVNAME	"gtp0"

int gtp_kernel_init(struct gsn_t *gsn, struct in_addr *net,
		    struct in_addr *mask,
		    struct gengetopt_args_info *args_info)
{
	if (!args_info->gtp_linux_given)
		return 0;

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
	if (debug) {
		SYS_ERR(DGGSN, LOGL_NOTICE, 0,
			"Using the GTP kernel mode (genl ID is %d)\n",
			gtp_nl.genl_id);
	}

	DEBUGP(DGGSN, "Setting route to reach %s via %s\n",
	       args_info->net_arg, GTP_DEVNAME);

	if (gtp_dev_config(GTP_DEVNAME, net, mask2prefix(mask)) < 0) {
		SYS_ERR(DGGSN, LOGL_ERROR, 0,
			"Cannot add route to reach network %s\n",
			args_info->net_arg);
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
			 ipup, GTP_DEVNAME, args_info->net_arg);
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
