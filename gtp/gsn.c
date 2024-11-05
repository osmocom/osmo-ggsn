/*
 *  OsmoGGSN - Gateway GPRS Support Node
 *  Copyright (C) 2002, 2003, 2004 Mondru AB.
 *  Copyright (C) 2010-2011, 2016-2017 Harald Welte <laforge@gnumonks.org>
 *  Copyright (C) 2015-2017 sysmocom - s.f.m.c. GmbH
 *
 *  The contents of this file may be used under the terms of the GNU
 *  General Public License Version 2, provided that the above copyright
 *  notice and this permission notice is included in all copies or
 *  substantial portions of the software.
 *
 */

/*
 * gtp.c: Contains all GTP functionality. Should be able to handle multiple
 * tunnels in the same program.
 *
 * TODO:
 *  - Do we need to handle fragmentation?
 */

#ifdef __linux__
#define _GNU_SOURCE 1
#endif

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/rate_ctr.h>

#if defined(__FreeBSD__)
#include <sys/endian.h>
#endif

#include "../config.h"
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>

#include <arpa/inet.h>

/* #include <stdint.h>  ISO C99 types */

#include <osmocom/gtp/pdp.h>
#include <osmocom/gtp/gtp.h>
#include <osmocom/gtp/gtpie.h>

#include "queue.h"
#include "gsn_internal.h"

/* Error reporting functions */

#define LOGP_WITH_ADDR(ss, level, addr, fmt, args...)                    \
		LOGP(ss, level, "addr(%s:%d) " fmt,                      \
		     inet_ntoa((addr).sin_addr), htons((addr).sin_port), \
		     ##args)

static const struct rate_ctr_desc gsn_ctr_description[] = {
	[GSN_CTR_ERR_SOCKET] = { "err:socket", "Socket error" },
	[GSN_CTR_ERR_READFROM] = { "err:readfrom", "readfrom() errors" },
	[GSN_CTR_ERR_SENDTO] = { "err:sendto", "sendto() errors" },
	[GSN_CTR_ERR_QUEUEFULL] = { "err:queuefull", "Failed to queue message because queue is full" },
	[GSN_CTR_ERR_SEQ] = { "err:seq", "Sequence number out of range" },
	[GSN_CTR_ERR_ADDRESS] = { "err:address", "GSN address conversion failed" },
	[GSN_CTR_ERR_UNKNOWN_PDP] = { "err:unknown_pdp", "Failed looking up PDP context" },
	[GSN_CTR_ERR_UNEXPECTED_CAUSE] = { "err:unexpected_cause", "Unexpected cause value received" },
	[GSN_CTR_ERR_OUT_OF_PDP] = { "err:out_of_pdp", "Out of storage for PDP contexts" },
	[GSN_CTR_PKT_EMPTY] = { "pkt:empty", "Empty packet received" },
	[GSN_CTR_PKT_UNSUP] = { "pkt:unsupported", "Unsupported GTP version received" },
	[GSN_CTR_PKT_TOOSHORT] = { "pkt:too_short", "Packet too short received" },
	[GSN_CTR_PKT_UNKNOWN] = { "pkt:unknown", "Unknown packet type received" },
	[GSN_CTR_PKT_UNEXPECT] = { "pkt:unexpected", "Unexpected packet type received" },
	[GSN_CTR_PKT_DUPLICATE] = { "pkt:duplicate", "Duplicate or unsolicited packet received" },
	[GSN_CTR_PKT_MISSING] = { "pkt:missing", "Missing IE in packet received" },
	[GSN_CTR_PKT_INCORRECT] = { "pkt:incorrect", "Incorrect IE in packet received" },
	[GSN_CTR_PKT_INVALID] = { "pkt:invalid", "Invalid format in packet received" },
};

static const struct rate_ctr_group_desc gsn_ctrg_desc = {
	"gsn",
	"GSN Statistics",
	OSMO_STATS_CLASS_PEER,
	ARRAY_SIZE(gsn_ctr_description),
	gsn_ctr_description,
};
static unsigned int gsn_ctr_next_idx = 0;

/* Global timer definitions for GTP operation, provided for convenience. To make these user configurable, it is convenient to add
 * gtp_gsn_tdefs as one of your program's osmo_tdef_group entries and call osmo_tdef_vty_init(). */
struct osmo_tdef gtp_T_defs[] = {
	{ .T = GTP_GSN_TIMER_T3_RESPONSE, .default_val = 5, .unit = OSMO_TDEF_S,
	  .desc = "Timer T3-RESPONSE holds the maximum wait time for a response of a request message"
	},
	{ .T = GTP_GSN_TIMER_N3_REQUESTS, .default_val = 3, .unit = OSMO_TDEF_CUSTOM,
	  .desc = "Counter N3-REQUESTS holds the maximum number of attempts made by GTP to send a request message"
	},
	{ .T = GTP_GSN_TIMER_T3_HOLD_RESPONSE, .default_val = 5 * 3 /* (GTP_GSN_TIMER_T3_RESPONSE * GTP_GSN_TIMER_N3_REQUESTS) */, .unit = OSMO_TDEF_S,
	  .desc = "Time a GTP respoonse message is kept cached to re-transmit it when a duplicate request is received. Value is generally equal to (T3-RESPONSE * N3-REQUESTS) set at the peer"
	},
	{}
};

static TALLOC_CTX *tall_gsn_ctx = NULL;


/* API Functions */

/* Deprecated, use gtp_pdp_newpdp() instead */
int gtp_newpdp(struct gsn_t *gsn, struct pdp_t **pdp,
	       uint64_t imsi, uint8_t nsapi)
{
	int rc;
	rc = gtp_pdp_newpdp(gsn, pdp, imsi, nsapi, NULL);
	return rc;
}

int gtp_freepdp(struct gsn_t *gsn, struct pdp_t *pdp)
{
	if (gsn->cb_delete_context)
		gsn->cb_delete_context(pdp);
	return pdp_freepdp(pdp);
}

/* Free pdp and all its secondary PDP contexts. Must be called on the primary PDP context. */
int gtp_freepdp_teardown(struct gsn_t *gsn, struct pdp_t *pdp)
{
	int n;
	struct pdp_t *secondary_pdp;
	OSMO_ASSERT(!pdp->secondary);

	for (n = 0; n < PDP_MAXNSAPI; n++) {
		if (pdp->secondary_tei[n]) {
			if (gtp_pdp_getgtp1(gsn, &secondary_pdp,
					     pdp->secondary_tei[n])) {
				LOGP(DLGTP, LOGL_ERROR,
					"Unknown secondary PDP context\n");
				continue;
			}
			if (pdp != secondary_pdp) {
				gtp_freepdp(gsn, secondary_pdp);
			}
		}
	}

	return gtp_freepdp(gsn, pdp);
}

/* gtp_gpdu */

extern int gtp_fd(struct gsn_t *gsn)
{
	return gsn->fd0;
}

int gtp_set_cb_unsup_ind(struct gsn_t *gsn,
			 int (*cb) (struct sockaddr_in * peer))
{
	gsn->cb_unsup_ind = cb;
	return 0;
}

int gtp_set_cb_extheader_ind(struct gsn_t *gsn,
			     int (*cb) (struct sockaddr_in * peer))
{
	gsn->cb_extheader_ind = cb;
	return 0;
}

int gtp_set_cb_ran_info_relay_ind(struct gsn_t *gsn,
			     int (*cb) (struct sockaddr_in * peer, union gtpie_member **ie))
{
	gsn->cb_ran_info_relay_ind = cb;
	return 0;
}

/* API: Initialise delete context callback */
/* Called whenever a pdp context is deleted for any reason */
int gtp_set_cb_delete_context(struct gsn_t *gsn, int (*cb) (struct pdp_t * pdp))
{
	gsn->cb_delete_context = cb;
	return 0;
}

int gtp_set_cb_conf(struct gsn_t *gsn,
		    int (*cb) (int type, int cause,
			       struct pdp_t * pdp, void *cbp))
{
	gsn->cb_conf = cb;
	return 0;
}

int gtp_set_cb_recovery(struct gsn_t *gsn,
			int (*cb) (struct sockaddr_in * peer, uint8_t recovery))
{
	gsn->cb_recovery = cb;
	return 0;
}

/* cb_recovery()
 * pdp may be NULL if Recovery IE was received from a message independent
 * of any PDP ctx (such as Echo Response), or because pdp ctx is unknown to the
 * local setup. In case pdp is known, caller may want to keep that pdp alive to
 * handle subsequent msg cb as this specific pdp ctx is still valid according to
 * specs.
 */
int gtp_set_cb_recovery2(struct gsn_t *gsn,
			int (*cb_recovery2) (struct sockaddr_in * peer, struct pdp_t * pdp, uint8_t recovery))
{
	gsn->cb_recovery2 = cb_recovery2;
	return 0;
}

/* cb_recovery()
 * pdp may be NULL if Recovery IE was received from a message independent
 * of any PDP ctx (such as Echo Response), or because pdp ctx is unknown to the
 * local setup. In case pdp is known, caller may want to keep that pdp alive to
 * handle subsequent msg cb as this specific pdp ctx is still valid according to
 * specs.
 */
int gtp_set_cb_recovery3(struct gsn_t *gsn,
			 int (*cb_recovery3) (struct gsn_t *gsn, struct sockaddr_in *peer,
					      struct pdp_t *pdp, uint8_t recovery))
{
	gsn->cb_recovery3 = cb_recovery3;
	return 0;
}

int gtp_set_cb_data_ind(struct gsn_t *gsn,
			       int (*cb_data_ind) (struct pdp_t * pdp,
						   void *pack, unsigned len))
{
	gsn->cb_data_ind = cb_data_ind;
	return 0;
}

static int queue_timer_retrans(struct gsn_t *gsn)
{
	/* Retransmit any outstanding packets */
	/* Remove from queue if maxretrans exceeded */
	time_t now;
	struct qmsg_t *qmsg;
	unsigned int t3_response, n3_requests;

	now = time(NULL);
	t3_response = osmo_tdef_get(gsn->tdef, GTP_GSN_TIMER_T3_RESPONSE, OSMO_TDEF_S, -1);
	n3_requests = osmo_tdef_get(gsn->tdef, GTP_GSN_TIMER_N3_REQUESTS, OSMO_TDEF_CUSTOM, -1);

	/* get first element in queue, as long as the timeout of that
	 * element has expired */
	while ((!queue_getfirst(gsn->queue_req, &qmsg)) &&
	       (qmsg->timeout <= now)) {
		if (qmsg->retrans > n3_requests) {	/* Too many retrans */
			LOGP(DLGTP, LOGL_NOTICE, "Retransmit req queue timeout of seq %" PRIu16 "\n",
			     qmsg->seq);
			if (gsn->cb_conf)
				gsn->cb_conf(qmsg->type, EOF, NULL, qmsg->cbp);
			queue_freemsg(gsn->queue_req, qmsg);
		} else {
			LOGP(DLGTP, LOGL_INFO, "Retransmit (%d) of seq %" PRIu16 "\n",
			     qmsg->retrans, qmsg->seq);
			if (sendto(qmsg->fd, &qmsg->p, qmsg->l, 0,
				   (struct sockaddr *)&qmsg->peer,
				   sizeof(struct sockaddr_in)) < 0) {
				rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_SENDTO);
				LOGP(DLGTP, LOGL_ERROR,
					"Sendto(fd0=%d, msg=%lx, len=%d) failed: Error = %s\n",
					gsn->fd0, (unsigned long)&qmsg->p,
					qmsg->l, strerror(errno));
			}
			queue_back(gsn->queue_req, qmsg);
			qmsg->timeout = now + t3_response;
			qmsg->retrans++;
		}
	}

	/* Also clean up reply timeouts */
	while ((!queue_getfirst(gsn->queue_resp, &qmsg)) &&
	       (qmsg->timeout < now)) {
		LOGP(DLGTP, LOGL_DEBUG, "Retransmit resp queue seq %"
		     PRIu16 " expired, removing from queue\n", qmsg->seq);
		queue_freemsg(gsn->queue_resp, qmsg);
	}

	return 0;
}

static int queue_timer_retranstimeout(struct gsn_t *gsn, struct timeval *timeout)
{
	time_t now, later, diff;
	struct qmsg_t *qmsg;
	timeout->tv_usec = 0;

	if (queue_getfirst(gsn->queue_req, &qmsg)) {
		timeout->tv_sec = 10;
	} else {
		now = time(NULL);
		later = qmsg->timeout;
		timeout->tv_sec = later - now;
		if (timeout->tv_sec < 0)
			timeout->tv_sec = 0;	/* No negative allowed */
		if (timeout->tv_sec > 10)
			timeout->tv_sec = 10;	/* Max sleep for 10 sec */
	}

	if (queue_getfirst(gsn->queue_resp, &qmsg)) {
		/* already set by queue_req, do nothing */
	} else { /* trigger faster if earlier timeout exists in queue_resp */
		now = time(NULL);
		later = qmsg->timeout;
		diff = later - now;
		if (diff < 0)
			diff = 0;
		if (diff < timeout->tv_sec)
			timeout->tv_sec = diff;
	}

	return 0;
}

void gtp_queue_timer_start(struct gsn_t *gsn)
{
	struct timeval next;

	/* Retrieve next retransmission as timeval */
	queue_timer_retranstimeout(gsn, &next);

	/* re-schedule the timer */
	osmo_timer_schedule(&gsn->queue_timer, next.tv_sec, next.tv_usec/1000);
}

/* timer callback for libgtp retransmission and ping */
static void queue_timer_cb(void *data)
{
	struct gsn_t *gsn = data;

	/* do all the retransmissions as needed */
	queue_timer_retrans(gsn);

	gtp_queue_timer_start(gsn);
}


/**
 * @brief clear the request and response queue. Useful for debugging to reset "some" state.
 * @param gsn The GGSN instance
 */
void gtp_clear_queues(struct gsn_t *gsn)
{
	struct qmsg_t *qmsg;

	LOGP(DLGTP, LOGL_INFO, "Clearing req & resp retransmit queues\n");
	while (!queue_getfirst(gsn->queue_req, &qmsg)) {
		queue_freemsg(gsn->queue_req, qmsg);
	}

	while (!queue_getfirst(gsn->queue_resp, &qmsg)) {
		queue_freemsg(gsn->queue_resp, qmsg);
	}
}

/* Perform restoration and recovery error handling as described in 29.060 */
static void log_restart(struct gsn_t *gsn)
{
	FILE *f;
	int i, rc;
	int counter = 0;
	char *filename;

	filename = talloc_asprintf(NULL, "%s/%s", gsn->statedir, RESTART_FILE);
	OSMO_ASSERT(filename);

	/* We try to open file. On failure we will later try to create file */
	if (!(f = fopen(filename, "r"))) {
		LOGP(DLGTP, LOGL_NOTICE,
			"State information file (%s) not found. Creating new file.\n",
			filename);
	} else {
		rc = fscanf(f, "%d", &counter);
		if (rc != 1) {
			LOGP(DLGTP, LOGL_ERROR,
				"fscanf failed to read counter value\n");
			goto close_file;
		}
		if (fclose(f)) {
			LOGP(DLGTP, LOGL_ERROR,
				"fclose failed: Error = %s\n", strerror(errno));
		}
	}

	gsn->restart_counter = (unsigned char)counter;
	gsn->restart_counter++;

	/* Keep the umask closely wrapped around our fopen() call in case the
	 * log outputs cause file creation. */
	i = umask(022);
	f = fopen(filename, "w");
	umask(i);
	if (!f) {
		LOGP(DLGTP, LOGL_ERROR,
			"fopen(path=%s, mode=%s) failed: Error = %s\n", filename,
			"w", strerror(errno));
		goto free_filename;
	}

	fprintf(f, "%d\n", gsn->restart_counter);
close_file:
	if (fclose(f))
		LOGP(DLGTP, LOGL_ERROR,
			"fclose failed: Error = %s\n", strerror(errno));
free_filename:
	talloc_free(filename);
}

static int create_and_bind_socket(const char *name, struct gsn_t *gsn, int *fd, int domain,
				  const struct in_addr *listen, int port)
{
	struct sockaddr_in addr;
	int type = SOCK_DGRAM;
	int protocol = 0;

	*fd = socket(domain, type, protocol);

	if (*fd < 0) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_SOCKET);
		LOGP(DLGTP, LOGL_ERROR,
		     "%s socket(domain=%d, type=%d, protocol=%d) failed: Error = %s\n",
		     name, domain, type, protocol, strerror(errno));
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = domain;
	addr.sin_addr = *listen;
	addr.sin_port = htons(port);
#if defined(__FreeBSD__) || defined(__APPLE__)
	addr.sin_len = sizeof(addr);
#endif

	if (bind(*fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_SOCKET);
		LOGP_WITH_ADDR(DLGTP, LOGL_ERROR, addr,
			       "%s bind(fd=%d) failed: Error = %s\n",
			       name, *fd, strerror(errno));
		return -errno;
	}

	return 0;
}

int gtp_new(struct gsn_t **gsn, char *statedir, struct in_addr *listen,
	    int mode)
{
	LOGP(DLGTP, LOGL_NOTICE, "GTP: gtp_newgsn() started at %s\n", inet_ntoa(*listen));

	*gsn = talloc_zero(tall_gsn_ctx, struct gsn_t);

	(*gsn)->statedir = statedir;
	log_restart(*gsn);

	/* Initialise sequence number */
	(*gsn)->seq_next = (*gsn)->restart_counter * 1024;

	/* Initialize timers: */
	(*gsn)->tdef = gtp_T_defs;
	/* Small hack to properly reset tdef for old clients not using the tdef_group: */
	OSMO_ASSERT(gtp_T_defs[0].default_val != 0);
	if (gtp_T_defs[0].val == 0)
		osmo_tdefs_reset((*gsn)->tdef);


	/* Initialise request retransmit queue */
	queue_new(&(*gsn)->queue_req);
	queue_new(&(*gsn)->queue_resp);

	/* Initialise pdp table */
	pdp_init(*gsn);

	/* Initialize internal queue timer */
	osmo_timer_setup(&(*gsn)->queue_timer, queue_timer_cb, *gsn);

	/* Initialize counter group: */
	(*gsn)->ctrg = rate_ctr_group_alloc(NULL, &gsn_ctrg_desc, gsn_ctr_next_idx++);

	/* Initialise call back functions */
	(*gsn)->cb_create_context_ind = 0;
	(*gsn)->cb_update_context_ind = 0;
	(*gsn)->cb_delete_context = 0;
	(*gsn)->cb_unsup_ind = 0;
	(*gsn)->cb_conf = 0;
	(*gsn)->cb_data_ind = 0;

	/* Store function parameters */
	/* Same IP for user traffic and signalling */
	(*gsn)->gsnc = *listen;
	(*gsn)->gsnu = *listen;
	(*gsn)->mode = mode;

	(*gsn)->fd0 = -1;
	(*gsn)->fd1c = -1;
	(*gsn)->fd1u = -1;

	/* Create GTP version 0 socket */
	if (create_and_bind_socket("GTPv0", *gsn, &(*gsn)->fd0, AF_INET, listen, GTP0_PORT) < 0)
		goto error;

	/* Create GTP version 1 control plane socket */
	if (create_and_bind_socket("GTPv1 control plane", *gsn, &(*gsn)->fd1c, AF_INET, listen, GTP1C_PORT) < 0)
		goto error;

	/* Create GTP version 1 user plane socket */
	if (create_and_bind_socket("GTPv1 user plane", *gsn, &(*gsn)->fd1u, AF_INET, listen, GTP1U_PORT) < 0)
		goto error;

	/* Start internal queue timer */
	gtp_queue_timer_start(*gsn);

	return 0;
error:
	gtp_free(*gsn);
	*gsn = NULL;
	return -1;
}

int gtp_free(struct gsn_t *gsn)
{

	/* Cleanup internal queue timer */
	osmo_timer_del(&gsn->queue_timer);

	/* Clean up retransmit queues */
	queue_free(gsn->queue_req);
	queue_free(gsn->queue_resp);

	close(gsn->fd0);
	close(gsn->fd1c);
	close(gsn->fd1u);

	rate_ctr_group_free(gsn->ctrg);

	talloc_free(gsn);
	return 0;
}

/* API: Register create context indication callback */
int gtp_set_cb_create_context_ind(struct gsn_t *gsn,
				  int (*cb_create_context_ind) (struct pdp_t *
								pdp))
{
	gsn->cb_create_context_ind = cb_create_context_ind;
	return 0;
}

int gtp_set_cb_update_context_ind(struct gsn_t *gsn,
				  int (*cb_update_context_ind)(struct pdp_t *pdp))
{
	gsn->cb_update_context_ind = cb_update_context_ind;
	return 0;
}

int gtp_retrans(struct gsn_t *gsn)
{
	/* dummy API, deprecated. */
	return 0;
}

int gtp_retranstimeout(struct gsn_t *gsn, struct timeval *timeout)
{
	timeout->tv_sec = 24*60*60;
	timeout->tv_usec = 0;
	/* dummy API, deprecated. Return a huge timer to do nothing */
	return 0;
}

void gtp_set_talloc_ctx(void *ctx)
{
	tall_gsn_ctx = ctx;
}
