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

#include "pdp.h"
#include "gtp.h"
#include "gtpie.h"
#include "queue.h"

/* According to section 14.2 of 3GPP TS 29.006 version 6.9.0 */
#define N3_REQUESTS	5

#define T3_REQUEST	3

/* Error reporting functions */

#define LOGP_WITH_ADDR(ss, level, addr, fmt, args...)                    \
		LOGP(ss, level, "addr(%s:%d) " fmt,                      \
		     inet_ntoa((addr).sin_addr), htons((addr).sin_port), \
		     ##args);

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
	now = time(NULL);

	/* get first element in queue, as long as the timeout of that
	 * element has expired */
	while ((!queue_getfirst(gsn->queue_req, &qmsg)) &&
	       (qmsg->timeout <= now)) {
		if (qmsg->retrans > N3_REQUESTS) {	/* Too many retrans */
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
				gsn->err_sendto++;
				LOGP(DLGTP, LOGL_ERROR,
					"Sendto(fd0=%d, msg=%lx, len=%d) failed: Error = %s\n",
					gsn->fd0, (unsigned long)&qmsg->p,
					qmsg->l, strerror(errno));
			}
			queue_back(gsn->queue_req, qmsg);
			qmsg->timeout = now + T3_REQUEST;
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

int gtp_new(struct gsn_t **gsn, char *statedir, struct in_addr *listen,
	    int mode)
{
	struct sockaddr_in addr;

	LOGP(DLGTP, LOGL_NOTICE, "GTP: gtp_newgsn() started at %s\n", inet_ntoa(*listen));

	*gsn = calloc(sizeof(struct gsn_t), 1);	/* TODO */

	(*gsn)->statedir = statedir;
	log_restart(*gsn);

	/* Initialise sequence number */
	(*gsn)->seq_next = (*gsn)->restart_counter * 1024;

	/* Initialise request retransmit queue */
	queue_new(&(*gsn)->queue_req);
	queue_new(&(*gsn)->queue_resp);

	/* Initialise pdp table */
	pdp_init(*gsn);

	/* Initialize internal queue timer */
	osmo_timer_setup(&(*gsn)->queue_timer, queue_timer_cb, *gsn);

	/* Initialise call back functions */
	(*gsn)->cb_create_context_ind = 0;
	(*gsn)->cb_delete_context = 0;
	(*gsn)->cb_unsup_ind = 0;
	(*gsn)->cb_conf = 0;
	(*gsn)->cb_data_ind = 0;

	/* Store function parameters */
	(*gsn)->gsnc = *listen;
	(*gsn)->gsnu = *listen;
	(*gsn)->mode = mode;

	/* Create GTP version 0 socket */
	if (((*gsn)->fd0 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		(*gsn)->err_socket++;
		LOGP(DLGTP, LOGL_ERROR,
		     "GTPv0 socket(domain=%d, type=%d, protocol=%d) failed: Error = %s\n",
			AF_INET, SOCK_DGRAM, 0, strerror(errno));
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = *listen;	/* Same IP for user traffic and signalling */
	addr.sin_port = htons(GTP0_PORT);
#if defined(__FreeBSD__) || defined(__APPLE__)
	addr.sin_len = sizeof(addr);
#endif

	if (bind((*gsn)->fd0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		(*gsn)->err_socket++;
		LOGP_WITH_ADDR(DLGTP, LOGL_ERROR, addr,
			       "bind(fd0=%d) failed: Error = %s\n",
			       (*gsn)->fd0, strerror(errno));
		return -errno;
	}

	/* Create GTP version 1 control plane socket */
	if (((*gsn)->fd1c = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		(*gsn)->err_socket++;
		LOGP(DLGTP, LOGL_ERROR,
		     "GTPv1 control plane socket(domain=%d, type=%d, protocol=%d) failed: Error = %s\n",
			AF_INET, SOCK_DGRAM, 0, strerror(errno));
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = *listen;	/* Same IP for user traffic and signalling */
	addr.sin_port = htons(GTP1C_PORT);
#if defined(__FreeBSD__) || defined(__APPLE__)
	addr.sin_len = sizeof(addr);
#endif

	if (bind((*gsn)->fd1c, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		(*gsn)->err_socket++;
		LOGP_WITH_ADDR(DLGTP, LOGL_ERROR, addr,
				"bind(fd1c=%d) failed: Error = %s\n",
				(*gsn)->fd1c, strerror(errno));
		return -errno;
	}

	/* Create GTP version 1 user plane socket */
	if (((*gsn)->fd1u = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		(*gsn)->err_socket++;
		LOGP(DLGTP, LOGL_ERROR,
		     "GTPv1 user plane socket(domain=%d, type=%d, protocol=%d) failed: Error = %s\n",
			AF_INET, SOCK_DGRAM, 0, strerror(errno));
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = *listen;	/* Same IP for user traffic and signalling */
	addr.sin_port = htons(GTP1U_PORT);
#if defined(__FreeBSD__) || defined(__APPLE__)
	addr.sin_len = sizeof(addr);
#endif

	if (bind((*gsn)->fd1u, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		(*gsn)->err_socket++;
		LOGP_WITH_ADDR(DLGTP, LOGL_ERROR, addr,
			"bind(fd1u=%d) failed: Error = %s\n",
			(*gsn)->fd1u, strerror(errno));
		return -errno;
	}

	/* Start internal queue timer */
	gtp_queue_timer_start(*gsn);

	return 0;
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

	free(gsn);
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