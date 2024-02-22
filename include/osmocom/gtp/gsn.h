/*
 *  OsmoGGSN - Gateway GPRS Support Node
 *  Copyright (C) 2002, 2003, 2004 Mondru AB.
 *
 *  The contents of this file may be used under the terms of the GNU
 *  General Public License Version 2, provided that the above copyright
 *  notice and this permission notice is included in all copies or
 *  substantial portions of the software.
 *
 */

#ifndef _GSN_H
#define _GSN_H

#include <osmocom/core/utils.h>
#include <osmocom/core/defs.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/rate_ctr.h>

#include "pdp.h"

#define GTP_MODE_GGSN 1
#define GTP_MODE_SGSN 2

#define RESTART_FILE "gsn_restart"

extern struct osmo_tdef gtp_T_defs[];

/* ***********************************************************
 * Information storage for each gsn instance
 *
 * Normally each instance of the application corresponds to
 * one instance of a gsn.
 *
 * In order to avoid global variables in the application, and
 * also in order to allow several instances of a gsn in the same
 * application this struct is provided in order to store all
 * relevant information related to the gsn.
 *
 * Note that this does not include information storage for '
 * each pdp context. This is stored in another struct.
 *************************************************************/

enum gsn_rate_ctr_keys {
	GSN_CTR_ERR_SOCKET,
	GSN_CTR_ERR_READFROM,	/* Number of readfrom errors */
	GSN_CTR_ERR_SENDTO,	/* Number of sendto errors */
	GSN_CTR_ERR_QUEUEFULL,	/* Number of times queue was full */
	GSN_CTR_ERR_SEQ,	/* Number of seq out of range */
	GSN_CTR_ERR_ADDRESS,	/* GSN address conversion failed */
	GSN_CTR_ERR_UNKNOWN_PDP,	/* GSN address conversion failed */
	GSN_CTR_ERR_UNEXPECTED_CAUSE,	/* Unexpected cause value received */
	GSN_CTR_ERR_OUT_OF_PDP,	/* Out of storage for PDP contexts */
	GSN_CTR_PKT_EMPTY,		/* Number of empty packets */
	GSN_CTR_PKT_UNSUP,		/* Number of unsupported version 29.60 11.1.1 */
	GSN_CTR_PKT_TOOSHORT,	/* Number of too short headers 29.60 11.1.2 */
	GSN_CTR_PKT_UNKNOWN,	/* Number of unknown messages 29.60 11.1.3 */
	GSN_CTR_PKT_UNEXPECT,	/* Number of unexpected messages 29.60 11.1.4 */
	GSN_CTR_PKT_DUPLICATE,	/* Number of duplicate or unsolicited replies */
	GSN_CTR_PKT_MISSING,	/* Number of missing information field messages */
	GSN_CTR_PKT_INCORRECT,	/* Number of incorrect information field messages */
	GSN_CTR_PKT_INVALID,	/* Number of invalid message format messages */
};

/* 3GPP TS 29.006 14.1, 14,2 */
enum gtp_gsn_timers {
	GTP_GSN_TIMER_T3_RESPONSE = 3,
	GTP_GSN_TIMER_N3_REQUESTS = 1003,
	GTP_GSN_TIMER_T3_HOLD_RESPONSE = -3,
};

struct gsn_t {
	/* Parameters related to the network interface */

	int fd0;		/* GTP0 file descriptor */
	int fd1c;		/* GTP1 control plane file descriptor */
	int fd1u;		/* GTP0 user plane file descriptor */
	int mode;		/* Mode of operation: GGSN or SGSN */
	struct in_addr gsnc;	/* IP address of this gsn for signalling */
	struct in_addr gsnu;	/* IP address of this gsn for user traffic */

	/* Parameters related to signalling messages */
	uint16_t seq_next;	/* Next sequence number to use */
	int seq_first;		/* First packet in queue (oldest timeout) */
	int seq_last;		/* Last packet in queue (youngest timeout) */

	unsigned char restart_counter;	/* Increment on restart. Stored on disk */
	char *statedir;		/* Disk location for permanent storage */
	void *priv;		/* used by libgtp users to attach their own state) */
	struct queue_t *queue_req;	/* Request queue */
	struct queue_t *queue_resp;	/* Response queue */

	struct pdp_t pdpa[PDP_MAX];	/* PDP storage */
	struct pdp_t *hashtid[PDP_MAX];	/* Hash table for IMSI + NSAPI */

	struct osmo_timer_list queue_timer; /* internal queue_{req,resp} timer */

	/* Call back functions */
	int (*cb_delete_context) (struct pdp_t *);
	int (*cb_create_context_ind) (struct pdp_t *);
	int (*cb_unsup_ind) (struct sockaddr_in * peer);
	int (*cb_extheader_ind) (struct sockaddr_in * peer);
	int (*cb_ran_info_relay_ind) (struct sockaddr_in *peer, union gtpie_member **ie);
	int (*cb_conf) (int type, int cause, struct pdp_t * pdp, void *cbp);
	int (*cb_data_ind) (struct pdp_t * pdp, void *pack, unsigned len);
	int (*cb_recovery) (struct sockaddr_in * peer, uint8_t recovery);
	int (*cb_recovery2) (struct sockaddr_in * peer, struct pdp_t * pdp, uint8_t recovery);
	int (*cb_recovery3) (struct gsn_t *gsn, struct sockaddr_in *peer, struct pdp_t *pdp, uint8_t recovery);

	/* Counters */
	struct rate_ctr_group *ctrg;

	/* Timers: */
	struct osmo_tdef *tdef;
};

/* External API functions */

extern int gtp_new(struct gsn_t **gsn, char *statedir, struct in_addr *listen,
		   int mode);

extern int gtp_free(struct gsn_t *gsn);

extern int gtp_newpdp(struct gsn_t *gsn, struct pdp_t **pdp,
		      uint64_t imsi, uint8_t nsapi) OSMO_DEPRECATED("Use gtp_pdp_newpdp() instead");
extern int gtp_freepdp(struct gsn_t *gsn, struct pdp_t *pdp);
extern int gtp_freepdp_teardown(struct gsn_t *gsn, struct pdp_t *pdp);

extern int gtp_create_context_req(struct gsn_t *gsn, struct pdp_t *pdp,
				  void *cbp);

extern int gtp_set_cb_create_context_ind(struct gsn_t *gsn,
					 int (*cb_create_context_ind) (struct
								       pdp_t *
								       pdp));
extern int gtp_set_cb_data_ind(struct gsn_t *gsn,
			       int (*cb_data_ind) (struct pdp_t * pdp,
						   void *pack, unsigned len));
extern int gtp_set_cb_delete_context(struct gsn_t *gsn,
				     int (*cb_delete_context) (struct pdp_t *
							       pdp));
/*extern int gtp_set_cb_create_context(struct gsn_t *gsn,
  int (*cb_create_context) (struct pdp_t* pdp)); */

extern int gtp_set_cb_unsup_ind(struct gsn_t *gsn,
				int (*cb) (struct sockaddr_in * peer));

extern int gtp_set_cb_extheader_ind(struct gsn_t *gsn,
				    int (*cb) (struct sockaddr_in * peer));

extern int gtp_set_cb_ran_info_relay_ind(struct gsn_t *gsn,
				    int (*cb) (struct sockaddr_in * peer, union gtpie_member **ie));

extern int gtp_set_cb_conf(struct gsn_t *gsn,
			   int (*cb) (int type, int cause, struct pdp_t * pdp,
				      void *cbp));

int gtp_set_cb_recovery(struct gsn_t *gsn,
			int (*cb) (struct sockaddr_in * peer,
				   uint8_t recovery))
	OSMO_DEPRECATED("Use gtp_set_cb_recovery2() instead, to obtain pdp ctx originating the recovery");
int gtp_set_cb_recovery2(struct gsn_t *gsn,
			int (*cb) (struct sockaddr_in * peer,
				   struct pdp_t * pdp,
				   uint8_t recovery))
	OSMO_DEPRECATED("Use gtp_set_cb_recovery3() instead, to obtain gsn handling the recovery");
int gtp_set_cb_recovery3(struct gsn_t *gsn,
			int (*cb) (struct gsn_t * gsn, struct sockaddr_in * peer,
				   struct pdp_t * pdp,
				   uint8_t recovery));
void gtp_clear_queues(struct gsn_t *gsn);
extern int gtp_fd(struct gsn_t *gsn);

extern int gtp_retrans(struct gsn_t *gsn) OSMO_DEPRECATED("This API is a no-op, libgtp already does the job internally");
extern int gtp_retranstimeout(struct gsn_t *gsn, struct timeval *timeout) OSMO_DEPRECATED("This API is a no-op and will return a 1 day timeout");

/* Internal APIs: */
void gtp_queue_timer_start(struct gsn_t *gsn);

#endif /* !_GSN_H */
