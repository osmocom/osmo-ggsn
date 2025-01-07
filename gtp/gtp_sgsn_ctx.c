/*
 *  OsmoGGSN - Gateway GPRS Support Node
 *  Copyright (C) 2024 sysmocom s.f.m.c. GmbH
 *
 *  Author: Alexander Couzens <lynxis@fe80.eu>
 *
 *  The contents of this file may be used under the terms of the GNU
 *  General Public License Version 2, provided that the above copyright
 *  notice and this permission notice is included in all copies or
 *  substantial portions of the software.
 *
 */

#include <osmocom/core/fsm.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/tdef.h>

#include <osmocom/gtp/gsn.h>
#include <osmocom/gtp/gtp.h>
#include <osmocom/gtp/gtpie.h>

#include "gtp_sgsn_ctx.h"

#define X(s) (1 << (s))

/* Handle the logic part of the SGSN Context Req/Resp/Ack */

const struct value_string sgsn_ctx_event_names[] = {
	OSMO_VALUE_STRING(SGSN_CTX_REQ_E_RX_REQ),
	OSMO_VALUE_STRING(SGSN_CTX_REQ_E_TX_RESP),
	OSMO_VALUE_STRING(SGSN_CTX_REQ_E_TX_RESP_FAIL),
	OSMO_VALUE_STRING(SGSN_CTX_REQ_E_RX_ACK),
	OSMO_VALUE_STRING(SGSN_CTX_REQ_E_RX_NACK),

	OSMO_VALUE_STRING(SGSN_CTX_REQ_E_TX_REQ),
	OSMO_VALUE_STRING(SGSN_CTX_REQ_E_RX_RESP),
	OSMO_VALUE_STRING(SGSN_CTX_REQ_E_RX_RESP_FAIL),
	OSMO_VALUE_STRING(SGSN_CTX_REQ_E_TX_ACK),
	OSMO_VALUE_STRING(SGSN_CTX_REQ_E_TX_NACK),
	{ 0, NULL }
};

static const struct osmo_tdef_state_timeout sgsn_ctx_fsm_timeouts[32] = {
	[SGSN_CTX_REQ_ST_START] = { },

	[SGSN_CTX_REQ_ST_WAIT_LOCAL_RESP] = { },
	[SGSN_CTX_REQ_ST_WAIT_REMOTE_ACK] = { },

	[SGSN_CTX_REQ_ST_WAIT_REMOTE_RESP] = { },
	[SGSN_CTX_REQ_ST_WAIT_LOCAL_ACK] = { },
};

struct osmo_tdef gtp_tdefs_sgsn_ctx[] = {
	{ /* terminator */ }
};

/* Used to pass all relevant data to the fsm via data */
struct ctx_msg {
	/* Message type */
	uint8_t msg;
	union gtpie_member * const *ie;
	unsigned int ie_size;
};

#define sgsn_ctx_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, sgsn_ctx_fsm_timeouts, gtp_tdefs_sgsn_ctx, 10)

/* Direction of the SGSN context.
 * Outgoing Ctx: From local to remote.
 * Incoming Ctx: From remote to local.
 */
static void sgsn_ctx_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_ctx_req *req = fi->priv;
	struct gsn_t *gsn = req->gsn;
	struct ctx_msg *msg = data;

	switch (event) {
	case SGSN_CTX_REQ_E_RX_REQ:
		/* remote SGSN ask this peer */
		sgsn_ctx_fsm_state_chg(fi, SGSN_CTX_REQ_ST_WAIT_LOCAL_RESP);
		if (gsn->cb_sgsn_context_request_ind)
			gsn->cb_sgsn_context_request_ind(gsn, &req->peer, req->local_teic, msg->ie, msg->ie_size);
		break;
	case SGSN_CTX_REQ_E_TX_REQ:
		/* local SGSN ask remote peer */
		sgsn_ctx_fsm_state_chg(fi, SGSN_CTX_REQ_ST_WAIT_REMOTE_RESP);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Outgoing Ctx: remote SGSN ask this peer, waiting for a resp from this node (SGSN) */
static void sgsn_ctx_wait_local_resp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SGSN_CTX_REQ_E_TX_RESP:
		sgsn_ctx_fsm_state_chg(fi, SGSN_CTX_REQ_ST_WAIT_REMOTE_ACK);
		break;
	case SGSN_CTX_REQ_E_TX_RESP_FAIL:
		sgsn_ctx_fsm_state_chg(fi, SGSN_CTX_REQ_ST_WAIT_REMOTE_RESP);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Outgoing Ctx: This node (SGSN) answered with a Ctx Resp, waiting for a remote Ack or Nack */
static void sgsn_ctx_wait_remote_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_ctx_req *req = fi->priv;
	struct gsn_t *gsn = req->gsn;
	struct ctx_msg *msg = data;

	switch (event) {
	case SGSN_CTX_REQ_E_RX_ACK:
		if (gsn->cb_sgsn_context_ack_ind)
			gsn->cb_sgsn_context_ack_ind(gsn, &req->peer, req->local_teic, msg->ie, msg->ie_size);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, NULL);
		break;
	case SGSN_CTX_REQ_E_RX_NACK:
		if (gsn->cb_sgsn_context_ack_ind)
			gsn->cb_sgsn_context_ack_ind(gsn, &req->peer, req->local_teic, msg->ie, msg->ie_size);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Incoming Ctx: This node requested a remote SGSN. Waiting for a remote response */
static void sgsn_ctx_wait_remote_resp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_ctx_req *req = fi->priv;
	struct gsn_t *gsn = req->gsn;
	struct ctx_msg *msg = data;

	switch (event) {
	case SGSN_CTX_REQ_E_RX_RESP:
		sgsn_ctx_fsm_state_chg(fi, SGSN_CTX_REQ_ST_WAIT_LOCAL_ACK);
		if (gsn->cb_sgsn_context_response_ind)
			gsn->cb_sgsn_context_response_ind(gsn, &req->peer, req->local_teic, msg->ie, msg->ie_size);
		break;
	case SGSN_CTX_REQ_E_RX_RESP_FAIL:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Incoming Ctx: Received a Response, waiting for this node to respond with an Ack or Nack */
static void sgsn_ctx_local_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SGSN_CTX_REQ_E_TX_ACK:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;
	case SGSN_CTX_REQ_E_TX_NACK:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

int sgsn_ctx_timer_cb(struct osmo_fsm_inst *fi)
{
	/* Terminating the FSM when a timeout happens */
	return 1;
}

static struct osmo_fsm_state sgsn_ctx_req_states[] = {
	[SGSN_CTX_REQ_ST_START] = {
		.in_event_mask =
			X(SGSN_CTX_REQ_E_RX_REQ) |
			X(SGSN_CTX_REQ_E_TX_REQ),
		.out_state_mask =
			X(SGSN_CTX_REQ_ST_WAIT_LOCAL_RESP) |
			X(SGSN_CTX_REQ_ST_WAIT_REMOTE_RESP),
		.name = "Init",
		.action = sgsn_ctx_init,
	},

	[SGSN_CTX_REQ_ST_WAIT_LOCAL_RESP] = {
		.in_event_mask =
			X(SGSN_CTX_REQ_E_TX_RESP) |
			X(SGSN_CTX_REQ_E_TX_RESP_FAIL),
		.out_state_mask =
			X(SGSN_CTX_REQ_ST_WAIT_REMOTE_ACK),
		.name = "Wait Local Response",
		.action = sgsn_ctx_wait_local_resp,
	},
	[SGSN_CTX_REQ_ST_WAIT_REMOTE_ACK] = {
		.in_event_mask =
			X(SGSN_CTX_REQ_E_RX_ACK) |
			X(SGSN_CTX_REQ_E_RX_NACK),
		.out_state_mask = 0,
		.name = "Wait Remote Ack",
		.action = sgsn_ctx_wait_remote_ack,
	},

	[SGSN_CTX_REQ_ST_WAIT_REMOTE_RESP] = {
		.in_event_mask =
			X(SGSN_CTX_REQ_E_RX_RESP) |
			X(SGSN_CTX_REQ_E_RX_RESP_FAIL),
		.out_state_mask =
			X(SGSN_CTX_REQ_ST_WAIT_LOCAL_ACK),
		.name = "Wait Remote Response",
		.action = sgsn_ctx_wait_remote_resp,
	},
	[SGSN_CTX_REQ_ST_WAIT_LOCAL_ACK] = {
		.in_event_mask =
			X(SGSN_CTX_REQ_E_TX_ACK) |
			X(SGSN_CTX_REQ_E_TX_NACK),
		.out_state_mask = 0,
		.name = "Wait Local Ack",
		.action = sgsn_ctx_local_ack,
	},
};

struct osmo_fsm sgsn_ctx_req_fsm = {
	.name = "SGSNCtxReq",
	.states = sgsn_ctx_req_states,
	.num_states = ARRAY_SIZE(sgsn_ctx_req_states),
	.event_names = sgsn_ctx_event_names,
	.log_subsys = DLGTP,
	.timer_cb = sgsn_ctx_timer_cb,
};

static __attribute__((constructor)) void sgsn_ctx_register(void)
{
	OSMO_ASSERT(osmo_fsm_register(&sgsn_ctx_req_fsm) == 0);
}

struct sgsn_ctx_reqs *sgsn_ctx_reqs_init(void *ctx, uint32_t lowest_teic, uint32_t highest_teic)
{
	struct sgsn_ctx_reqs *reqs;

	if (lowest_teic >= highest_teic)
		return NULL;

	reqs = talloc_zero(ctx, struct sgsn_ctx_reqs);
	if (!reqs)
		return reqs;

	reqs->lowest_teic = reqs->next_teic = lowest_teic;
	reqs->high_teic = highest_teic;

	INIT_LLIST_HEAD(&reqs->local_reqs);
	INIT_LLIST_HEAD(&reqs->remote_reqs);

	return reqs;
}

static uint32_t get_next_teic(struct gsn_t *gsn)
{
	uint32_t teic = gsn->sgsn_ctx->next_teic++;

	if (gsn->sgsn_ctx->next_teic > gsn->sgsn_ctx->high_teic)
		gsn->sgsn_ctx->next_teic = gsn->sgsn_ctx->lowest_teic;

	/* FIXME: check if this is already assigned! */

	return teic;
}

static struct sgsn_ctx_req *_sgsn_ctx_req_alloc(struct gsn_t *gsn)
{
	struct sgsn_ctx_req *req = talloc_zero(gsn, struct sgsn_ctx_req);

	if (!req)
		return NULL;

	req->fi = osmo_fsm_inst_alloc(&sgsn_ctx_req_fsm, req, req, LOGL_INFO, NULL);
	if (!req->fi)
		goto out;

	req->gsn = gsn;
	req->local_teic = get_next_teic(gsn);
	return req;

out:
	osmo_fsm_inst_free(req->fi);
	talloc_free(req);
	return NULL;
}

/* Alloc a SGSN_CTX for an outgoing Context (Remote SGSN requested) */
static struct sgsn_ctx_req *sgsn_ctx_req_alloc_outgoing(struct gsn_t *gsn, const struct sockaddr_in *peer, uint16_t seq)
{
	struct sgsn_ctx_req *req = _sgsn_ctx_req_alloc(gsn);
	if (!req)
		return req;

	req->seq = seq;
	req->peer = *peer;
	llist_add_tail(&req->list, &gsn->sgsn_ctx->remote_reqs);

	return req;
}

/* Alloc a SGSN_CTX for an incoming Context (Local SGSN requested) */
static struct sgsn_ctx_req *sgsn_ctx_req_alloc_incoming(struct gsn_t *gsn, const struct sockaddr_in *peer, uint16_t seq)
{
	struct sgsn_ctx_req *req = _sgsn_ctx_req_alloc(gsn);
	if (!req)
		return req;

	req->seq = seq;
	req->peer = *peer;
	llist_add_tail(&req->list, &gsn->sgsn_ctx->local_reqs);

	return req;
}

static void sgsn_ctx_free(struct sgsn_ctx_req *req)
{
	if (!req)
		return;

	osmo_fsm_inst_free(req->fi);
	llist_del(&req->list);
	talloc_free(req);
}

static struct sgsn_ctx_req *sgsn_ctx_by_teic(struct gsn_t *gsn, uint32_t teic, bool local_req)
{
	struct sgsn_ctx_req *req;
	struct llist_head *head;

	if (local_req)
		head = &gsn->sgsn_ctx->local_reqs;
	else
		head = &gsn->sgsn_ctx->remote_reqs;

	llist_for_each_entry(req, head, list) {
		if (req->local_teic == teic)
			return req;
	}

	return NULL;
}

int sgsn_ctx_req_fsm_rx_req(struct gsn_t *gsn, const struct sockaddr_in *peer,
			    uint16_t seq,
			    union gtpie_member * const *ie, unsigned int ie_size)
{
	struct sgsn_ctx_req *req = sgsn_ctx_req_alloc_outgoing(gsn, peer, seq);
	struct ctx_msg ctx_msg = {
		.msg = GTP_SGSN_CONTEXT_REQ,
		.ie = ie,
		.ie_size = ie_size,
	};

	if (!req)
		return -ENOMEM;

	if (!gsn->cb_sgsn_context_request_ind)
		goto err;

	if (gtpie_gettv4(ie, GTPIE_TEI_C, 0, &req->remote_teic))
		goto err;

	if (osmo_fsm_inst_dispatch(req->fi, SGSN_CTX_REQ_E_RX_REQ, &ctx_msg))
		goto err;

	return 0;
err:
	sgsn_ctx_free(req);
	return -EINVAL;
}

int sgsn_ctx_req_fsm_rx_resp(struct gsn_t *gsn, const struct sockaddr_in *peer,
			     uint16_t seq, uint32_t local_teic,
			     union gtpie_member * const *ie, unsigned int ie_size)
{
	struct sgsn_ctx_req *req = sgsn_ctx_by_teic(gsn, local_teic, true);
	uint8_t cause;
	struct ctx_msg ctx_msg = {
	    .msg = GTP_SGSN_CONTEXT_RSP,
	    .ie = ie,
	    .ie_size = ie_size,
	};

	if (!req)
		return -ENOENT;

	if (gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause))
		return -EINVAL;

	if (gtpie_gettv4(ie, GTPIE_TEI_C, 0, &req->remote_teic) && cause == GTPCAUSE_ACC_REQ)
		return -EINVAL;

	if (osmo_fsm_inst_dispatch(req->fi,
				   cause == GTPCAUSE_ACC_REQ ? SGSN_CTX_REQ_E_RX_RESP : SGSN_CTX_REQ_E_RX_RESP_FAIL,
				   &ctx_msg))
		return -EINVAL;

	return 0;
}

int sgsn_ctx_req_fsm_rx_ack(struct gsn_t *gsn, const struct sockaddr_in *peer,
			    uint16_t seq, uint32_t local_teic,
			    union gtpie_member * const *ie, unsigned int ie_size)
{
	struct sgsn_ctx_req *req = sgsn_ctx_by_teic(gsn, local_teic, false);
	struct ctx_msg ctx_msg = {
	    .msg = GTP_SGSN_CONTEXT_ACK,
	    .ie = ie,
	    .ie_size = ie_size,
	};

	if (!req)
		return -ENOENT;

	if (osmo_fsm_inst_dispatch(req->fi, SGSN_CTX_REQ_E_RX_ACK, &ctx_msg))
		return -EINVAL;

	return 0;
}

int sgsn_ctx_req_fsm_tx_req(struct gsn_t *gsn, const struct sockaddr_in *peer,
			    union gtpie_member * const *ie, unsigned int ie_size,
			    uint32_t *local_teic, uint16_t seq)
{
	struct sgsn_ctx_req *req = sgsn_ctx_req_alloc_incoming(gsn, peer, seq);
	struct ctx_msg ctx_msg = {
	    .msg = GTP_SGSN_CONTEXT_REQ,
	    .ie = ie,
	    .ie_size = ie_size,
	};

	if (!req)
		return -ENOMEM;

	/* TODO: move tx GTPv1 into the fsm */
	*local_teic = req->local_teic;

	if (osmo_fsm_inst_dispatch(req->fi, SGSN_CTX_REQ_E_TX_REQ, &ctx_msg))
		goto err;

	return 0;

err:
	sgsn_ctx_free(req);
	return -EINVAL;
}

int sgsn_ctx_req_fsm_tx_resp(struct gsn_t *gsn, struct sockaddr_in *peer,
			     uint16_t *seq, uint32_t local_teic, uint32_t *remote_teic,
			     union gtpie_member * const *ie, unsigned int ie_size)
{
	struct sgsn_ctx_req *req = sgsn_ctx_by_teic(gsn, local_teic, false);
	uint8_t cause;
	struct ctx_msg ctx_msg = {
	    .msg = GTP_SGSN_CONTEXT_RSP,
	    .ie = ie,
	    .ie_size = ie_size,
	};

	if (!req)
		return -ENOENT;

	/* TODO: move tx GTPv1 into the fsm */
	*seq = req->seq;
	*peer = req->peer;
	*remote_teic = req->remote_teic;

	if (gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause))
		return -EINVAL;

	if (osmo_fsm_inst_dispatch(req->fi,
				   cause == GTPCAUSE_ACC_REQ ? SGSN_CTX_REQ_E_TX_RESP : SGSN_CTX_REQ_E_TX_RESP_FAIL,
				   &ctx_msg))
		return -EINVAL;

	return 0;
}

int sgsn_ctx_req_fsm_tx_ack(struct gsn_t *gsn, struct sockaddr_in *peer,
			    uint16_t *seq, uint32_t local_teic, uint32_t *remote_teic,
			    union gtpie_member * const *ie, unsigned int ie_size)
{
	struct sgsn_ctx_req *req = sgsn_ctx_by_teic(gsn, local_teic, true);
	uint8_t cause;
	struct ctx_msg ctx_msg = {
	    .msg = GTP_SGSN_CONTEXT_ACK,
	    .ie = ie,
	    .ie_size = ie_size,
	};

	if (!req)
		return -ENOENT;

	/* TODO: move tx GTPv1 into the fsm */
	*seq = req->seq;
	*peer = req->peer;
	*remote_teic = req->remote_teic;

	if (gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause))
		return -EINVAL;

	if (osmo_fsm_inst_dispatch(req->fi,
				   cause == GTPCAUSE_ACC_REQ ? SGSN_CTX_REQ_E_TX_ACK : SGSN_CTX_REQ_E_TX_NACK,
				   &ctx_msg))
		return -EINVAL;

	return 0;
}
