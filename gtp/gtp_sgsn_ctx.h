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

#include <netinet/in.h>

#include <osmocom/core/linuxlist.h>

struct gsn_t;
struct osmo_fsm_inst;
union gtpie_member;


enum gtp_sgsn_ctx_states {
	SGSN_CTX_REQ_ST_START,
	/* remote SGSN/MME request a Ctx from this peer */
	SGSN_CTX_REQ_ST_WAIT_LOCAL_RESP, /*! wait for this peer to tx a SGSN Ctx Respond */
	SGSN_CTX_REQ_ST_WAIT_REMOTE_ACK, /*! wait for remote peer SGSN Ctx Ack */

	/* local SGSN request a Ctx from a remote peer (SGSN/MME) */
	SGSN_CTX_REQ_ST_WAIT_REMOTE_RESP, /*! wait for remote peer to send this peer a SGSN Ctx Respond */
	SGSN_CTX_REQ_ST_WAIT_LOCAL_ACK, /*! wait for the local peer to ack */
};

enum gtp_sgsn_ctx_req_event {
	/* remote SGSN/MME request a Ctx from this peer */
	SGSN_CTX_REQ_E_RX_REQ,
	SGSN_CTX_REQ_E_TX_RESP, /* a response with a success reason */
	SGSN_CTX_REQ_E_TX_RESP_FAIL,
	SGSN_CTX_REQ_E_RX_ACK,
	SGSN_CTX_REQ_E_RX_NACK, /* a nack with a reason != success */

	/* local SGSN requests a Context from a remote peer (SGSN/MME) */
	SGSN_CTX_REQ_E_TX_REQ,
	SGSN_CTX_REQ_E_RX_RESP,
	SGSN_CTX_REQ_E_RX_RESP_FAIL,
	SGSN_CTX_REQ_E_TX_ACK,
	SGSN_CTX_REQ_E_TX_NACK,
};

struct sgsn_ctx_reqs {
	/*! contains SGSN Context Request which this peer started by requesting a Ctx */
	struct llist_head local_reqs;
	/*! contains SGSN Context Requests which the remote peer started by sending a Ctx */
	struct llist_head remote_reqs;

	/* TEID-C */
	uint32_t lowest_teic; /*! lowest valid teic for Gn interface */
	uint32_t next_teic;
	uint32_t high_teic; /*! highest valid teic for Gn interface */
};

struct sgsn_ctx_req {
	/*! entry in sgsn_ctx_reqs local or remote reqs */
	struct llist_head list;
	struct gsn_t *gsn;

	struct osmo_fsm_inst *fsm;

	struct sockaddr_in peer;

	uint32_t local_teic;
	uint32_t remote_teic;

	uint16_t seq;
};

struct sgsn_ctx_reqs *sgsn_ctx_reqs_init(void *ctx, uint32_t lowest_teic, uint32_t highest_teic);

/*! Received a SGSN Context Request from a peeer */
int sgsn_ctx_req_fsm_rx_req(struct gsn_t *gsn, const struct sockaddr_in *peer,
			    uint16_t seq,
			    union gtpie_member * const *ie, unsigned int ie_size);

int sgsn_ctx_req_fsm_rx_resp(struct gsn_t *gsn, const struct sockaddr_in *peer,
			     uint16_t seq, uint32_t local_teic,
			     union gtpie_member * const *ie, unsigned int ie_size);

int sgsn_ctx_req_fsm_rx_ack(struct gsn_t *gsn, const struct sockaddr_in *peer,
			     uint16_t seq, uint32_t local_teic,
			     union gtpie_member * const *ie, unsigned int ie_size);


int sgsn_ctx_req_fsm_tx_req(struct gsn_t *gsn, const struct sockaddr_in *peer,
			    union gtpie_member * const *ie, unsigned int ie_size,
			    uint32_t *local_teic, uint16_t seq);

int sgsn_ctx_req_fsm_tx_resp(struct gsn_t *gsn, struct sockaddr_in *peer,
			     uint16_t *seq, uint32_t local_teic, uint32_t *remote_teic,
			     union gtpie_member * const *ie, unsigned int ie_size);

int sgsn_ctx_req_fsm_tx_ack(struct gsn_t *gsn, struct sockaddr_in *peer,
			    uint16_t *seq, uint32_t local_teic, uint32_t *remote_teic,
			    union gtpie_member * const *ie, unsigned int ie_size);
