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

#define GTP_LOGPKG(pri, peer, pack, len, fmt, args...)			\
	logp2(DLGTP, pri, __FILE__, __LINE__, 0,			\
		"Packet from %s:%u, length: %d content: %s: " fmt,	\
		inet_ntoa((peer)->sin_addr), htons((peer)->sin_port),	\
		len, osmo_hexdump((const uint8_t *) pack, len),		\
		##args);

#define LOGP_WITH_ADDR(ss, level, addr, fmt, args...)                    \
		LOGP(ss, level, "addr(%s:%d) " fmt,                      \
		     inet_ntoa((addr).sin_addr), htons((addr).sin_port), \
		     ##args);

/* API Functions */

const char *gtp_version()
{
	return VERSION;
}

const struct value_string gtp_type_names[] = {
	{ GTP_ECHO_REQ,        "Echo Request" },
	{ GTP_ECHO_RSP,        "Echo Response" },
	{ GTP_NOT_SUPPORTED,   "Version Not Supported" },
	{ GTP_ALIVE_REQ,       "Node Alive Request" },
	{ GTP_ALIVE_RSP,       "Node Alive Response" },
	{ GTP_REDIR_REQ,       "Redirection Request" },
	{ GTP_REDIR_RSP,       "Redirection Response" },
	{ GTP_CREATE_PDP_REQ,  "Create PDP Context Request" },
	{ GTP_CREATE_PDP_RSP,  "Create PDP Context Response" },
	{ GTP_UPDATE_PDP_REQ,  "Update PDP Context Request" },
	{ GTP_UPDATE_PDP_RSP,  "Update PDP Context Response" },
	{ GTP_DELETE_PDP_REQ,  "Delete PDP Context Request" },
	{ GTP_DELETE_PDP_RSP,  "Delete PDP Context Response" },
	{ GTP_ERROR,           "Error Indication" },
	{ GTP_PDU_NOT_REQ,     "PDU Notification Request" },
	{ GTP_PDU_NOT_RSP,     "PDU Notification Response" },
	{ GTP_PDU_NOT_REJ_REQ, "PDU Notification Reject Request" },
	{ GTP_PDU_NOT_REJ_RSP, "PDU Notification Reject Response" },
	{ GTP_SUPP_EXT_HEADER, "Supported Extension Headers Notification" },
	{ GTP_SND_ROUTE_REQ,   "Send Routeing Information for GPRS Request" },
	{ GTP_SND_ROUTE_RSP,   "Send Routeing Information for GPRS Response" },
	{ GTP_FAILURE_REQ,     "Failure Report Request" },
	{ GTP_FAILURE_RSP,     "Failure Report Response" },
	{ GTP_MS_PRESENT_REQ,  "Note MS GPRS Present Request" },
	{ GTP_MS_PRESENT_RSP,  "Note MS GPRS Present Response" },
	{ GTP_IDEN_REQ,        "Identification Request" },
	{ GTP_IDEN_RSP,        "Identification Response" },
	{ GTP_SGSN_CONTEXT_REQ,"SGSN Context Request" },
	{ GTP_SGSN_CONTEXT_RSP,"SGSN Context Response" },
	{ GTP_SGSN_CONTEXT_ACK,"SGSN Context Acknowledge" },
	{ GTP_FWD_RELOC_REQ,   "Forward Relocation Request" },
	{ GTP_FWD_RELOC_RSP,   "Forward Relocation Response" },
	{ GTP_FWD_RELOC_COMPL, "Forward Relocation Complete" },
	{ GTP_RELOC_CANCEL_REQ,"Relocation Cancel Request" },
	{ GTP_RELOC_CANCEL_RSP,"Relocation Cancel Response" },
	{ GTP_FWD_SRNS,        "Forward SRNS Context" },
	{ GTP_FWD_RELOC_ACK,   "Forward Relocation Complete Acknowledge" },
	{ GTP_FWD_SRNS_ACK,    "Forward SRNS Context Acknowledge" },
	{ GTP_DATA_TRAN_REQ,   "Data Record Transfer Request" },
	{ GTP_DATA_TRAN_RSP,   "Data Record Transfer Response" },
	{ GTP_GPDU,            "G-PDU" },
	{ 0, NULL }
};



static void emit_cb_recovery(struct gsn_t *gsn, struct sockaddr_in * peer,
			     struct pdp_t * pdp, uint8_t recovery)
{
	if (gsn->cb_recovery)
		gsn->cb_recovery(peer, recovery);
	if (gsn->cb_recovery2)
		gsn->cb_recovery2(peer, pdp, recovery);
	if (gsn->cb_recovery3)
		gsn->cb_recovery3(gsn, peer, pdp, recovery);
}

/**
 * get_default_gtp()
 * Generate a GPRS Tunneling Protocol signalling packet header, depending
 * on GTP version and message type. pdp is used for teid/flow label.
 * *packet must be allocated by the calling function, and be large enough
 * to hold the packet header.
 * returns the length of the header. 0 on error.
 **/
static unsigned int get_default_gtp(uint8_t version, uint8_t type, void *packet)
{
	struct gtp0_header *gtp0_default = (struct gtp0_header *)packet;
	struct gtp1_header_long *gtp1_default =
	    (struct gtp1_header_long *)packet;
	switch (version) {
	case 0:
		/* Initialise "standard" GTP0 header */
		memset(gtp0_default, 0, sizeof(struct gtp0_header));
		gtp0_default->flags = 0x1e;
		gtp0_default->type = hton8(type);
		gtp0_default->spare1 = 0xff;
		gtp0_default->spare2 = 0xff;
		gtp0_default->spare3 = 0xff;
		gtp0_default->number = 0xff;
		return GTP0_HEADER_SIZE;
	case 1:
		/* Initialise "standard" GTP1 header */
		/* 29.060: 8.2: S=1 and PN=0 */
		/* 29.060 9.3.1: For GTP-U messages Echo Request, Echo Response */
		/* and Supported Extension Headers Notification, the S field shall be */
		/* set to 1 */
		/* Currently extension headers are not supported */
		memset(gtp1_default, 0, sizeof(struct gtp1_header_long));
		/* No extension, enable sequence, no N-PDU */
		gtp1_default->flags = GTPHDR_F_VER(1) | GTP1HDR_F_GTP1 | GTP1HDR_F_SEQ;
		gtp1_default->type = hton8(type);
		return GTP1_HEADER_SIZE_LONG;
	default:
		LOGP(DLGTP, LOGL_ERROR,
			"Unknown GTP packet version: %d\n", version);
		return 0;
	}
}

/**
 * get_seq()
 * Get sequence number of a packet.
 * Returns 0 on error
 **/
static uint16_t get_seq(void *pack)
{
	union gtp_packet *packet = (union gtp_packet *)pack;
	uint8_t ver = GTPHDR_F_GET_VER(packet->flags);

	if (ver == 0) {
		return ntoh16(packet->gtp0.h.seq);
	} else if (ver == 1 && (packet->flags & GTP1HDR_F_SEQ)) {	/* Version 1 with seq */
		return ntoh16(packet->gtp1l.h.seq);
	} else {
		return 0;
	}
}

/**
 * get_tid()
 * Get tunnel identifier of a packet.
 * Returns 0 on error
 **/
static uint64_t get_tid(void *pack)
{
	union gtp_packet *packet = (union gtp_packet *)pack;

	if (GTPHDR_F_GET_VER(packet->flags) == 0) {	/* Version 0 */
		return be64toh(packet->gtp0.h.tid);
	}
	return 0;
}

/**
 * get_hlen()
 * Get the header length of a packet.
 * Returns 0 on error
 **/
static uint16_t get_hlen(void *pack)
{
	union gtp_packet *packet = (union gtp_packet *)pack;
	uint8_t ver = GTPHDR_F_GET_VER(packet->flags);

	if (ver == 0) {	/* Version 0 */
		return GTP0_HEADER_SIZE;
	} else if (ver == 1 && (packet->flags & 0x07) == 0) {	/* Short version 1 */
		return GTP1_HEADER_SIZE_SHORT;
	} else if (ver == 1) {	/* Version 1 with seq/n-pdu/ext */
		return GTP1_HEADER_SIZE_LONG;
	} else {
		LOGP(DLGTP, LOGL_ERROR, "Unknown packet flags: 0x%02x\n", packet->flags);
		return 0;
	}
}

/**
 * get_tei()
 * Get the tunnel endpoint identifier (flow label) of a packet.
 * Returns 0xffffffff on error.
 **/
static uint32_t get_tei(void *pack)
{
	union gtp_packet *packet = (union gtp_packet *)pack;
	uint8_t ver = GTPHDR_F_GET_VER(packet->flags);

	if (ver == 0) {	/* Version 0 */
		return ntoh16(packet->gtp0.h.flow);
	} else if (ver == 1) {	/* Version 1 */
		return ntoh32(packet->gtp1l.h.tei);
	} else {
		LOGP(DLGTP, LOGL_ERROR, "Unknown packet flags: 0x%02x\n", packet->flags);
		return 0xffffffff;
	}
}

/* ***********************************************************
 * Reliable delivery of signalling messages
 *
 * Sequence numbers are used for both signalling messages and
 * data messages.
 *
 * For data messages each tunnel maintains a sequence counter,
 * which is incremented by one each time a new data message
 * is sent. The sequence number starts at (0) zero at tunnel
 * establishment, and wraps around at 65535 (29.060 9.3.1.1
 * and 09.60 8.1.1.1). The sequence numbers are either ignored,
 * or can be used to check the validity of the message in the
 * receiver, or for reordering af packets.
 *
 * For signalling messages the sequence number is used by
 * signalling messages for which a response is defined. A response
 * message should copy the sequence from the corresponding request
 * message. The sequence number "unambiguously" identifies a request
 * message within a given path, with a path being defined as a set of
 * two endpoints (29.060 8.2, 29.060 7.6, 09.60 7.8). "All request
 * messages shall be responded to, and all response messages associated
 * with a certain request shall always include the same information"
 *
 * We take this to mean that the GSN transmitting a request is free to
 * choose the sequence number, as long as it is unique within a given path.
 * It means that we are allowed to count backwards, or roll over at 17
 * if we prefer that. It also means that we can use the same counter for
 * all paths. This has the advantage that the transmitted request sequence
 * numbers are unique within each GSN, and also we dont have to mess around
 * with path setup and teardown.
 *
 * If a response message is lost, the request will be retransmitted, and
 * the receiving GSN will receive a "duplicated" request. The standard
 * requires the receiving GSN to send a response, with the same information
 * as in the original response. For most messages this happens automatically:
 *
 * Echo: Automatically duplicates the original response
 * Create pdp context: The SGSN may send create context request even if
 *   a context allready exist (imsi+nsapi?). This means that the reply will
     automatically duplicate the original response. It might however have
 *   side effects in the application which is asked twice to validate
 *   the login.
 * Update pdp context: Automatically duplicates the original response???
 * Delete pdp context. Automatically in gtp0, but in gtp1 will generate
 *   a nonexist reply message.
 *
 * The correct solution will be to make a queue containing response messages.
 * This queue should be checked whenever a request is received. If the
 * response is already in the queue that response should be transmitted.
 * It should be possible to find messages in this queue on the basis of
 * the sequence number and peer GSN IP address (The sequense number is unique
 * within each path). This need to be implemented by a hash table. Furthermore
 * it should be possibly to delete messages based on a timeout. This can be
 * achieved by means of a linked list. The timeout value need to be larger
 * than T3-RESPONSE * N3-REQUESTS (recommended value 5). These timers are
 * set in the peer GSN, so there is no way to know these parameters. On the
 * other hand the timeout value need to be so small that we do not receive
 * wraparound sequence numbere before the message is deleted. 60 seconds is
 * probably not a bad choise.
 *
 * This queue however is first really needed from gtp1.
 *
 * gtp_req:
 *   Send off a signalling message with appropiate sequence
 *   number. Store packet in queue.
 * gtp_conf:
 *   Remove an incoming confirmation from the queue
 * gtp_resp:
 *   Send off a response to a request. Use the same sequence
 *   number in the response as in the request.
 * gtp_notification:
 *   Send off a notification message. This is neither a request nor
 *   a response. Both TEI and SEQ are zero.
 * gtp_retrans:
 *   Retransmit any outstanding packets which have exceeded
 *   a predefined timeout.
 *************************************************************/

static int gtp_req(struct gsn_t *gsn, uint8_t version, struct pdp_t *pdp,
	    union gtp_packet *packet, int len,
	    struct in_addr *inetaddr, void *cbp)
{
	uint8_t ver = GTPHDR_F_GET_VER(packet->flags);
	struct sockaddr_in addr;
	struct qmsg_t *qmsg;
	int fd;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = *inetaddr;
#if defined(__FreeBSD__) || defined(__APPLE__)
	addr.sin_len = sizeof(addr);
#endif

	if (ver == 0) {	/* Version 0 */
		addr.sin_port = htons(GTP0_PORT);
		packet->gtp0.h.length = hton16(len - GTP0_HEADER_SIZE);
		packet->gtp0.h.seq = hton16(gsn->seq_next);
		if (pdp) {
			packet->gtp0.h.tid =
				htobe64(pdp_gettid(pdp->imsi, pdp->nsapi));
		}
		if (pdp && ((packet->gtp0.h.type == GTP_GPDU)
			    || (packet->gtp0.h.type == GTP_ERROR)))
			packet->gtp0.h.flow = hton16(pdp->flru);
		else if (pdp)
			packet->gtp0.h.flow = hton16(pdp->flrc);
		fd = gsn->fd0;
	} else if (ver == 1 && (packet->flags & GTP1HDR_F_SEQ)) {	/* Version 1 with seq */
		addr.sin_port = htons(GTP1C_PORT);
		packet->gtp1l.h.length = hton16(len - GTP1_HEADER_SIZE_SHORT);
		packet->gtp1l.h.seq = hton16(gsn->seq_next);
		if (pdp && ((packet->gtp1l.h.type == GTP_GPDU) ||
			    (packet->gtp1l.h.type == GTP_ERROR)))
			packet->gtp1l.h.tei = hton32(pdp->teid_gn);
		else if (pdp)
			packet->gtp1l.h.tei = hton32(pdp->teic_gn);
		fd = gsn->fd1c;
	} else {
		LOGP(DLGTP, LOGL_ERROR, "Unknown packet flags: 0x%02x\n", packet->flags);
		return -1;
	}

	if (sendto(fd, packet, len, 0,
		   (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_SENDTO);
		LOGP(DLGTP, LOGL_ERROR, "Sendto(fd=%d, msg=%lx, len=%d, dst=%s) failed: Error = %s\n", fd,
		     (unsigned long)&packet, len, inet_ntoa(addr.sin_addr), strerror(errno));
		return -1;
	}

	/* Use new queue structure */
	if (queue_newmsg(gsn->queue_req, &qmsg, &addr, gsn->seq_next)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_QUEUEFULL);
		LOGP(DLGTP, LOGL_ERROR, "Retransmit req queue is full (seq=%" PRIu16 ")\n",
		     gsn->seq_next);
	} else {
		LOGP(DLGTP, LOGL_DEBUG, "Registering seq=%" PRIu16
		     " in restransmit req queue\n", gsn->seq_next);
		memcpy(&qmsg->p, packet, sizeof(union gtp_packet));
		qmsg->l = len;
		qmsg->timeout = time(NULL) + T3_REQUEST; /* When to timeout */
		qmsg->retrans = 0;	/* No retransmissions so far */
		qmsg->cbp = cbp;
		qmsg->type = ntoh8(packet->gtp0.h.type);
		qmsg->fd = fd;
		if (pdp) /* echo requests are not pdp-bound */
			llist_add(&qmsg->entry, &pdp->qmsg_list_req);

		/* Rearm timer: Retrans time for qmsg just queued may be required
		   before an existing one (for instance a gtp echo req) */
		gtp_queue_timer_start(gsn);
	}
	gsn->seq_next++;	/* Count up this time */
	return 0;
}

/* gtp_conf
 * Remove signalling packet from retransmission queue.
 * return 0 on success, EOF if packet was not found */

static int gtp_conf(struct gsn_t *gsn, uint8_t version, struct sockaddr_in *peer,
	     union gtp_packet *packet, int len, uint8_t * type, void **cbp)
{
	uint8_t ver = GTPHDR_F_GET_VER(packet->flags);
	uint16_t seq;

	if (ver == 0)
		seq = ntoh16(packet->gtp0.h.seq);
	else if (ver == 1 && (packet->gtp1l.h.flags & GTP1HDR_F_SEQ))
		seq = ntoh16(packet->gtp1l.h.seq);
	else {
		GTP_LOGPKG(LOGL_ERROR, peer, packet, len,
			    "Unknown GTP packet version\n");
		return EOF;
	}

	GTP_LOGPKG(LOGL_DEBUG, peer, packet, len,
		    "Freeing seq=%" PRIu16 " from retransmit req queue\n",
		    seq);
	if (queue_freemsg_seq(gsn->queue_req, peer, seq, type, cbp)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_SEQ);
		GTP_LOGPKG(LOGL_ERROR, peer, packet, len,
			    "Confirmation packet not found in retransmit req queue (seq=%"
			    PRIu16 ")\n", seq);
		return EOF;
	}

	return 0;
}

static int gtp_resp(uint8_t version, struct gsn_t *gsn, struct pdp_t *pdp,
	     union gtp_packet *packet, int len,
	     struct sockaddr_in *peer, int fd, uint16_t seq, uint64_t tid)
{
	uint8_t ver = GTPHDR_F_GET_VER(packet->flags);
	struct qmsg_t *qmsg;

	if (ver == 0) {	/* Version 0 */
		packet->gtp0.h.length = hton16(len - GTP0_HEADER_SIZE);
		packet->gtp0.h.seq = hton16(seq);
		packet->gtp0.h.tid = htobe64(tid);
		if (pdp && ((packet->gtp0.h.type == GTP_GPDU) ||
			    (packet->gtp0.h.type == GTP_ERROR)))
			packet->gtp0.h.flow = hton16(pdp->flru);
		else if (pdp)
			packet->gtp0.h.flow = hton16(pdp->flrc);
	} else if (ver == 1 && (packet->flags & GTP1HDR_F_SEQ)) {	/* Version 1 with seq */
		packet->gtp1l.h.length = hton16(len - GTP1_HEADER_SIZE_SHORT);
		packet->gtp1l.h.seq = hton16(seq);
		if (pdp && (fd == gsn->fd1u))
			packet->gtp1l.h.tei = hton32(pdp->teid_gn);
		else if (pdp)
			packet->gtp1l.h.tei = hton32(pdp->teic_gn);
	} else {
		LOGP(DLGTP, LOGL_ERROR, "Unknown packet flags: 0x%02x\n", packet->flags);
		return -1;
	}

	if (fcntl(fd, F_SETFL, 0)) {
		LOGP(DLGTP, LOGL_ERROR, "fnctl()\n");
		return -1;
	}

	if (sendto(fd, packet, len, 0,
		   (struct sockaddr *)peer, sizeof(struct sockaddr_in)) < 0) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_SENDTO);
		LOGP(DLGTP, LOGL_ERROR,
			"Sendto(fd=%d, msg=%lx, len=%d) failed: Error = %s\n", fd,
			(unsigned long)&packet, len, strerror(errno));
		return -1;
	}

	/* Use new queue structure */
	if (queue_newmsg(gsn->queue_resp, &qmsg, peer, seq)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_QUEUEFULL);
		LOGP(DLGTP, LOGL_ERROR, "Retransmit resp queue is full (seq=%" PRIu16 ")\n",
		     seq);
	} else {
		LOGP(DLGTP, LOGL_DEBUG, "Registering seq=%" PRIu16
		     " in restransmit resp queue\n", seq);
		memcpy(&qmsg->p, packet, sizeof(union gtp_packet));
		qmsg->l = len;
		qmsg->timeout = time(NULL) + 60;	/* When to timeout */
		qmsg->retrans = 0;	/* No retransmissions so far */
		qmsg->cbp = NULL;
		qmsg->type = 0;
		qmsg->fd = fd;
		/* No need to add to pdp list here, because even on pdp ctx free
		   we want to leave messages in queue_resp until timeout to
		   detect duplicates */

		/* Rearm timer: Retrans time for qmsg just queued may be required
		   before an existing one (for instance a gtp echo req) */
		gtp_queue_timer_start(gsn);
	}
	return 0;
}

static int gtp_notification(struct gsn_t *gsn, uint8_t version,
		     union gtp_packet *packet, int len,
		     const struct sockaddr_in *peer, int fd, uint16_t seq)
{

	uint8_t ver = GTPHDR_F_GET_VER(packet->flags);
	struct sockaddr_in addr;

	memcpy(&addr, peer, sizeof(addr));

	/* In GTP0 notifications are treated as replies. In GTP1 they
	   are requests for which there is no reply */

	if (fd == gsn->fd1c)
		addr.sin_port = htons(GTP1C_PORT);
	else if (fd == gsn->fd1u)
		addr.sin_port = htons(GTP1C_PORT);

	if (ver == 0) {	/* Version 0 */
		packet->gtp0.h.length = hton16(len - GTP0_HEADER_SIZE);
		packet->gtp0.h.seq = hton16(seq);
	} else if (ver == 1 && (packet->flags & GTP1HDR_F_SEQ)) {	/* Version 1 with seq */
		packet->gtp1l.h.length = hton16(len - GTP1_HEADER_SIZE_SHORT);
		packet->gtp1l.h.seq = hton16(seq);
	} else {
		LOGP(DLGTP, LOGL_ERROR, "Unknown packet flags: 0x%02x\n", packet->flags);
		return -1;
	}

	if (fcntl(fd, F_SETFL, 0)) {
		LOGP(DLGTP, LOGL_ERROR, "fnctl()\n");
		return -1;
	}

	if (sendto(fd, packet, len, 0,
		   (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_SENDTO);
		LOGP(DLGTP, LOGL_ERROR,
			"Sendto(fd=%d, msg=%lx, len=%d) failed: Error = %s\n", fd,
			(unsigned long)&packet, len, strerror(errno));
		return -1;
	}
	return 0;
}

static int gtp_duplicate(struct gsn_t *gsn, uint8_t version,
		  struct sockaddr_in *peer, uint16_t seq)
{
	struct qmsg_t *qmsg;
	char buf[INET_ADDRSTRLEN];

	if (queue_seqget(gsn->queue_resp, &qmsg, peer, seq)) {
		return EOF;	/* Notfound */
	}


	buf[0] = '\0';
	inet_ntop(AF_INET, &peer->sin_addr, buf, sizeof(buf));
	LOGP(DLGTP, LOGL_INFO,
		"Rx duplicate seq=%" PRIu16 " from %s, retrans resp\n", seq, buf);
	rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_DUPLICATE);

	if (fcntl(qmsg->fd, F_SETFL, 0)) {
		LOGP(DLGTP, LOGL_ERROR, "fnctl()\n");
		return -1;
	}

	if (sendto(qmsg->fd, &qmsg->p, qmsg->l, 0,
		   (struct sockaddr *)peer, sizeof(struct sockaddr_in)) < 0) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_SENDTO);
		LOGP(DLGTP, LOGL_ERROR,
			"Sendto(fd=%d, msg=%lx, len=%d) failed: Error = %s\n",
			qmsg->fd, (unsigned long)&qmsg->p, qmsg->l,
			strerror(errno));
	}
	return 0;
}

/* ***********************************************************
 * Path management messages
 * Messages: echo and version not supported.
 * A path is connection between two UDP/IP endpoints
 *
 * A path is either using GTP0 or GTP1. A path can be
 * established by any kind of GTP message??

 * Which source port to use?
 * GTP-C request destination port is 2123/3386
 * GTP-U request destination port is 2152/3386
 * T-PDU destination port is 2152/3386.
 * For the above messages the source port is locally allocated.
 * For response messages src=rx-dst and dst=rx-src.
 * For simplicity we should probably use 2123+2152/3386 as
 * src port even for the cases where src can be locally
 * allocated. This also means that we have to listen only to
 * the same ports.
 * For response messages we need to be able to respond to
 * the relevant src port even if it is locally allocated by
 * the peer.
 *
 * The need for path management!
 * We might need to keep a list of active paths. This might
 * be in the form of remote IP address + UDP port numbers.
 * (We will consider a path astablished if we have a context
 * with the node in question)
 *************************************************************/

/* Send off an echo request */
int gtp_echo_req(struct gsn_t *gsn, int version, void *cbp,
		 struct in_addr *inetaddr)
{
	union gtp_packet packet;
	unsigned int length = get_default_gtp(version, GTP_ECHO_REQ, &packet);
	return gtp_req(gsn, version, NULL, &packet, length, inetaddr, cbp);
}

/* Send off an echo reply */
int gtp_echo_resp(struct gsn_t *gsn, int version,
		  struct sockaddr_in *peer, int fd, void *pack, unsigned len)
{
	union gtp_packet packet;
	unsigned int length = get_default_gtp(version, GTP_ECHO_RSP, &packet);
	gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_RECOVERY,
		  gsn->restart_counter);
	return gtp_resp(version, gsn, NULL, &packet, length, peer, fd,
			get_seq(pack), get_tid(pack));
}

/* Handle a received echo request */
int gtp_echo_ind(struct gsn_t *gsn, int version, struct sockaddr_in *peer,
		 int fd, void *pack, unsigned len)
{

	/* Check if it was a duplicate request */
	if (!gtp_duplicate(gsn, 0, peer, get_seq(pack)))
		return 0;

	/* Send off reply to request */
	return gtp_echo_resp(gsn, version, peer, fd, pack, len);
}

/* Handle a received echo reply */
int gtp_echo_conf(struct gsn_t *gsn, int version, struct sockaddr_in *peer,
		  void *pack, unsigned len)
{
	union gtpie_member *ie[GTPIE_SIZE];
	unsigned char recovery;
	void *cbp = NULL;
	uint8_t type = 0;
	int hlen = get_hlen(pack);

	/* Remove packet from queue */
	if (gtp_conf(gsn, version, peer, pack, len, &type, &cbp))
		return EOF;

	/* Extract information elements into a pointer array */
	if (gtpie_decaps(ie, version, pack + hlen, len - hlen)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_INVALID);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Invalid message format\n");
		if (gsn->cb_conf)
			gsn->cb_conf(type, EOF, NULL, cbp);
		return EOF;
	}

	if (gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Missing mandatory field\n");
		if (gsn->cb_conf)
			gsn->cb_conf(type, EOF, NULL, cbp);
		return EOF;
	}

	/* Echo reply packages does not have a cause information element */
	/* Instead we return the recovery number in the callback function */
	if (gsn->cb_conf)
		gsn->cb_conf(type, recovery, NULL, cbp);

	emit_cb_recovery(gsn, peer, NULL, recovery);

	return 0;
}

/* Send off a Version Not Supported message */
/* This message is somewhat special in that it actually is a
 * response to some other message with unsupported GTP version
 * For this reason it has parameters like a response, and does
 * its own message transmission. No signalling queue is used
 * The reply is sent to the peer IP and peer UDP. This means that
 * the peer will be receiving a GTP0 message on a GTP1 port!
 * In practice however this will never happen as a GTP0 GSN will
 * only listen to the GTP0 port, and therefore will never receive
 * anything else than GTP0 */

int gtp_unsup_req(struct gsn_t *gsn, int version, struct sockaddr_in *peer,
		  int fd, void *pack, unsigned len)
{
	union gtp_packet packet;

	/* GTP 1 is the highest supported protocol */
	unsigned int length = get_default_gtp(1, GTP_NOT_SUPPORTED, &packet);
	return gtp_notification(gsn, version, &packet, length, peer, fd, 0);
}

/* Handle a Version Not Supported message */
int gtp_unsup_ind(struct gsn_t *gsn, struct sockaddr_in *peer,
		  void *pack, unsigned len)
{

	if (gsn->cb_unsup_ind)
		gsn->cb_unsup_ind(peer);

	return 0;
}

/* Send off an Supported Extension Headers Notification */
static int gtp_extheader_req(struct gsn_t *gsn, uint8_t version, struct sockaddr_in *peer,
		      int fd, void *pack, unsigned len)
{
	union gtp_packet packet;
	unsigned int length =
	    get_default_gtp(version, GTP_SUPP_EXT_HEADER, &packet);

	uint8_t pdcp_pdu = GTP_EXT_PDCP_PDU;

	if (version < 1)
		return 0;

	/* We report back that we support only PDCP PDU headers */
	gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_EXT_HEADER_T,
		  sizeof(pdcp_pdu), &pdcp_pdu);

	return gtp_notification(gsn, version, &packet, length,
				peer, fd, get_seq(pack));
}

/* Handle a Supported Extension Headers Notification */
static int gtp_extheader_ind(struct gsn_t *gsn, struct sockaddr_in *peer,
		      void *pack, unsigned len)
{

	if (gsn->cb_extheader_ind)
		gsn->cb_extheader_ind(peer);

	return 0;
}

/* Handle a RAN Information Relay message */
static int gtp_ran_info_relay_ind(struct gsn_t *gsn, int version, struct sockaddr_in *peer,
		      void *pack, unsigned len)
{
	union gtpie_member *ie[GTPIE_SIZE];

	if (version != 1) {
		LOGP(DLGTP, LOGL_NOTICE,
			"RAN Information Relay expected only on GTPCv1: %u\n", version);
		return -EINVAL;
	}

	int hlen = get_hlen(pack);

	/* Decode information elements */
	if (gtpie_decaps(ie, version, pack + hlen, len - hlen)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_INVALID);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Invalid message format (AN Information Relay)\n");
		return -EINVAL;
	}

	if (gsn->cb_ran_info_relay_ind)
		gsn->cb_ran_info_relay_ind(peer, ie);

	return 0;
}

/* Send off a RAN Information Relay message */
int gtp_ran_info_relay_req(struct gsn_t *gsn, const struct sockaddr_in *peer,
			   const uint8_t *ran_container, size_t ran_container_len,
			   const uint8_t *rim_route_addr, size_t rim_route_addr_len,
			   uint8_t rim_route_addr_discr)
{
	union gtp_packet packet;

	/* GTP 1 is the highest supported protocol */
	unsigned int length = get_default_gtp(1, GTP_RAN_INFO_RELAY, &packet);

	gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_RAN_T_CONTAIN, ran_container_len,
		  ran_container);
	if (rim_route_addr) {
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_RIM_ROUT_ADDR,
			  rim_route_addr_len, rim_route_addr);
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_RIM_RA_DISCR, 1,
			  &rim_route_addr_discr);
	}

	return gtp_notification(gsn, 1, &packet, length, peer, gsn->fd1c, 0);
}

/* ***********************************************************
 * Session management messages
 * Messages: create, update and delete PDP context
 *
 * Information storage
 * Information storage for each PDP context is defined in
 * 23.060 section 13.3. Includes IMSI, MSISDN, APN, PDP-type,
 * PDP-address (IP address), sequence numbers, charging ID.
 * For the SGSN it also includes radio related mobility
 * information.
 *************************************************************/

/* API: Send Create PDP Context Request (7.3.1) */
int gtp_create_context_req(struct gsn_t *gsn, struct pdp_t *pdp,
				  void *cbp)
{
	union gtp_packet packet;
	unsigned int length =
	    get_default_gtp(pdp->version, GTP_CREATE_PDP_REQ, &packet);
	struct pdp_t *linked_pdp = NULL;

	/* TODO: Secondary PDP Context Activation Procedure */
	/* In secondary activation procedure the PDP context is identified
	   by tei in the header. The following fields are omitted: Selection
	   mode, IMSI, MSISDN, End User Address, Access Point Name and
	   Protocol Configuration Options */

	if (pdp->secondary) {
		if (gtp_pdp_getgtp1(gsn, &linked_pdp, pdp->teic_own)) {
			LOGP(DLGTP, LOGL_ERROR,
				"Unknown linked PDP context: %u\n", pdp->teic_own);
			return EOF;
		}
	}

	if (pdp->version == 0) {
		gtpie_tv0(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE0,
			  sizeof(pdp->qos_req0), pdp->qos_req0);
	}

	/* Section 7.7.2 */
	if (pdp->version == 1) {
		if (!pdp->secondary)	/* Not Secondary PDP Context Activation Procedure */
			gtpie_tv0(&packet, &length, GTP_MAX, GTPIE_IMSI,
				  sizeof(pdp->imsi), (uint8_t *) & pdp->imsi);
	}

	/* Section 7.7.3 Routing Area Information */
	if (pdp->rai_given == 1)
		gtpie_tv0(&packet, &length, GTP_MAX, GTPIE_RAI,
			  pdp->rai.l, (uint8_t *) & pdp->rai.v);

	/* Section 7.7.11 */
	if (pdp->norecovery_given == 0)
		gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_RECOVERY,
			  gsn->restart_counter);

	/* Section 7.7.12 */
	if (!pdp->secondary)	/* Not Secondary PDP Context Activation Procedure */
		gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_SELECTION_MODE,
			  pdp->selmode);

	if (pdp->version == 0) {
		gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_DI, pdp->fllu);
		gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_C, pdp->fllc);
	}

	/* Section 7.7.13 */
	if (pdp->version == 1) {
		gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_DI,
			  pdp->teid_own);

		/* Section 7.7.14 */
		if (!pdp->teic_confirmed)
			gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_C,
				  pdp->teic_own);

		/* Section 7.7.17 */
		gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_NSAPI, pdp->nsapi);

		/* Section 7.7.17 */
		if (pdp->secondary)	/* Secondary PDP Context Activation Procedure */
			gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_NSAPI,
				  linked_pdp->nsapi);

		/* Section 7.7.23 */
		if (pdp->cch_pdp)	/* Only include charging if flags are set */
			gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_CHARGING_C,
				  pdp->cch_pdp);
	}

	/* TODO
	   gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_TRACE_REF,
	   pdp->traceref);
	   gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_TRACE_TYPE,
	   pdp->tracetype); */

	/* Section 7.7.27 */
	if (!pdp->secondary)	/* Not Secondary PDP Context Activation Procedure */
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_EUA,
			  pdp->eua.l, pdp->eua.v);

	/* Section 7.7.30 */
	if (!pdp->secondary)	/* Not Secondary PDP Context Activation Procedure */
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_APN,
			  pdp->apn_use.l, pdp->apn_use.v);

	/* Section 7.7.31 */
	if (!pdp->secondary)	/* Not Secondary PDP Context Activation Procedure */
		if (pdp->pco_req.l)
			gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_PCO,
				  pdp->pco_req.l, pdp->pco_req.v);

	/* Section 7.7.32 */
	gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR,
		  pdp->gsnlc.l, pdp->gsnlc.v);
	/* Section 7.7.32 */
	gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR,
		  pdp->gsnlu.l, pdp->gsnlu.v);

	/* Section 7.7.33 */
	if (!pdp->secondary)	/* Not Secondary PDP Context Activation Procedure */
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_MSISDN,
			  pdp->msisdn.l, pdp->msisdn.v);

	/* Section 7.7.34 */
	if (pdp->version == 1)
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE,
			  pdp->qos_req.l, pdp->qos_req.v);

	/* Section 7.7.36 */
	if ((pdp->version == 1) && pdp->tft.l)
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_TFT,
			  pdp->tft.l, pdp->tft.v);

	/* Section 7.7.41 */
	if ((pdp->version == 1) && pdp->triggerid.l)
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_TRIGGER_ID,
			  pdp->triggerid.l, pdp->triggerid.v);

	/* Section 7.7.42 */
	if ((pdp->version == 1) && pdp->omcid.l)
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_OMC_ID,
			  pdp->omcid.l, pdp->omcid.v);

	/* new R7 fields */
	if (pdp->rattype_given == 1)
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_RAT_TYPE,
			  pdp->rattype.l, pdp->rattype.v);

	if (pdp->userloc_given == 1)
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_USER_LOC,
			  pdp->userloc.l, pdp->userloc.v);

	if (pdp->mstz_given == 1)
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_MS_TZ,
			  pdp->mstz.l, pdp->mstz.v);

	if (pdp->imeisv_given == 1)
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_IMEI_SV,
			  pdp->imeisv.l, pdp->imeisv.v);

	/* TODO hisaddr0 */
	gtp_req(gsn, pdp->version, pdp, &packet, length, &pdp->hisaddr0, cbp);

	return 0;
}

/* API: Application response to context indication */
int gtp_create_context_resp(struct gsn_t *gsn, struct pdp_t *pdp, int cause)
{

	/* Now send off a reply to the peer */
	gtp_create_pdp_resp(gsn, pdp->version, pdp, cause);

	if (cause != GTPCAUSE_ACC_REQ)
		gtp_freepdp(gsn, pdp);

	return 0;
}

/* Send Create PDP Context Response */
int gtp_create_pdp_resp(struct gsn_t *gsn, int version, struct pdp_t *pdp,
			uint8_t cause)
{
	union gtp_packet packet;
	unsigned int length =
	    get_default_gtp(version, GTP_CREATE_PDP_RSP, &packet);

	gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_CAUSE, cause);

	if (cause == GTPCAUSE_ACC_REQ) {

		if (version == 0)
			gtpie_tv0(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE0,
				  sizeof(pdp->qos_neg0), pdp->qos_neg0);

		gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_REORDER,
			  pdp->reorder);
		gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_RECOVERY,
			  gsn->restart_counter);

		if (version == 0) {
			gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_DI,
				  pdp->fllu);
			gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_C,
				  pdp->fllc);
		}

		if (version == 1) {
			gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_DI,
				  pdp->teid_own);
			gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_C,
				  pdp->teic_own);
		}

		/* TODO: We use teic_own as charging ID */
		gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_CHARGING_ID,
			  pdp->teic_own);

		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_EUA,
			  pdp->eua.l, pdp->eua.v);

		if (pdp->pco_neg.l) {	/* Optional PCO */
			gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_PCO,
				  pdp->pco_neg.l, pdp->pco_neg.v);
		}

		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR,
			  pdp->gsnlc.l, pdp->gsnlc.v);
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR,
			  pdp->gsnlu.l, pdp->gsnlu.v);

		if (version == 1)
			gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE,
				  pdp->qos_neg.l, pdp->qos_neg.v);

		/* TODO: Charging gateway address */
	}

	return gtp_resp(version, gsn, pdp, &packet, length, &pdp->sa_peer,
			pdp->fd, pdp->seq, pdp->tid);
}

/* Handle Create PDP Context Request */
int gtp_create_pdp_ind(struct gsn_t *gsn, int version,
		       struct sockaddr_in *peer, int fd,
		       void *pack, unsigned len)
{
	struct pdp_t *pdp, *pdp_old;
	struct pdp_t pdp_buf;
	union gtpie_member *ie[GTPIE_SIZE];
	uint8_t recovery;
	bool recovery_recvd = false;
	int rc;

	uint16_t seq = get_seq(pack);
	int hlen = get_hlen(pack);
	uint8_t linked_nsapi = 0;
	struct pdp_t *linked_pdp = NULL;

	if (!gtp_duplicate(gsn, version, peer, seq))
		return 0;

	pdp = &pdp_buf;
	memset(pdp, 0, sizeof(struct pdp_t));

	if (version == 0)
		pdp_set_imsi_nsapi(pdp, get_tid(pack));

	pdp->seq = seq;
	pdp->sa_peer = *peer;
	pdp->fd = fd;
	pdp->version = version;

	/* Decode information elements */
	if (gtpie_decaps(ie, version, pack + hlen, len - hlen)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_INVALID);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Invalid message format\n");
		if (0 == version)
			return EOF;
		else
			return gtp_create_pdp_resp(gsn, version, pdp,
						   GTPCAUSE_INVALID_MESSAGE);
	}

	switch (version) {
	case 1:
		/* Linked NSAPI (conditional) */
		/* If included this is the Secondary PDP Context Activation Procedure */
		/* In secondary activation IMSI is not included, so the context must be */
		/* identified by the tei */
		if (!gtpie_gettv1(ie, GTPIE_NSAPI, 1, &linked_nsapi)) {

			/* Find the primary PDP context */
			if (gtp_pdp_getgtp1(gsn, &linked_pdp, get_tei(pack))) {
				rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_INCORRECT);
				GTP_LOGPKG(LOGL_ERROR, peer,
					    pack, len,
					    "Incorrect optional information field\n");
				return gtp_create_pdp_resp(gsn, version, pdp,
							   GTPCAUSE_OPT_IE_INCORRECT);
			}

			/* Check that the primary PDP context matches linked nsapi */
			if (linked_pdp->nsapi != linked_nsapi) {
				rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_INCORRECT);
				GTP_LOGPKG(LOGL_ERROR, peer,
					    pack, len,
					    "Incorrect optional information field\n");
				return gtp_create_pdp_resp(gsn, version, pdp,
							   GTPCAUSE_OPT_IE_INCORRECT);
			}

			/* Copy parameters from primary context */
			pdp->selmode = linked_pdp->selmode;
			pdp->imsi = linked_pdp->imsi;
			pdp->msisdn = linked_pdp->msisdn;
			pdp->eua = linked_pdp->eua;
			pdp->pco_req = linked_pdp->pco_req;
			pdp->apn_req = linked_pdp->apn_req;
			pdp->teic_gn = linked_pdp->teic_gn;
			pdp->secondary = 1;
		} else {
			/* Not Secondary PDP Context Activation Procedure */
			/* IMSI (conditional): If the MS is emergency attached
			   and the MS is UICCless, the IMSI cannot be included
			   in the message and therefore IMSI shall not be
			   included in the message. */
			if (gtpie_gettv0
			    (ie, GTPIE_IMSI, 0, &pdp->imsi, sizeof(pdp->imsi))) {
				rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
				GTP_LOGPKG(LOGL_ERROR, peer, pack,
					    len, "Missing IMSI not supported\n");
				return gtp_create_pdp_resp(gsn, version, pdp,
							   GTPCAUSE_MAN_IE_MISSING);
			}
		}

		/* TEID (mandatory) */
		if (gtpie_gettv4(ie, GTPIE_TEI_DI, 0, &pdp->teid_gn)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			return gtp_create_pdp_resp(gsn, version, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}
		/* TEIC (conditional) */
		if (!linked_pdp) {	/* Not Secondary PDP Context Activation Procedure */
			if (gtpie_gettv4(ie, GTPIE_TEI_C, 0, &pdp->teic_gn)) {
				rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
				GTP_LOGPKG(LOGL_ERROR, peer,
					    pack, len,
					    "Missing mandatory information field\n");
				return gtp_create_pdp_resp(gsn, version, pdp,
							   GTPCAUSE_MAN_IE_MISSING);
			}
		}
		/* NSAPI (mandatory) */
		if (gtpie_gettv1(ie, GTPIE_NSAPI, 0, &pdp->nsapi)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			return gtp_create_pdp_resp(gsn, version, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}
		/* QoS (mandatory) */
		if (gtpie_gettlv(ie, GTPIE_QOS_PROFILE, 0, &pdp->qos_req.l,
				 &pdp->qos_req.v, sizeof(pdp->qos_req.v))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			return gtp_create_pdp_resp(gsn, version, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}
		/* TFT (conditional) */
		if (gtpie_gettlv(ie, GTPIE_TFT, 0, &pdp->tft.l,
				 &pdp->tft.v, sizeof(pdp->tft.v))) {
		}
		break; /* version 1 */

	case 0:
		if (gtpie_gettv0(ie, GTPIE_QOS_PROFILE0, 0,
				 pdp->qos_req0, sizeof(pdp->qos_req0))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			return gtp_create_pdp_resp(gsn, version, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}
		if (gtpie_gettv2(ie, GTPIE_FL_DI, 0, &pdp->flru)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			return gtp_create_pdp_resp(gsn, version, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}
		if (gtpie_gettv2(ie, GTPIE_FL_C, 0, &pdp->flrc)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			return gtp_create_pdp_resp(gsn, version, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}
		break;
	}

	/* SGSN address for signalling (mandatory) */
	if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 0, &pdp->gsnrc.l,
			 &pdp->gsnrc.v, sizeof(pdp->gsnrc.v))) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Missing mandatory information field\n");
		return gtp_create_pdp_resp(gsn, version, pdp,
					   GTPCAUSE_MAN_IE_MISSING);
	}

	/* SGSN address for user traffic (mandatory) */
	if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 1, &pdp->gsnru.l,
			 &pdp->gsnru.v, sizeof(pdp->gsnru.v))) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Missing mandatory information field\n");
		return gtp_create_pdp_resp(gsn, version, pdp,
					   GTPCAUSE_MAN_IE_MISSING);
	}
	/* Recovery (optional) */
	if (!gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
		/* we use recovery futher down after announcing new pdp ctx to user */
		recovery_recvd = true;
	}

	if (!linked_pdp) {	/* Not Secondary PDP Context Activation Procedure */
		/* Selection mode (conditional) */
		if (gtpie_gettv0(ie, GTPIE_SELECTION_MODE, 0,
				 &pdp->selmode, sizeof(pdp->selmode))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			return gtp_create_pdp_resp(gsn, version, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}
		/* End User Address (conditional) */
		if (gtpie_gettlv(ie, GTPIE_EUA, 0, &pdp->eua.l,
				 &pdp->eua.v, sizeof(pdp->eua.v))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			return gtp_create_pdp_resp(gsn, version, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}
		/* APN */
		if (gtpie_gettlv(ie, GTPIE_APN, 0, &pdp->apn_req.l,
				 &pdp->apn_req.v, sizeof(pdp->apn_req.v))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			return gtp_create_pdp_resp(gsn, version, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}
		/* Extract protocol configuration options (optional) */
		if (!gtpie_gettlv(ie, GTPIE_PCO, 0, &pdp->pco_req.l,
				  &pdp->pco_req.v, sizeof(pdp->pco_req.v))) {
		}
		/* MSISDN (conditional) */
		if (gtpie_gettlv(ie, GTPIE_MSISDN, 0, &pdp->msisdn.l,
				 &pdp->msisdn.v, sizeof(pdp->msisdn.v))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			return gtp_create_pdp_resp(gsn, version, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}
	}

	/* Initialize our own IP addresses */
	in_addr2gsna(&pdp->gsnlc, &gsn->gsnc);
	in_addr2gsna(&pdp->gsnlu, &gsn->gsnu);

	if (!gtp_pdp_getimsi(gsn, &pdp_old, pdp->imsi, pdp->nsapi)) {
		/* Found old pdp with same tid. Now the voodoo begins! */
		/* 09.60 / 29.060 allows create on existing context to "steal" */
		/* the context which was allready established */
		/* We check that the APN, selection mode and MSISDN is the same */
		DEBUGP(DLGTP, "gtp_create_pdp_ind: Old context found\n");
		if ((pdp->apn_req.l == pdp_old->apn_req.l)
		    &&
		    (!memcmp
		     (pdp->apn_req.v, pdp_old->apn_req.v, pdp->apn_req.l))
		    && (pdp->selmode == pdp_old->selmode)
		    && (pdp->msisdn.l == pdp_old->msisdn.l)
		    &&
		    (!memcmp(pdp->msisdn.v, pdp_old->msisdn.v, pdp->msisdn.l)))
		{
			/* OK! We are dealing with the same APN. We will copy new
			 * parameters to the old pdp and send off confirmation
			 * We ignore the following information elements:
			 * QoS: MS will get originally negotiated QoS.
			 * End user address (EUA). MS will get old EUA anyway.
			 * Protocol configuration option (PCO): Only application can verify */
			DEBUGP(DLGTP, "gtp_create_pdp_ind: Reusing old context\n");

			/* Copy remote flow label */
			pdp_old->flru = pdp->flru;
			pdp_old->flrc = pdp->flrc;

			/* Copy remote tei */
			pdp_old->teid_gn = pdp->teid_gn;
			pdp_old->teic_gn = pdp->teic_gn;

			/* Copy peer GSN address */
			pdp_old->gsnrc.l = pdp->gsnrc.l;
			memcpy(&pdp_old->gsnrc.v, &pdp->gsnrc.v, pdp->gsnrc.l);
			pdp_old->gsnru.l = pdp->gsnru.l;
			memcpy(&pdp_old->gsnru.v, &pdp->gsnru.v, pdp->gsnru.l);

			/* Copy request parameters */
			pdp_old->seq = pdp->seq;
			pdp_old->sa_peer = pdp->sa_peer;
			pdp_old->fd = pdp->fd = fd;
			pdp_old->version = pdp->version = version;

			/* Switch to using the old pdp context */
			pdp = pdp_old;

			if (recovery_recvd)
				emit_cb_recovery(gsn, peer, pdp, recovery);

			/* Confirm to peer that things were "successful" */
			return gtp_create_pdp_resp(gsn, version, pdp,
						   GTPCAUSE_ACC_REQ);
		} else {	/* This is not the same PDP context. Delete the old one. */

			DEBUGP(DLGTP, "gtp_create_pdp_ind: Deleting old context\n");

			gtp_freepdp(gsn, pdp_old);

			DEBUGP(DLGTP, "gtp_create_pdp_ind: Deleted...\n");
		}
	}

	rc = gtp_pdp_newpdp(gsn, &pdp, pdp->imsi, pdp->nsapi, pdp);
	if (rc != 0) {
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			   "Failed creating a new PDP context, array full (%u)\n", PDP_MAX);
		/* &pdp in gtp_pdp_newpdp is untouched if it failed: */
		rc = gtp_create_pdp_resp(gsn, version, pdp, GTPCAUSE_NO_MEMORY);
		/* Don't pass it to emit_cb_recovery, since allocation failed and it was already rejected: */
		pdp = NULL;
		goto recover_ret;
	}

	/* Callback function to validate login */
	if (gsn->cb_create_context_ind != 0)
		rc = gsn->cb_create_context_ind(pdp);
	else {
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "No create_context_ind callback defined\n");
		rc = gtp_create_pdp_resp(gsn, version, pdp,
					   GTPCAUSE_NOT_SUPPORTED);
	}

recover_ret:
	if (recovery_recvd)
		emit_cb_recovery(gsn, peer, pdp, recovery);
	return rc;
}

/* Handle Create PDP Context Response */
int gtp_create_pdp_conf(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, void *pack, unsigned len)
{
	struct pdp_t *pdp;
	union gtpie_member *ie[GTPIE_SIZE];
	uint8_t cause, recovery;
	void *cbp = NULL;
	uint8_t type = 0;
	int hlen = get_hlen(pack);

	/* Remove packet from queue */
	if (gtp_conf(gsn, version, peer, pack, len, &type, &cbp))
		return EOF;

	/* Find the context in question */
	if (gtp_pdp_getgtp1(gsn, &pdp, get_tei(pack))) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNKNOWN_PDP);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Unknown PDP context: %u\n", get_tei(pack));
		if (gsn->cb_conf)
			gsn->cb_conf(type, EOF, NULL, cbp);
		return EOF;
	}

	/* Decode information elements */
	if (gtpie_decaps(ie, version, pack + hlen, len - hlen)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_INVALID);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Invalid message format\n");
		if (gsn->cb_conf)
			gsn->cb_conf(type, EOF, pdp, cbp);
		return EOF;
	}

	/* Extract cause value (mandatory) */
	if (gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Missing mandatory information field\n");
		if (gsn->cb_conf)
			gsn->cb_conf(type, EOF, pdp, cbp);
		return EOF;
	}

	/* Extract recovery (optional) */
	if (!gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
		emit_cb_recovery(gsn, peer, pdp, recovery);
	}

	/* Extract protocol configuration options (optional) */
	if (!gtpie_gettlv(ie, GTPIE_PCO, 0, &pdp->pco_req.l,
			  &pdp->pco_req.v, sizeof(pdp->pco_req.v))) {
	}

	/* Check all conditional information elements */
	if (GTPCAUSE_ACC_REQ == cause) {

		if (version == 0) {
			if (gtpie_gettv0(ie, GTPIE_QOS_PROFILE0, 0,
					 &pdp->qos_neg0,
					 sizeof(pdp->qos_neg0))) {
				rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
				GTP_LOGPKG(LOGL_ERROR, peer,
					    pack, len,
					    "Missing conditional information field\n");
				if (gsn->cb_conf)
					gsn->cb_conf(type, EOF, pdp, cbp);
				return EOF;
			}
		}

		if (gtpie_gettv1(ie, GTPIE_REORDER, 0, &pdp->reorder)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len,
				    "Missing conditional information field\n");
			if (gsn->cb_conf)
				gsn->cb_conf(type, EOF, pdp, cbp);
			return EOF;
		}

		if (version == 0) {
			if (gtpie_gettv2(ie, GTPIE_FL_DI, 0, &pdp->flru)) {
				rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
				GTP_LOGPKG(LOGL_ERROR, peer,
					    pack, len,
					    "Missing conditional information field\n");
				if (gsn->cb_conf)
					gsn->cb_conf(type, EOF, pdp, cbp);
				return EOF;
			}

			if (gtpie_gettv2(ie, GTPIE_FL_C, 0, &pdp->flrc)) {
				rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
				GTP_LOGPKG(LOGL_ERROR, peer,
					    pack, len,
					    "Missing conditional information field\n");
				if (gsn->cb_conf)
					gsn->cb_conf(type, EOF, pdp, cbp);
				return EOF;
			}
		}

		if (version == 1) {
			if (gtpie_gettv4(ie, GTPIE_TEI_DI, 0, &pdp->teid_gn)) {
				rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
				GTP_LOGPKG(LOGL_ERROR, peer,
					    pack, len,
					    "Missing conditional information field\n");
				if (gsn->cb_conf)
					gsn->cb_conf(type, EOF, pdp, cbp);
				return EOF;
			}

			if (gtpie_gettv4(ie, GTPIE_TEI_C, 0, &pdp->teic_gn)) {
				rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
				GTP_LOGPKG(LOGL_ERROR, peer,
					    pack, len,
					    "Missing conditional information field\n");
				if (gsn->cb_conf)
					gsn->cb_conf(type, EOF, pdp, cbp);
				return EOF;
			}
			/* Register that we have received a valid teic from GGSN */
			pdp->teic_confirmed = 1;
		}

		if (gtpie_gettv4(ie, GTPIE_CHARGING_ID, 0, &pdp->cid)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len,
				    "Missing conditional information field\n");
			if (gsn->cb_conf)
				gsn->cb_conf(type, EOF, pdp, cbp);
		}

		if (gtpie_gettlv(ie, GTPIE_EUA, 0, &pdp->eua.l,
				 &pdp->eua.v, sizeof(pdp->eua.v))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len,
				    "Missing conditional information field\n");
			if (gsn->cb_conf)
				gsn->cb_conf(type, EOF, pdp, cbp);
			return EOF;
		}

		if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 0, &pdp->gsnrc.l,
				 &pdp->gsnrc.v, sizeof(pdp->gsnrc.v))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len,
				    "Missing conditional information field\n");
			if (gsn->cb_conf)
				gsn->cb_conf(type, EOF, pdp, cbp);
			return EOF;
		}

		if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 1, &pdp->gsnru.l,
				 &pdp->gsnru.v, sizeof(pdp->gsnru.v))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len,
				    "Missing conditional information field\n");
			if (gsn->cb_conf)
				gsn->cb_conf(type, EOF, pdp, cbp);
			return EOF;
		}

		if (version == 1) {
			if (gtpie_gettlv
			    (ie, GTPIE_QOS_PROFILE, 0, &pdp->qos_neg.l,
			     &pdp->qos_neg.v, sizeof(pdp->qos_neg.v))) {
				rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
				GTP_LOGPKG(LOGL_ERROR, peer,
					    pack, len,
					    "Missing conditional information field\n");
				if (gsn->cb_conf)
					gsn->cb_conf(type, EOF, pdp, cbp);
				return EOF;
			}
		}

	}

	if (gsn->cb_conf)
		gsn->cb_conf(type, cause, pdp, cbp);

	return 0;
}

/* API: Send Update PDP Context Request */
int gtp_update_context(struct gsn_t *gsn, struct pdp_t *pdp, void *cbp,
		       struct in_addr *inetaddr)
{
	union gtp_packet packet;
	unsigned int length =
	    get_default_gtp(pdp->version, GTP_UPDATE_PDP_REQ, &packet);

	if (pdp->version == 0)
		gtpie_tv0(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE0,
			  sizeof(pdp->qos_req0), pdp->qos_req0);

	/* Include IMSI if updating with unknown teic_gn */
	if ((pdp->version == 1) && (!pdp->teic_gn))
		gtpie_tv0(&packet, &length, GTP_MAX, GTPIE_IMSI,
			  sizeof(pdp->imsi), (uint8_t *) & pdp->imsi);

	gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_RECOVERY,
		  gsn->restart_counter);

	if (pdp->version == 0) {
		gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_DI, pdp->fllu);
		gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_C, pdp->fllc);
	}

	if (pdp->version == 1) {
		gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_DI,
			  pdp->teid_own);

		if (!pdp->teic_confirmed)
			gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_C,
				  pdp->teic_own);
	}

	gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_NSAPI, pdp->nsapi);

	/* TODO
	   gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_TRACE_REF,
	   pdp->traceref);
	   gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_TRACE_TYPE,
	   pdp->tracetype); */

	/* TODO if ggsn update message
	   gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_EUA,
	   pdp->eua.l, pdp->eua.v);
	 */

	gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR,
		  pdp->gsnlc.l, pdp->gsnlc.v);
	gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR,
		  pdp->gsnlu.l, pdp->gsnlu.v);

	if (pdp->version == 1)
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE,
			  pdp->qos_req.l, pdp->qos_req.v);

	if ((pdp->version == 1) && pdp->tft.l)
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_TFT,
			  pdp->tft.l, pdp->tft.v);

	if ((pdp->version == 1) && pdp->triggerid.l)
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_TRIGGER_ID,
			  pdp->triggerid.l, pdp->triggerid.v);

	if ((pdp->version == 1) && pdp->omcid.l)
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_OMC_ID,
			  pdp->omcid.l, pdp->omcid.v);

	gtp_req(gsn, pdp->version, pdp, &packet, length, inetaddr, cbp);

	return 0;
}

/* Send Update PDP Context Response */
static int gtp_update_pdp_resp(struct gsn_t *gsn, uint8_t version,
			struct sockaddr_in *peer, int fd,
			void *pack, unsigned len,
			struct pdp_t *pdp, uint8_t cause)
{

	union gtp_packet packet;
	unsigned int length =
	    get_default_gtp(version, GTP_UPDATE_PDP_RSP, &packet);

	gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_CAUSE, cause);

	if (cause == GTPCAUSE_ACC_REQ) {

		if (version == 0)
			gtpie_tv0(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE0,
				  sizeof(pdp->qos_neg0), pdp->qos_neg0);

		gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_RECOVERY,
			  gsn->restart_counter);

		if (version == 0) {
			gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_DI,
				  pdp->fllu);
			gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_C,
				  pdp->fllc);
		}

		if (version == 1) {
			gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_DI,
				  pdp->teid_own);

			if (!pdp->teic_confirmed)
				gtpie_tv4(&packet, &length, GTP_MAX,
					  GTPIE_TEI_C, pdp->teic_own);
		}

		/* TODO we use teid_own as charging ID address */
		gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_CHARGING_ID,
			  pdp->teid_own);

		/* If ggsn
		   gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_EUA,
		   pdp->eua.l, pdp->eua.v); */

		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR,
			  pdp->gsnlc.l, pdp->gsnlc.v);
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR,
			  pdp->gsnlu.l, pdp->gsnlu.v);

		if (version == 1)
			gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE,
				  pdp->qos_neg.l, pdp->qos_neg.v);

		/* TODO: Charging gateway address */
	}

	return gtp_resp(version, gsn, pdp, &packet, length, peer,
			fd, get_seq(pack), get_tid(pack));
}

/* Handle Update PDP Context Request */
static int gtp_update_pdp_ind(struct gsn_t *gsn, uint8_t version,
		       struct sockaddr_in *peer, int fd,
		       void *pack, unsigned len)
{
	struct pdp_t *pdp;
	struct pdp_t pdp_backup;
	union gtpie_member *ie[GTPIE_SIZE];
	uint8_t recovery;

	uint16_t seq = get_seq(pack);
	int hlen = get_hlen(pack);

	uint64_t imsi;
	uint8_t nsapi;

	/* Is this a duplicate ? */
	if (!gtp_duplicate(gsn, version, peer, seq)) {
		return 0;	/* We allready send of response once */
	}

	/* Decode information elements */
	if (gtpie_decaps(ie, version, pack + hlen, len - hlen)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_INVALID);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Invalid message format\n");
		if (0 == version)
			return EOF;
		else
			return gtp_update_pdp_resp(gsn, version, peer, fd, pack,
						   len, NULL,
						   GTPCAUSE_INVALID_MESSAGE);
	}

	/* Finding PDP: */
	/* For GTP0 we use the tunnel identifier to provide imsi and nsapi. */
	/* For GTP1 we must use imsi and nsapi if imsi is present. Otherwise */
	/* we have to use the tunnel endpoint identifier */
	if (version == 0) {
		/* Find the context in question */
		if (gtp_pdp_tidget(gsn, &pdp, get_tid(pack))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNKNOWN_PDP);
			GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
				   "Unknown PDP context: TID=0x%" PRIx64 "\n",
				   get_tid(pack));
			return gtp_update_pdp_resp(gsn, version, peer, fd, pack,
						   len, NULL,
						   GTPCAUSE_NON_EXIST);
		}

		/* Update IMSI and NSAPI */
		pdp_set_imsi_nsapi(pdp, get_tid(pack));
	} else if (version == 1) {
		/* NSAPI (mandatory) */
		if (gtpie_gettv1(ie, GTPIE_NSAPI, 0, &nsapi)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			return gtp_update_pdp_resp(gsn, version, peer, fd, pack,
						   len, NULL,
						   GTPCAUSE_MAN_IE_MISSING);
		}

		/* IMSI (conditional) */
		if (gtpie_gettv0(ie, GTPIE_IMSI, 0, &imsi, sizeof(imsi))) {
			/* Find the context in question */
			if (gtp_pdp_getgtp1(gsn, &pdp, get_tei(pack))) {
				rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNKNOWN_PDP);
				GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
					   "Unknown PDP context: TEI=0x%" PRIx32 "\n",
					   get_tei(pack));
				return gtp_update_pdp_resp(gsn, version, peer,
							   fd, pack, len, NULL,
							   GTPCAUSE_NON_EXIST);
			}
		} else {
			/* Find the context in question */
			if (gtp_pdp_getimsi(gsn, &pdp, imsi, nsapi)) {
				rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNKNOWN_PDP);
				GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
					   "Unknown PDP context: IMSI=0x%" PRIx64
					   " NSAPI=%" PRIu8 "\n", imsi, nsapi);
				return gtp_update_pdp_resp(gsn, version, peer,
							   fd, pack, len, NULL,
							   GTPCAUSE_NON_EXIST);
			}
		}
	} else {
		LOGP(DLGTP, LOGL_ERROR, "Unknown version: %d\n", version);
		return EOF;
	}

	/* Make a backup copy in case anything is wrong */
	memcpy(&pdp_backup, pdp, sizeof(pdp_backup));

	if (version == 0) {
		if (gtpie_gettv0(ie, GTPIE_QOS_PROFILE0, 0,
				 pdp->qos_req0, sizeof(pdp->qos_req0))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
			return gtp_update_pdp_resp(gsn, version, peer, fd, pack,
						   len, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}
	}

	/* Recovery (optional) */
	if (!gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
		emit_cb_recovery(gsn, peer, pdp, recovery);
	}

	if (version == 0) {
		if (gtpie_gettv2(ie, GTPIE_FL_DI, 0, &pdp->flru)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
			return gtp_update_pdp_resp(gsn, version, peer, fd, pack,
						   len, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}

		if (gtpie_gettv2(ie, GTPIE_FL_C, 0, &pdp->flrc)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
			return gtp_update_pdp_resp(gsn, version, peer, fd, pack,
						   len, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}
	}

	if (version == 1) {
		/* TEID (mandatory) */
		if (gtpie_gettv4(ie, GTPIE_TEI_DI, 0, &pdp->teid_gn)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
			return gtp_update_pdp_resp(gsn, version, peer, fd, pack,
						   len, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}

		/* TEIC (conditional) */
		/* If TEIC is not included it means that we have allready received it */
		/* TODO: From 29.060 it is not clear if TEI_C MUST be included for */
		/* all updated contexts, or only for one of the linked contexts */
		gtpie_gettv4(ie, GTPIE_TEI_C, 0, &pdp->teic_gn);

		/* NSAPI (mandatory) */
		if (gtpie_gettv1(ie, GTPIE_NSAPI, 0, &pdp->nsapi)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
			return gtp_update_pdp_resp(gsn, version, peer, fd, pack,
						   len, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}
	}

	/* Trace reference (optional) */
	/* Trace type (optional) */

	/* End User Address (conditional) TODO: GGSN Initiated
	   if (gtpie_gettlv(ie, GTPIE_EUA, 0, &pdp->eua.l,
	   &pdp->eua.v, sizeof(pdp->eua.v))) {
	   rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
	   GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
	   "Missing mandatory information field");
	   memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
	   return gtp_update_pdp_resp(gsn, version, pdp,
	   GTPCAUSE_MAN_IE_MISSING);
	   } */

	/* SGSN address for signalling (mandatory) */
	/* It is weird that this is mandatory when TEIC is conditional */
	if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 0, &pdp->gsnrc.l,
			 &pdp->gsnrc.v, sizeof(pdp->gsnrc.v))) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Missing mandatory information field\n");
		memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
		return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len,
					   pdp, GTPCAUSE_MAN_IE_MISSING);
	}

	/* SGSN address for user traffic (mandatory) */
	if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 1, &pdp->gsnru.l,
			 &pdp->gsnru.v, sizeof(pdp->gsnru.v))) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Missing mandatory information field\n");
		memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
		return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len,
					   pdp, GTPCAUSE_MAN_IE_MISSING);
	}

	if (version == 1) {
		/* QoS (mandatory) */
		if (gtpie_gettlv(ie, GTPIE_QOS_PROFILE, 0, &pdp->qos_req.l,
				 &pdp->qos_req.v, sizeof(pdp->qos_req.v))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				    len, "Missing mandatory information field\n");
			memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
			return gtp_update_pdp_resp(gsn, version, peer, fd, pack,
						   len, pdp,
						   GTPCAUSE_MAN_IE_MISSING);
		}

		/* TFT (conditional) */
		if (gtpie_gettlv(ie, GTPIE_TFT, 0, &pdp->tft.l,
				 &pdp->tft.v, sizeof(pdp->tft.v))) {
		}

		/* OMC identity */
	}

	/* Confirm to peer that things were "successful" */
	return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len, pdp,
				   GTPCAUSE_ACC_REQ);
}

/* Handle Update PDP Context Response */
static int gtp_update_pdp_conf(struct gsn_t *gsn, uint8_t version,
			struct sockaddr_in *peer, void *pack, unsigned len)
{
	struct pdp_t *pdp = NULL;
	union gtpie_member *ie[GTPIE_SIZE];
	uint8_t cause = EOF;
	uint8_t recovery;
	int rc = 0;
	void *cbp = NULL;
	uint8_t type = 0;
	bool trigger_recovery = false;
	int hlen = get_hlen(pack);

	/* Remove packet from queue */
	if (gtp_conf(gsn, 0, peer, pack, len, &type, &cbp))
		return EOF;

	/* Decode information elements */
	if (gtpie_decaps(ie, version, pack + hlen, len - hlen)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_INVALID);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Invalid message format\n");
		goto err_out;
	}

	/* Extract recovery (optional) */
	if (!gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery))
		trigger_recovery = true;

	/* Extract cause value (mandatory) */
	if (gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause)) {
		goto err_missing;
	}

	/*  3GPP TS 29.060 sec 8.2: "Receiving node shall send back to the source
	 *  of the message, a response with the appropriate cause value (either
	 *  "Non-existent" or "Context not found"). The Tunnel Endpoint
	 *  Identifier used in the response message shall be set to all zeroes."
	 *  Hence, TEID=0 in this scenario, it makes no sense to infer PDP ctx
	 *  from it. User is responsible to infer it from cbp */
	if (cause != GTPCAUSE_NON_EXIST && cause != GTPCAUSE_CONTEXT_NOT_FOUND) {
		/* Find the context in question */
		if (gtp_pdp_getgtp1(gsn, &pdp, get_tei(pack))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNKNOWN_PDP);
			GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
				   "Unknown PDP context: TEI=0x%" PRIx32 "\n", get_tei(pack));
			goto err_out;
		}
	}

	/* Check all conditional information elements */
	/* TODO: This does not handle GGSN-initiated update responses */
	if (cause == GTPCAUSE_ACC_REQ) {
		if (version == 0) {
			if (gtpie_gettv0(ie, GTPIE_QOS_PROFILE0, 0,
					 &pdp->qos_neg0,
					 sizeof(pdp->qos_neg0))) {
				goto err_missing;
			}

			if (gtpie_gettv2(ie, GTPIE_FL_DI, 0, &pdp->flru)) {
				goto err_missing;
			}

			if (gtpie_gettv2(ie, GTPIE_FL_C, 0, &pdp->flrc)) {
				goto err_missing;
			}
		}

		if (version == 1) {
			if (gtpie_gettv4(ie, GTPIE_TEI_DI, 0, &pdp->teid_gn)) {
				goto err_missing;
			}

			if (gtpie_gettv4(ie, GTPIE_TEI_C, 0, &pdp->teic_gn)) {
				goto err_missing;
			}
			/* Register that we have received a valid teic from GGSN */
			pdp->teic_confirmed = 1;
		}

		if (gtpie_gettv4(ie, GTPIE_CHARGING_ID, 0, &pdp->cid)) {
			goto err_missing;
		}

		if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 0, &pdp->gsnrc.l,
				 &pdp->gsnrc.v, sizeof(pdp->gsnrc.v))) {
			goto err_missing;
		}

		if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 1, &pdp->gsnru.l,
				 &pdp->gsnru.v, sizeof(pdp->gsnru.v))) {
			goto err_missing;
		}

		if (version == 1) {
			if (gtpie_gettlv
			    (ie, GTPIE_QOS_PROFILE, 0, &pdp->qos_neg.l,
			     &pdp->qos_neg.v, sizeof(pdp->qos_neg.v))) {
				goto err_missing;
			}
		}
	}

generic_ret:
	if (trigger_recovery)
		emit_cb_recovery(gsn, peer, pdp, recovery);
	if (gsn->cb_conf)
		gsn->cb_conf(type, cause, pdp, cbp);
	return rc;	/* Succes */

err_missing:
	rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
	GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
		    "Missing information field\n");
err_out:
	rc = EOF;
	goto generic_ret;
}

/* API: Deprecated. Send Delete PDP Context Request And free pdp ctx. */
int gtp_delete_context_req(struct gsn_t *gsn, struct pdp_t *pdp, void *cbp,
			   int teardown)
{
	struct pdp_t *linked_pdp;

	if (gtp_pdp_getgtp1(gsn, &linked_pdp, pdp->teic_own)) {
		LOGP(DLGTP, LOGL_ERROR,
			"Unknown linked PDP context: %u\n", pdp->teic_own);
		return EOF;
	}

	if (gtp_delete_context_req2(gsn, pdp, cbp, teardown) == EOF)
		return EOF;

	if (teardown) {		/* Remove all contexts */
		gtp_freepdp_teardown(gsn, linked_pdp);
	} else {
		/* If we end up here (no teardown) it means we still
		   have at least another pdp context active for this
		   PDN connection (since last DeleteReq should come
		   with teardown enabled). If the ctx to delete is a
		   secondary ctx, simply free it. If it's the primary
		   ctx, mark it as nodata but don't free it since we
		   need it to hold data linked together and we'll
		   require it later to tear down the entire tree. Still,
		   we announce its deletion through cb_delete_context
		   because we don't want user to release its related
		   data and not use it anymore.
		 */
		if (pdp == linked_pdp) {
			if (gsn->cb_delete_context)
				gsn->cb_delete_context(pdp);
			pdp->secondary_tei[pdp->nsapi & 0xf0] = 0;
			pdp->nodata = 1;
		} else {
			gtp_freepdp(gsn, pdp);
		}
	}

	return 0;
}

/* API: Send Delete PDP Context Request. PDP CTX shall be free'd by user at any
   point in time later than this function through a call to pdp_freepdp(pdp) (or
   through gtp_freepdp() if willing to receive cb_delete_context() callback),
   but it must be freed no later than during cb_conf(GTP_DELETE_PDP_REQ, pdp) */
int gtp_delete_context_req2(struct gsn_t *gsn, struct pdp_t *pdp, void *cbp,
			   int teardown)
{
	union gtp_packet packet;
	unsigned int length =
	    get_default_gtp(pdp->version, GTP_DELETE_PDP_REQ, &packet);
	struct in_addr addr;
	struct pdp_t *linked_pdp;
	int count;

	if (gsna2in_addr(&addr, &pdp->gsnrc)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_ADDRESS);
		LOGP(DLGTP, LOGL_ERROR, "GSN address (len=%u) conversion failed\n", pdp->gsnrc.l);
		return EOF;
	}

	if (gtp_pdp_getgtp1(gsn, &linked_pdp, pdp->teic_own)) {
		LOGP(DLGTP, LOGL_ERROR,
			"Unknown linked PDP context: %u\n", pdp->teic_own);
		return EOF;
	}

	if (!teardown) {
		count = pdp_count_secondary(linked_pdp);
		if (count <= 1) {
			LOGP(DLGTP, LOGL_ERROR,
				"Must use teardown for last context: %d\n", count);
			return EOF;
		}
	}

	if (pdp->version == 1) {
		if (teardown)
			gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_TEARDOWN,
				  0xff);

		gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_NSAPI, pdp->nsapi);
	}

	gtp_req(gsn, pdp->version, pdp, &packet, length, &addr, cbp);

	return 0;
}

/* Send Delete PDP Context Response */
int gtp_delete_pdp_resp(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, int fd,
			void *pack, unsigned len,
			struct pdp_t *pdp, struct pdp_t *linked_pdp,
			uint8_t cause, int teardown)
{
	union gtp_packet packet;
	unsigned int length =
	    get_default_gtp(version, GTP_DELETE_PDP_RSP, &packet);

	gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_CAUSE, cause);

	gtp_resp(version, gsn, pdp, &packet, length, peer, fd,
		 get_seq(pack), get_tid(pack));

	if (cause == GTPCAUSE_ACC_REQ) {
		if ((teardown) || (version == 0)) {	/* Remove all contexts */
			gtp_freepdp_teardown(gsn, linked_pdp);
		} else {
			/* If we end up here (no teardown) it means we still
			   have at least another pdp context active for this
			   PDN connection (since last DeleteReq should come
			   with teardown enabled). If the ctx to delete is a
			   secondary ctx, simply free it. If it's the primary
			   ctx, mark it as nodata but don't free it since we
			   need it to hold data linked together and we'll
			   require it later to tear down the entire tree. Still,
			   we announce its deletion through cb_delete_context
			   because we don't want user to release its related
			   data and not use it anymore.
			 */
			if (pdp == linked_pdp) {
				if (gsn->cb_delete_context)
					gsn->cb_delete_context(pdp);
				pdp->secondary_tei[pdp->nsapi & 0xf0] = 0;
				pdp->nodata = 1;
			} else {
				gtp_freepdp(gsn, pdp);
			}
		}
	}
	/* if (cause == GTPCAUSE_ACC_REQ) */
	return 0;
}

/* Handle Delete PDP Context Request */
int gtp_delete_pdp_ind(struct gsn_t *gsn, int version,
		       struct sockaddr_in *peer, int fd,
		       void *pack, unsigned len)
{
	struct pdp_t *pdp = NULL;
	struct pdp_t *linked_pdp = NULL;
	union gtpie_member *ie[GTPIE_SIZE];

	uint16_t seq = get_seq(pack);
	int hlen = get_hlen(pack);

	uint8_t nsapi;
	uint8_t teardown = 0;
	int count;

	/* Is this a duplicate ? */
	if (!gtp_duplicate(gsn, version, peer, seq)) {
		return 0;	/* We allready send off response once */
	}

	/* Find the linked context in question */
	if (gtp_pdp_getgtp1(gsn, &linked_pdp, get_tei(pack))) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNKNOWN_PDP);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			   "Unknown PDP context: TEI=0x%" PRIx32 "\n", get_tei(pack));
		return gtp_delete_pdp_resp(gsn, version, peer, fd, pack, len,
					   NULL, NULL, GTPCAUSE_NON_EXIST,
					   teardown);
	}

	/* If version 0 this is also the secondary context */
	if (version == 0)
		pdp = linked_pdp;

	/* Decode information elements */
	if (gtpie_decaps(ie, version, pack + hlen, len - hlen)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_INVALID);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Invalid message format\n");
		if (0 == version)
			return EOF;
		else
			return gtp_delete_pdp_resp(gsn, version, peer, fd, pack,
						   len, NULL, NULL,
						   GTPCAUSE_INVALID_MESSAGE,
						   teardown);
	}

	if (version == 1) {
		/* NSAPI (mandatory) */
		if (gtpie_gettv1(ie, GTPIE_NSAPI, 0, &nsapi)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack,
				   len, "Missing mandatory information field\n");
			return gtp_delete_pdp_resp(gsn, version, peer, fd, pack,
						   len, NULL, NULL,
						   GTPCAUSE_MAN_IE_MISSING,
						   teardown);
		}

		/* Find the context in question */
		if (gtp_pdp_getgtp1(gsn, &pdp, linked_pdp->secondary_tei[nsapi & 0x0f])) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNKNOWN_PDP);
			GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
				   "Unknown PDP context: Secondary TEI=0x%" PRIx32 "\n",
				   linked_pdp->secondary_tei[nsapi & 0x0f]);
			return gtp_delete_pdp_resp(gsn, version, peer, fd, pack,
						   len, NULL, NULL,
						   GTPCAUSE_NON_EXIST,
						   teardown);
		}

		/* Teardown (conditional) */
		gtpie_gettv1(ie, GTPIE_TEARDOWN, 0, &teardown);

		if (!teardown) {
			/* TS 29.060 section 7.3.5: If a GSN receives a Delete PDP context
			 * without a Teardown Indicator or with a Teardown Indicator with
			 * value set to "0" and only that PDP context is active for a PDN
			 * connection, then the GSN shall ignore the message.  (Note:
			 * This is symptom of a race condition. The reliable delivery of
			 * signalling messages will eventually lead to a consistent
			 * situation, allowing the teardown of the PDP context.)
			 */
			count = pdp_count_secondary(linked_pdp);
			if (count <= 1) {
				GTP_LOGPKG(LOGL_NOTICE, peer, pack, len,
					   "Ignoring CTX DEL without teardown and count=%d\n",
					   count);
				return 0;	/* 29.060 7.3.5 Ignore message */
			}
		}
	}

	return gtp_delete_pdp_resp(gsn, version, peer, fd, pack, len,
				   pdp, linked_pdp, GTPCAUSE_ACC_REQ, teardown);
}

/* Handle Delete PDP Context Response */
int gtp_delete_pdp_conf(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, void *pack, unsigned len)
{
	union gtpie_member *ie[GTPIE_SIZE];
	uint8_t cause;
	void *cbp = NULL;
	uint8_t type = 0;
	struct pdp_t *pdp = NULL;
	int hlen = get_hlen(pack);

	/* Remove packet from queue */
	if (gtp_conf(gsn, version, peer, pack, len, &type, &cbp))
		return EOF;

	/* Find the context in question. It may not be available if gtp_delete_context_req
	 * was used and as a result the PDP ctx was already freed */
	if (gtp_pdp_getgtp1(gsn, &pdp, get_tei(pack))) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNKNOWN_PDP);
		GTP_LOGPKG(LOGL_NOTICE, peer, pack, len,
			   "Unknown PDP context: TEI=0x%" PRIx32 " (expected if "
			   "gtp_delete_context_req is used or pdp ctx was freed "
			   "manually before response)\n", get_tei(pack));
		if (gsn->cb_conf)
			gsn->cb_conf(type, EOF, NULL, cbp);
		return EOF;
	}

	/* Decode information elements */
	if (gtpie_decaps(ie, version, pack + hlen, len - hlen)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_INVALID);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Invalid message format\n");
		if (gsn->cb_conf)
			gsn->cb_conf(type, EOF, pdp, cbp);
		return EOF;
	}

	/* Extract cause value (mandatory) */
	if (gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Missing mandatory information field\n");
		if (gsn->cb_conf)
			gsn->cb_conf(type, EOF, pdp, cbp);
		return EOF;
	}

	/* Check the cause value (again) */
	if ((GTPCAUSE_ACC_REQ != cause) && (GTPCAUSE_NON_EXIST != cause)) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNEXPECTED_CAUSE);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Unexpected cause value received: %d\n", cause);
		if (gsn->cb_conf)
			gsn->cb_conf(type, cause, pdp, cbp);
		return EOF;
	}

	/* Callback function to notify application */
	if (gsn->cb_conf)
		gsn->cb_conf(type, cause, pdp, cbp);

	return 0;
}

/* Send Error Indication (response to a GPDU message) - 3GPP TS 29.060 7.3.7 */
static int gtp_error_ind_resp(struct gsn_t *gsn, uint8_t version,
		       struct sockaddr_in *peer, int fd,
		       void *pack, unsigned len)
{
	union gtp_packet packet;
	unsigned int length = get_default_gtp(version, GTP_ERROR, &packet);

	if (version == 1) {
		/* Mandatory 7.7.13 TEI Data I */
		gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_DI,
			  ntoh32(((union gtp_packet *)pack)->gtp1l.h.tei));

		/* Mandatory 7.7.32 GSN Address */
		gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR,
			  sizeof(gsn->gsnu), &gsn->gsnu);
	}

	return gtp_resp(version, gsn, NULL, &packet, length, peer, fd,
			get_seq(pack), get_tid(pack));
}

/* Handle Error Indication */
static int gtp_error_ind_conf(struct gsn_t *gsn, uint8_t version,
		       struct sockaddr_in *peer, void *pack, unsigned len)
{
	union gtpie_member *ie[GTPIE_SIZE];
	struct pdp_t *pdp;

	/* Find the context in question */
	if (version == 0) {
		if (gtp_pdp_tidget(gsn, &pdp, get_tid(pack))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNKNOWN_PDP);
			GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
				   "Unknown PDP context: TID=0x%" PRIx64 "\n",
				   get_tid(pack));
			return EOF;
		}
	} else if (version == 1) {
		/* we have to look-up based on the *peer* TEID */
		int hlen = get_hlen(pack);
		uint32_t teid_gn;

		/* Decode information elements */
		if (gtpie_decaps(ie, version, pack + hlen, len - hlen)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_INVALID);
			GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
				    "Invalid message format\n");
			return EOF;
		}

		if (gtpie_gettv4(ie, GTPIE_TEI_DI, 0, &teid_gn)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_MISSING);
			GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
				    "Missing mandatory information field\n");
			return EOF;
		}

		if (gtp_pdp_getgtp1_peer_d(gsn, &pdp, peer, teid_gn)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNKNOWN_PDP);
			GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
				   "Unknown PDP context: Peer TEID=0x%" PRIx32 "\n",
				   teid_gn);
			return EOF;
		}
	} else {
		LOGP(DLGTP, LOGL_ERROR, "Unknown version: %d\n", version);
		return EOF;
	}

	GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
		    "Received Error Indication\n");

	/* This is obvious from above code, given the semantics of the
	 * functions above, but Coverity doesn't figure this out, so
	 * let's make it clear. It's good style anyway in case above
	 * code should ever change. */
	OSMO_ASSERT(pdp);

	gtp_freepdp(gsn, pdp);
	return 0;
}

static int gtp_gpdu_ind(struct gsn_t *gsn, uint8_t version,
		 struct sockaddr_in *peer, int fd, void *pack, unsigned len)
{

	int hlen;

	struct pdp_t *pdp;

	switch (version) {
	case 0:
		if (gtp_pdp_getgtp0(gsn, &pdp, get_tei(pack))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNKNOWN_PDP);
			GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
				   "Unknown PDP context: TEI=0x%" PRIx32 "\n",
				   get_tei(pack));
			return gtp_error_ind_resp(gsn, version, peer, fd, pack,
						  len);
		}
		hlen = GTP0_HEADER_SIZE;
		break;
	case 1:
		if (gtp_pdp_getgtp1(gsn, &pdp, get_tei(pack))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNKNOWN_PDP);
			GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
				   "Unknown PDP context: TEI=0x%" PRIx32 "\n",
				   get_tei(pack));
			return gtp_error_ind_resp(gsn, version, peer, fd, pack,
						  len);
		}

		/* Is this a long or a short header ? */
		if (((union gtp_packet *)pack)->gtp1l.h.flags & 0x07)
			hlen = GTP1_HEADER_SIZE_LONG;
		else
			hlen = GTP1_HEADER_SIZE_SHORT;
		break;
	default:
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
			    "Unknown version: %d\n", version);
		return EOF;
	}

	/* If the GPDU was not from the peer GSN tell him to delete context */
	if (memcmp(&peer->sin_addr, pdp->gsnru.v, pdp->gsnru.l)) {	/* TODO Range? */
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_UNKNOWN_PDP);
		GTP_LOGPKG(LOGL_ERROR, peer, pack, len, "Unknown GSN peer %s\n", inet_ntoa(peer->sin_addr));
		return gtp_error_ind_resp(gsn, version, peer, fd, pack, len);
	}

	/* Callback function */
	if (gsn->cb_data_ind != 0)
		return gsn->cb_data_ind(pdp, pack + hlen, len - hlen);

	return 0;
}

/* Receives GTP packet and sends off for further processing
 * Function will check the validity of the header. If the header
 * is not valid the packet is either dropped or a version not
 * supported is returned to the peer.
 * TODO: Need to decide on return values! */
int gtp_decaps0(struct gsn_t *gsn)
{
	unsigned char buffer[PACKET_MAX];
	struct sockaddr_in peer;
	socklen_t peerlen;
	int status;
	struct gtp0_header *pheader;
	uint8_t version;
	int fd = gsn->fd0;

	/* TODO: Need strategy of userspace buffering and blocking */
	/* Currently read is non-blocking and send is blocking. */
	/* This means that the program have to wait for busy send calls... */

	while (1) {		/* Loop until no more to read */
		if (fcntl(gsn->fd0, F_SETFL, O_NONBLOCK)) {
			LOGP(DLGTP, LOGL_ERROR, "fnctl()\n");
			return -1;
		}
		peerlen = sizeof(peer);
		if ((status =
		     recvfrom(gsn->fd0, buffer, sizeof(buffer), 0,
			      (struct sockaddr *)&peer, &peerlen)) < 0) {
			if (errno == EAGAIN)
				return 0;
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_READFROM);
			LOGP(DLGTP, LOGL_ERROR,
				"recvfrom(fd0=%d, buffer=%lx, len=%zu) failed: status = %d error = %s\n",
				gsn->fd0, (unsigned long)buffer, sizeof(buffer),
				status, status ? strerror(errno) : "No error");
			return -1;
		}

		/* Need at least 1 byte in order to check version */
		if (status < (1)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_EMPTY);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status, "Discarding packet - too small\n");
			continue;
		}

		pheader = (struct gtp0_header *)(buffer);

		version = GTPHDR_F_GET_VER(pheader->flags);

		/* Version should be gtp0 (or earlier) */
		/* 09.60 is somewhat unclear on this issue. On gsn->fd0 we expect only */
		/* GTP 0 messages. If other version message is received we reply that we */
		/* only support version 0, implying that this is the only version */
		/* supported on this port */
		if (version > 0) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNSUP);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer, status,
				"Unsupported GTP version %"PRIu8"\n", version);
			gtp_unsup_req(gsn, 0, &peer, gsn->fd0, buffer, status);	/* 29.60: 11.1.1 */
			continue;
		}

		/* Check length of gtp0 packet */
		if (status < GTP0_HEADER_SIZE) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_TOOSHORT);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status, "GTP0 packet too short\n");
			continue;	/* Silently discard 29.60: 11.1.2 */
		}

		/* Check packet length field versus length of packet */
		if (status != (ntoh16(pheader->length) + GTP0_HEADER_SIZE)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_TOOSHORT);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status,
				    "GTP packet length field does not match actual length\n");
			continue;	/* Silently discard */
		}

		if ((gsn->mode == GTP_MODE_GGSN) &&
		    ((pheader->type == GTP_CREATE_PDP_RSP) ||
		     (pheader->type == GTP_UPDATE_PDP_RSP))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNEXPECT);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status,
				    "Unexpected GTPv0 Signalling Message '%s'\n",
				    get_value_string(gtp_type_names, pheader->type));
			continue;	/* Silently discard 29.60: 11.1.4 */
		}

		if ((gsn->mode == GTP_MODE_SGSN) &&
		    ((pheader->type == GTP_CREATE_PDP_REQ) ||
		     (pheader->type == GTP_UPDATE_PDP_REQ))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNEXPECT);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status,
				    "Unexpected GTPv0 Signalling Message '%s'\n",
				    get_value_string(gtp_type_names, pheader->type));
			continue;	/* Silently discard 29.60: 11.1.4 */
		}

		switch (pheader->type) {
		case GTP_ECHO_REQ:
			gtp_echo_ind(gsn, version, &peer, fd, buffer, status);
			break;
		case GTP_ECHO_RSP:
			gtp_echo_conf(gsn, version, &peer, buffer, status);
			break;
		case GTP_NOT_SUPPORTED:
			gtp_unsup_ind(gsn, &peer, buffer, status);
			break;
		case GTP_CREATE_PDP_REQ:
			gtp_create_pdp_ind(gsn, version, &peer, fd, buffer,
					   status);
			break;
		case GTP_CREATE_PDP_RSP:
			gtp_create_pdp_conf(gsn, version, &peer, buffer,
					    status);
			break;
		case GTP_UPDATE_PDP_REQ:
			gtp_update_pdp_ind(gsn, version, &peer, fd, buffer,
					   status);
			break;
		case GTP_UPDATE_PDP_RSP:
			gtp_update_pdp_conf(gsn, version, &peer, buffer,
					    status);
			break;
		case GTP_DELETE_PDP_REQ:
			gtp_delete_pdp_ind(gsn, version, &peer, fd, buffer,
					   status);
			break;
		case GTP_DELETE_PDP_RSP:
			gtp_delete_pdp_conf(gsn, version, &peer, buffer,
					    status);
			break;
		case GTP_ERROR:
			gtp_error_ind_conf(gsn, version, &peer, buffer, status);
			break;
		case GTP_GPDU:
			gtp_gpdu_ind(gsn, version, &peer, fd, buffer, status);
			break;
		default:
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNKNOWN);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer, status,
				"Unknown GTP message type received: %d\n",
				pheader->type);
			break;
		}
	}
}

int gtp_decaps1c(struct gsn_t *gsn)
{
	unsigned char buffer[PACKET_MAX];
	struct sockaddr_in peer;
	socklen_t peerlen;
	int status;
	struct gtp1_header_short *pheader;
	uint8_t version;
	int fd = gsn->fd1c;

	/* TODO: Need strategy of userspace buffering and blocking */
	/* Currently read is non-blocking and send is blocking. */
	/* This means that the program have to wait for busy send calls... */

	while (1) {		/* Loop until no more to read */
		if (fcntl(fd, F_SETFL, O_NONBLOCK)) {
			LOGP(DLGTP, LOGL_ERROR, "fnctl()\n");
			return -1;
		}
		peerlen = sizeof(peer);
		if ((status =
		     recvfrom(fd, buffer, sizeof(buffer), 0,
			      (struct sockaddr *)&peer, &peerlen)) < 0) {
			if (errno == EAGAIN)
				return 0;
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_READFROM);
			LOGP(DLGTP, LOGL_ERROR,
				"recvfrom(fd=%d, buffer=%lx, len=%zu) failed: status = %d error = %s\n",
				fd, (unsigned long)buffer, sizeof(buffer),
				status, status ? strerror(errno) : "No error");
			return -1;
		}

		/* Need at least 1 byte in order to check version */
		if (status < (1)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_EMPTY);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status, "Discarding packet - too small\n");
			continue;
		}

		pheader = (struct gtp1_header_short *)(buffer);

		version = GTPHDR_F_GET_VER(pheader->flags);

		/* Version must be no larger than GTP 1 */
		if (version > 1) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNSUP);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer, status,
				"Unsupported GTP version %"PRIu8"\n", version);
			gtp_unsup_req(gsn, version, &peer, fd, buffer, status);
			/*29.60: 11.1.1 */
			continue;
		}

		/* Version must be at least GTP 1 */
		/* 29.060 is somewhat unclear on this issue. On gsn->fd1c we expect only */
		/* GTP 1 messages. If GTP 0 message is received we silently discard */
		/* the message */
		if (version < 1) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNSUP);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer, status,
				"Unsupported GTP version %"PRIu8"\n", version);
			continue;
		}

		/* Check packet flag field */
		if (((pheader->flags & 0xf7) != 0x32)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNSUP);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status, "Unsupported packet flags: 0x%02x\n", pheader->flags);
			continue;
		}

		/* Check length of packet */
		if (status < GTP1_HEADER_SIZE_LONG) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_TOOSHORT);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status, "GTP packet too short\n");
			continue;	/* Silently discard 29.60: 11.1.2 */
		}

		/* Check packet length field versus length of packet */
		if (status !=
		    (ntoh16(pheader->length) + GTP1_HEADER_SIZE_SHORT)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_TOOSHORT);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status,
				    "GTP packet length field does not match actual length\n");
			continue;	/* Silently discard */
		}

		/* Check for extension headers */
		/* TODO: We really should cycle through the headers and determine */
		/* if any have the comprehension required flag set */
		if (((pheader->flags & GTP1HDR_F_EXT) != 0x00)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNSUP);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status, "Unsupported extension header\n");
			gtp_extheader_req(gsn, version, &peer, fd, buffer,
					  status);

			continue;
		}

		if ((gsn->mode == GTP_MODE_GGSN) &&
		    ((pheader->type == GTP_CREATE_PDP_RSP) ||
		     (pheader->type == GTP_UPDATE_PDP_RSP))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNEXPECT);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status,
				    "Unexpected GTPv1 Signalling Message '%s'\n",
				    get_value_string(gtp_type_names, pheader->type));
			continue;	/* Silently discard 29.60: 11.1.4 */
		}

		if ((gsn->mode == GTP_MODE_SGSN) &&
		    ((pheader->type == GTP_CREATE_PDP_REQ) ||
		     (pheader->type == GTP_UPDATE_PDP_REQ))) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNEXPECT);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status,
				    "Unexpected GTPv1 Signalling Message '%s'\n",
				    get_value_string(gtp_type_names, pheader->type));
			continue;	/* Silently discard 29.60: 11.1.4 */
		}

		switch (pheader->type) {
		case GTP_ECHO_REQ:
			gtp_echo_ind(gsn, version, &peer, fd, buffer, status);
			break;
		case GTP_ECHO_RSP:
			gtp_echo_conf(gsn, version, &peer, buffer, status);
			break;
		case GTP_NOT_SUPPORTED:
			gtp_unsup_ind(gsn, &peer, buffer, status);
			break;
		case GTP_SUPP_EXT_HEADER:
			gtp_extheader_ind(gsn, &peer, buffer, status);
			break;
		case GTP_CREATE_PDP_REQ:
			gtp_create_pdp_ind(gsn, version, &peer, fd, buffer,
					   status);
			break;
		case GTP_CREATE_PDP_RSP:
			gtp_create_pdp_conf(gsn, version, &peer, buffer,
					    status);
			break;
		case GTP_UPDATE_PDP_REQ:
			gtp_update_pdp_ind(gsn, version, &peer, fd, buffer,
					   status);
			break;
		case GTP_UPDATE_PDP_RSP:
			gtp_update_pdp_conf(gsn, version, &peer, buffer,
					    status);
			break;
		case GTP_DELETE_PDP_REQ:
			gtp_delete_pdp_ind(gsn, version, &peer, fd, buffer,
					   status);
			break;
		case GTP_DELETE_PDP_RSP:
			gtp_delete_pdp_conf(gsn, version, &peer, buffer,
					    status);
			break;
		case GTP_ERROR:
			gtp_error_ind_conf(gsn, version, &peer, buffer, status);
			break;
		case GTP_RAN_INFO_RELAY:
			gtp_ran_info_relay_ind(gsn, version, &peer, buffer, status);
			break;
		default:
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNKNOWN);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer, status,
				"Unknown GTP message type received: %u\n",
				pheader->type);
			break;
		}
	}
}

int gtp_decaps1u(struct gsn_t *gsn)
{
	unsigned char buffer[PACKET_MAX];
	struct sockaddr_in peer;
	socklen_t peerlen;
	int status;
	struct gtp1_header_short *pheader;
	uint8_t version;
	int fd = gsn->fd1u;

	/* TODO: Need strategy of userspace buffering and blocking */
	/* Currently read is non-blocking and send is blocking. */
	/* This means that the program have to wait for busy send calls... */

	while (1) {		/* Loop until no more to read */
		if (fcntl(gsn->fd1u, F_SETFL, O_NONBLOCK)) {
			LOGP(DLGTP, LOGL_ERROR, "fnctl()\n");
			return -1;
		}
		peerlen = sizeof(peer);
		if ((status =
		     recvfrom(gsn->fd1u, buffer, sizeof(buffer), 0,
			      (struct sockaddr *)&peer, &peerlen)) < 0) {
			if (errno == EAGAIN)
				return 0;
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_READFROM);
			LOGP(DLGTP, LOGL_ERROR,
				"recvfrom(fd1u=%d, buffer=%lx, len=%zu) failed: status = %d error = %s\n",
				gsn->fd1u, (unsigned long)buffer,
				sizeof(buffer), status,
				status ? strerror(errno) : "No error");
			return -1;
		}

		/* Need at least 1 byte in order to check version */
		if (status < (1)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_EMPTY);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status, "Discarding packet - too small\n");
			continue;
		}

		pheader = (struct gtp1_header_short *)(buffer);

		version = GTPHDR_F_GET_VER(pheader->flags);

		/* Version must be no larger than GTP 1 */
		if (version > 1) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNSUP);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer, status,
				"Unsupported GTP version %"PRIu8"\n", version);
			gtp_unsup_req(gsn, 1, &peer, gsn->fd1c, buffer, status);	/*29.60: 11.1.1 */
			continue;
		}

		/* Version must be at least GTP 1 */
		/* 29.060 is somewhat unclear on this issue. On gsn->fd1c we expect only */
		/* GTP 1 messages. If GTP 0 message is received we silently discard */
		/* the message */
		if (version < 1) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNSUP);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer, status,
				"Unsupported GTP version %"PRIu8"\n", version);
			continue;
		}

		/* Check packet flag field (allow both with and without sequence number) */
		if (((pheader->flags & 0xf5) != 0x30)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNSUP);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status, "Unsupported packet flags 0x%02x\n", pheader->flags);
			continue;
		}

		/* Check length of packet */
		if (status < GTP1_HEADER_SIZE_SHORT) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_TOOSHORT);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status, "GTP packet too short\n");
			continue;	/* Silently discard 29.60: 11.1.2 */
		}

		/* Check packet length field versus length of packet */
		if (status !=
		    (ntoh16(pheader->length) + GTP1_HEADER_SIZE_SHORT)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_TOOSHORT);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status,
				    "GTP packet length field does not match actual length\n");
			continue;	/* Silently discard */
		}

		/* Check for extension headers */
		/* TODO: We really should cycle through the headers and determine */
		/* if any have the comprehension required flag set */
		if (((pheader->flags & GTP1HDR_F_EXT) != 0x00)) {
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNSUP);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer,
				    status, "Unsupported extension header\n");
			gtp_extheader_req(gsn, version, &peer, fd, buffer,
					  status);

			continue;
		}

		switch (pheader->type) {
		case GTP_ECHO_REQ:
			gtp_echo_ind(gsn, version, &peer, fd, buffer, status);
			break;
		case GTP_ECHO_RSP:
			gtp_echo_conf(gsn, version, &peer, buffer, status);
			break;
		case GTP_SUPP_EXT_HEADER:
			gtp_extheader_ind(gsn, &peer, buffer, status);
			break;
		case GTP_ERROR:
			gtp_error_ind_conf(gsn, version, &peer, buffer, status);
			break;
			/* Supported header extensions */
		case GTP_GPDU:
			gtp_gpdu_ind(gsn, version, &peer, fd, buffer, status);
			break;
		default:
			rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_UNKNOWN);
			GTP_LOGPKG(LOGL_ERROR, &peer, buffer, status,
				"Unknown GTP message type received: %u\n",
				pheader->type);
			break;
		}
	}
}

int gtp_data_req(struct gsn_t *gsn, struct pdp_t *pdp, void *pack, unsigned len)
{
	union gtp_packet packet;
	struct sockaddr_in addr;
	struct msghdr msgh;
	struct iovec iov[2];
	int fd;

	/* prepare destination address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
#if defined(__FreeBSD__) || defined(__APPLE__)
	addr.sin_len = sizeof(addr);
#endif
	memcpy(&addr.sin_addr, pdp->gsnru.v, pdp->gsnru.l);	/* TODO range check */

	/* prepare msghdr */
	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_name = &addr;
	msgh.msg_namelen = sizeof(addr);
	msgh.msg_iov = iov;
	msgh.msg_iovlen = ARRAY_SIZE(iov);

	/* prepare iovectors */
	iov[0].iov_base = &packet;
	/* iov[0].iov_len is not known here yet */
	iov[1].iov_base = pack;
	iov[1].iov_len = len;

	if (pdp->version == 0) {

		iov[0].iov_len = GTP0_HEADER_SIZE;
		addr.sin_port = htons(GTP0_PORT);
		fd = gsn->fd0;

		get_default_gtp(0, GTP_GPDU, &packet);
		packet.gtp0.h.length = hton16(len);
		if (pdp->tx_gpdu_seq)
			packet.gtp0.h.seq = hton16(pdp->gtpsntx++);
		else
			packet.gtp0.h.seq = 0;
		packet.gtp0.h.flow = hton16(pdp->flru);
		packet.gtp0.h.tid = htobe64(pdp_gettid(pdp->imsi, pdp->nsapi));
	} else if (pdp->version == 1) {

		addr.sin_port = htons(GTP1U_PORT);
		fd = gsn->fd1u;

		get_default_gtp(1, GTP_GPDU, &packet);
		if (pdp->tx_gpdu_seq) {
			packet.gtp1l.h.seq = hton16(pdp->gtpsntx++);
			packet.gtp1l.h.length = hton16(len - GTP1_HEADER_SIZE_SHORT +
						       GTP1_HEADER_SIZE_LONG);
			packet.gtp1l.h.tei = hton32(pdp->teid_gn);
			iov[0].iov_len = GTP1_HEADER_SIZE_LONG;
		} else {
			packet.gtp1s.h.flags &= ~GTP1HDR_F_SEQ;
			packet.gtp1s.h.length = hton16(len);
			packet.gtp1s.h.tei = hton32(pdp->teid_gn);
			iov[0].iov_len = GTP1_HEADER_SIZE_SHORT;
		}
	} else {
		LOGP(DLGTP, LOGL_ERROR, "Unknown version: %d\n", pdp->version);
		return EOF;
	}

	if (fcntl(fd, F_SETFL, 0)) {
		LOGP(DLGTP, LOGL_ERROR, "fnctl()\n");
		return -1;
	}

	if (sendmsg(fd, &msgh, 0) < 0) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_ERR_SENDTO);
		LOGP(DLGTP, LOGL_ERROR,
			"sendmsg(fd=%d, msg=%lx, len=%d) failed: Error = %s\n", fd,
			(unsigned long)&packet, GTP0_HEADER_SIZE + len,
			strerror(errno));
		return EOF;
	}
	return 0;
}

/* ***********************************************************
 * Conversion functions
 *************************************************************/

/* ***********************************************************
 * IP address conversion functions
 * There exist several types of address representations:
 * - eua: End User Address. (29.060, 7.7.27, message type 128)
 *   Used for signalling address to mobile station. Supports IPv4
 *   IPv6 x.25 etc. etc.
 * - gsna: GSN Address. (29.060, 7.7.32, message type 133): IP address
 *   of GSN. If length is 4 it is IPv4. If length is 16 it is IPv6.
 * - in_addr: IPv4 address struct.
 * - sockaddr_in: Socket API representation of IP address and
 *   port number.
 *************************************************************/

int ipv42eua(struct ul66_t *eua, struct in_addr *src)
{
	eua->v[0] = PDP_EUA_ORG_IETF;
	eua->v[1] = PDP_EUA_TYPE_v4;
	if (src) {
		eua->l = 6;
		memcpy(&eua->v[2], src, 4);
	} else {
		eua->l = 2;
	}
	return 0;
}

int eua2ipv4(struct in_addr *dst, struct ul66_t *eua)
{
	if ((eua->l != 6) || (eua->v[0] != PDP_EUA_ORG_IETF) || (eua->v[1] != PDP_EUA_TYPE_v4))
		return -1;	/* Not IPv4 address */
	memcpy(dst, &eua->v[2], 4);
	return 0;
}

int gsna2in_addr(struct in_addr *dst, struct ul16_t *gsna)
{
	memset(dst, 0, sizeof(struct in_addr));
	if (gsna->l != 4)
		return EOF;	/* Return if not IPv4 */
	memcpy(dst, gsna->v, gsna->l);
	return 0;
}

int in_addr2gsna(struct ul16_t *gsna, struct in_addr *src)
{
	memset(gsna, 0, sizeof(struct ul16_t));
	gsna->l = 4;
	memcpy(gsna->v, src, gsna->l);
	return 0;
}

/* TS 29.060 has yet again a different encoding for IMSIs than
 * what we have in other places, so we cannot use the gsm48
 * decoding functions.  Also, libgtp uses an uint64_t in
 * _network byte order_ to contain BCD digits ?!? */
const char *imsi_gtp2str(const uint64_t *imsi)
{
	static char buf[sizeof(*imsi)*2+1];
	const uint8_t *imsi8 = (const uint8_t *) imsi;
	unsigned int i, j = 0;

	for (i = 0; i < sizeof(*imsi); i++) {
		uint8_t nibble;

		nibble = imsi8[i] & 0xf;
		if (nibble == 0xf)
			break;
		buf[j++] = osmo_bcd2char(nibble);

		nibble = imsi8[i] >> 4;
		if (nibble == 0xf)
			break;
		buf[j++] = osmo_bcd2char(nibble);
	}

	buf[j++] = '\0';
	return buf;
}

/* Generate the GTP IMSI IE according to 09.60 Section 7.9.2 */
uint64_t gtp_imsi_str2gtp(const char *str)
{
	uint64_t imsi64 = 0;
	unsigned int n;
	unsigned int imsi_len = strlen(str);

	if (imsi_len > 16) {
		LOGP(DLGTP, LOGL_NOTICE, "IMSI length > 16 not supported!\n");
		return 0;
	}

	for (n = 0; n < 16; n++) {
		uint64_t val;
		if (n < imsi_len)
			val = (str[n]-'0') & 0xf;
		else
			val = 0xf;
		imsi64 |= (val << (n*4));
	}
	return imsi64;
}
