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

#ifndef _GTP_H
#define _GTP_H

#include <osmocom/core/utils.h>

#include "gtpie.h"
#include "pdp.h"
#include "gsn.h"

#define GTP0_PORT	3386
#define GTP1C_PORT	2123
#define GTP1U_PORT	2152
#define PACKET_MAX      8196

#define GTP_MAX  0xffff		/* TODO: Choose right number */
#define GTP0_HEADER_SIZE 20
#define GTP1_HEADER_SIZE_SHORT  8
#define GTP1_HEADER_SIZE_LONG  12

#define NAMESIZE 1024
#define SYSLOG_PRINTSIZE 255
#define ERRMSG_SIZE 255

/* GTP version 1 extension header type definitions. */
#define GTP_EXT_PDCP_PDU    0xC0	/* PDCP PDU Number */

/* GTP version 1 message type definitions. Also covers version 0 except *
 * for anonymous PDP context which was superceded in version 1 */

/* 0 For future use. */
#define GTP_ECHO_REQ          1	/* Echo Request */
#define GTP_ECHO_RSP          2	/* Echo Response */
#define GTP_NOT_SUPPORTED     3	/* Version Not Supported */
#define GTP_ALIVE_REQ         4	/* Node Alive Request */
#define GTP_ALIVE_RSP         5	/* Node Alive Response */
#define GTP_REDIR_REQ         6	/* Redirection Request */
#define GTP_REDIR_RSP         7	/* Redirection Response */
/* 8-15 For future use. */
#define GTP_CREATE_PDP_REQ   16	/* Create PDP Context Request */
#define GTP_CREATE_PDP_RSP   17	/* Create PDP Context Response */
#define GTP_UPDATE_PDP_REQ   18	/* Update PDP Context Request */
#define GTP_UPDATE_PDP_RSP   19	/* Update PDP Context Response */
#define GTP_DELETE_PDP_REQ   20	/* Delete PDP Context Request */
#define GTP_DELETE_PDP_RSP   21	/* Delete PDP Context Response */
/* 22-25 For future use. *//* In version GTP 1 anonomous PDP context */
#define GTP_ERROR            26	/* Error Indication */
#define GTP_PDU_NOT_REQ      27	/* PDU Notification Request */
#define GTP_PDU_NOT_RSP      28	/* PDU Notification Response */
#define GTP_PDU_NOT_REJ_REQ  29	/* PDU Notification Reject Request */
#define GTP_PDU_NOT_REJ_RSP  30	/* PDU Notification Reject Response */
#define GTP_SUPP_EXT_HEADER  31	/* Supported Extension Headers Notification */
#define GTP_SND_ROUTE_REQ    32	/* Send Routeing Information for GPRS Request */
#define GTP_SND_ROUTE_RSP    33	/* Send Routeing Information for GPRS Response */
#define GTP_FAILURE_REQ      34	/* Failure Report Request */
#define GTP_FAILURE_RSP      35	/* Failure Report Response */
#define GTP_MS_PRESENT_REQ   36	/* Note MS GPRS Present Request */
#define GTP_MS_PRESENT_RSP   37	/* Note MS GPRS Present Response */
/* 38-47 For future use. */
#define GTP_IDEN_REQ         48	/* Identification Request */
#define GTP_IDEN_RSP         49	/* Identification Response */
#define GTP_SGSN_CONTEXT_REQ 50	/* SGSN Context Request */
#define GTP_SGSN_CONTEXT_RSP 51	/* SGSN Context Response */
#define GTP_SGSN_CONTEXT_ACK 52	/* SGSN Context Acknowledge */
#define GTP_FWD_RELOC_REQ    53	/* Forward Relocation Request */
#define GTP_FWD_RELOC_RSP    54	/* Forward Relocation Response */
#define GTP_FWD_RELOC_COMPL  55	/* Forward Relocation Complete */
#define GTP_RELOC_CANCEL_REQ 56	/* Relocation Cancel Request */
#define GTP_RELOC_CANCEL_RSP 57	/* Relocation Cancel Response */
#define GTP_FWD_SRNS         58	/* Forward SRNS Context */
#define GTP_FWD_RELOC_ACK    59	/* Forward Relocation Complete Acknowledge */
#define GTP_FWD_SRNS_ACK     60	/* Forward SRNS Context Acknowledge */
#define GTP_RAN_INFO_RELAY   70	/* RAN Information Relay */
/* 61-239 For future use. */
#define GTP_DATA_TRAN_REQ   240	/* Data Record Transfer Request */
#define GTP_DATA_TRAN_RSP   241	/* Data Record Transfer Response */
/* 242-254 For future use. */
#define GTP_GPDU            255	/* G-PDU */

extern const struct value_string gtp_type_names[];
static inline const char *gtp_type_name(uint8_t val)
{ return get_value_string(gtp_type_names, val); }

/* GTP information element cause codes from 29.060 v15.3.0 7.7.1 */
/*                                                            */
#define GTPCAUSE_REQ_IMSI                   0	/* Request IMSI */
#define GTPCAUSE_REQ_IMEI                   1	/* Request IMEI */
#define GTPCAUSE_REQ_IMSI_IMEI              2	/* Request IMSI and IMEI */
#define GTPCAUSE_NO_ID_NEEDED               3	/* No identity needed */
#define GTPCAUSE_MS_REFUSES_X               4	/* MS refuses */
#define GTPCAUSE_MS_NOT_RESP_X              5	/* MS is not GPRS responding */
#define GTPCAUSE_REACTIVATION_REQ           6	/* Reactivation Requested */
#define GTPCAUSE_PDP_ADDR_INACT             7	/* PDP address inactivity timer expires */
#define GTPCAUSE_NET_FAILURE                8	/* Network failure */
#define GTPCAUSE_QOS_MISMATCH               9	/* QoS parameter mismatch */

/* 10-48 For future use */
/* 49-63 Cause values reserved for GPRS charging protocol use (See GTP' 3GPP TS 32.295) */
/* 64-127 For future use */
#define GTPCAUSE_ACC_REQ                  128	/* Request accepted */
#define GTPCAUSE_NEW_PDP_NET_PREF         129	/* New PDP type due to network preference */
#define GTPCAUSE_NEW_PDP_ADDR_BEAR        130	/* New PDP type due to single address bearer only */
/* 131-176 For future use */
/* 177-191 Cause values reserved for GPRS charging protocol use (See GTP' 3GPP TS 32.295) */
#define GTPCAUSE_NON_EXIST                192	/* Non-existent */
#define GTPCAUSE_INVALID_MESSAGE          193	/* Invalid message format */
#define GTPCAUSE_IMSI_NOT_KNOWN           194	/* IMSI not known */
#define GTPCAUSE_MS_DETACHED              195	/* MS is GPRS detached */
#define GTPCAUSE_MS_NOT_RESP              196	/* MS is not GPRS responding */
#define GTPCAUSE_MS_REFUSES               197	/* MS refuses */
#define GTPCAUSE_VERSION_NOT_SUPPORTED    198	/* Version not supported */
#define GTPCAUSE_NO_RESOURCES             199	/* No resources available */
#define GTPCAUSE_NOT_SUPPORTED            200	/* Service not supported */
#define GTPCAUSE_MAN_IE_INCORRECT         201	/* Mandatory IE incorrect */
#define GTPCAUSE_MAN_IE_MISSING           202	/* Mandatory IE missing */
#define GTPCAUSE_OPT_IE_INCORRECT         203	/* Optional IE incorrect */
#define GTPCAUSE_SYS_FAIL                 204	/* System failure */
#define GTPCAUSE_ROAMING_REST             205	/* Roaming Restriction */
#define GTPCAUSE_PTIMSI_MISMATCH          206	/* P-TMSI signature mismatch */
#define GTPCAUSE_CONN_SUSP                207	/* GPRS connection suspended */
#define GTPCAUSE_AUTH_FAIL                208	/* Authentication failure */
#define GTPCAUSE_USER_AUTH_FAIL           209	/* User authentication failed */
#define GTPCAUSE_CONTEXT_NOT_FOUND        210	/* Context not found */
#define GTPCAUSE_ADDR_OCCUPIED            211	/* All dynamic PDP addresses are occupied */
#define GTPCAUSE_NO_MEMORY                212	/* No memory is available */
#define GTPCAUSE_RELOC_FAIL               213	/* Relocation failure */
#define GTPCAUSE_UNKNOWN_MAN_EXTHEADER    214	/* Unknown mandatory extension header */
#define GTPCAUSE_SEM_ERR_TFT              215	/* Semantic error in the TFT operation */
#define GTPCAUSE_SYN_ERR_TFT              216	/* Syntactic error in the TFT operation */
#define GTPCAUSE_SEM_ERR_FILTER           217	/* Semantic errors in packet filter(s) */
#define GTPCAUSE_SYN_ERR_FILTER           218	/* Syntactic errors in packet filter(s) */
#define GTPCAUSE_MISSING_APN              219	/* Missing or unknown APN */
#define GTPCAUSE_UNKNOWN_PDP              220	/* Unknown PDP address or PDP type */
/* 234-240 For future use */
/* 241-255 Cause Values Reserved For Gprs Charging Protocol Use (See Gtp' 3GPP TS 32.295) */

static inline bool gtp_cause_successful(uint8_t cause)
{
	return cause == GTPCAUSE_ACC_REQ ||
		cause == GTPCAUSE_NEW_PDP_NET_PREF ||
		cause == GTPCAUSE_NEW_PDP_ADDR_BEAR;
}

struct ul66_t;
struct ul16_t;
struct pdp_t;

/* GTP 0 header.
 * Explanation to some of the fields:
 * SNDCP NPDU Number flag = 0 except for inter SGSN handover situations
 * SNDCP N-PDU LCC Number 0 = 0xff except for inter SGSN handover situations
 * Sequence number. Used for reliable delivery of signalling messages, and
 *   to discard "illegal" data messages.
 * Flow label. Is used to point a particular PDP context. Is used in data
 *   messages as well as signalling messages related to a particular context.
 * Tunnel ID is IMSI+NSAPI. Unique identifier of PDP context. Is somewhat
 *   redundant because the header also includes flow. */

struct gtp0_header {		/*    Descriptions from 3GPP 09.60 */
	uint8_t flags;		/* 01 bitfield, with typical values */
	/*    000..... Version: 1 (0) */
	/*    ...1111. Spare (7) */
	/*    .......0 SNDCP N-PDU Number flag (0) */
	uint8_t type;		/* 02 Message type. T-PDU = 0xff */
	uint16_t length;	/* 03 Length (of G-PDU excluding header) */
	uint16_t seq;		/* 05 Sequence Number */
	uint16_t flow;		/* 07 Flow Label ( = 0 for signalling) */
	uint8_t number;		/* 09 SNDCP N-PDU LCC Number ( 0 = 0xff) */
	uint8_t spare1;		/* 10 Spare */
	uint8_t spare2;		/* 11 Spare */
	uint8_t spare3;		/* 12 Spare */
	uint64_t tid;		/* 13 Tunnel ID */
} __attribute__((packed));	/* 20 */

#define GTP1HDR_F_NPDU	0x01
#define GTP1HDR_F_SEQ	0x02
#define GTP1HDR_F_EXT	0x04
#define GTP1HDR_F_GTP1	0x10
#define GTPHDR_F_VER(n)	((n) << 5)
#define GTPHDR_F_GET_VER(flags) ((flags)>>5)

struct gtp1_header_short {	/*    Descriptions from 3GPP 29060 */
	uint8_t flags;		/* 01 bitfield, with typical values */
	/*    001..... Version: 1 */
	/*    ...1.... Protocol Type: GTP=1, GTP'=0 */
	/*    ....0... Spare = 0 */
	/*    .....0.. Extension header flag: 0 */
	/*    ......0. Sequence number flag: 0 */
	/*    .......0 PN: N-PDU Number flag */
	uint8_t type;		/* 02 Message type. T-PDU = 0xff */
	uint16_t length;	/* 03 Length (of IP packet or signalling) */
	uint32_t tei;		/* 05 - 08 Tunnel Endpoint ID */
} __attribute__((packed));

struct gtp1_header_long {	/*    Descriptions from 3GPP 29060 */
	uint8_t flags;		/* 01 bitfield, with typical values */
	/*    001..... Version: 1 */
	/*    ...1.... Protocol Type: GTP=1, GTP'=0 */
	/*    ....0... Spare = 0 */
	/*    .....0.. Extension header flag: 0 */
	/*    ......1. Sequence number flag: 1 */
	/*    .......0 PN: N-PDU Number flag */
	uint8_t type;		/* 02 Message type. T-PDU = 0xff */
	uint16_t length;	/* 03 Length (of IP packet or signalling) */
	uint32_t tei;		/* 05 Tunnel Endpoint ID */
	uint16_t seq;		/* 10 Sequence Number */
	uint8_t npdu;		/* 11 N-PDU Number */
	uint8_t next;		/* 12 Next extension header type. Empty = 0 */
} __attribute__((packed));

struct gtp0_packet {
	struct gtp0_header h;
	uint8_t p[GTP_MAX];
} __attribute__ ((packed));

struct gtp1_packet_short {
	struct gtp1_header_short h;
	uint8_t p[GTP_MAX];
} __attribute__ ((packed));

struct gtp1_packet_long {
	struct gtp1_header_long h;
	uint8_t p[GTP_MAX];
} __attribute__ ((packed));

union gtp_packet {
	uint8_t flags;
	struct gtp0_packet gtp0;
	struct gtp1_packet_short gtp1s;
	struct gtp1_packet_long gtp1l;
} __attribute__ ((packed));

/* External API functions */

extern const char *gtp_version();

extern int gtp_create_context_req(struct gsn_t *gsn, struct pdp_t *pdp,
				  void *cbp);

extern int gtp_create_context_resp(struct gsn_t *gsn, struct pdp_t *pdp,
				   int cause);

extern int gtp_update_context(struct gsn_t *gsn, struct pdp_t *pdp,
			      void *cbp, struct in_addr *inetaddr);

extern int gtp_update_context_resp(struct gsn_t *gsn, struct pdp_t *pdp,
				   int cause);

extern int gtp_delete_context_req(struct gsn_t *gsn, struct pdp_t *pdp,
				  void *cbp, int teardown)
		OSMO_DEPRECATED("Use gtp_delete_context_req2() instead, to avoid freeing pdp ctx before reply");
extern int gtp_delete_context_req2(struct gsn_t *gsn, struct pdp_t *pdp,
				   void *cbp, int teardown);

extern int gtp_data_req(struct gsn_t *gsn, struct pdp_t *pdp,
			void *pack, unsigned len);

extern int gtp_ran_info_relay_req(struct gsn_t *gsn, const struct sockaddr_in *peer,
				  const uint8_t *ran_container, size_t ran_container_len,
				  const uint8_t *rim_route_addr, size_t rim_route_addr_len,
				  uint8_t rim_route_addr_discr);

/* Tx a SGSN Context Request */
extern int gtp_sgsn_context_req(struct gsn_t *gsn, uint32_t *local_ref,
				const struct sockaddr_in *peer, union gtpie_member **ie, size_t ie_size);

/* Tx a SGSN Context Response */
extern int gtp_sgsn_context_resp(struct gsn_t *gsn, uint32_t local_ref,
				 union gtpie_member **ie, unsigned int ie_size);

/* Tx a SGSN Context Response, simplified when returning an error */
int gtp_sgsn_context_resp_error(struct gsn_t *gsn, uint32_t local_ref,
				uint8_t cause);

/* Tx a SGSN Context Ack */
extern int gtp_sgsn_context_ack(struct gsn_t *gsn, uint32_t local_ref,
				union gtpie_member **ie, unsigned int ie_size);

/* Tx a SGSN Context Ack, simplified when returning an error */
int gtp_sgsn_context_ack_error(struct gsn_t *gsn, uint32_t local_ref,
				uint8_t cause);


extern int gtp_decaps0(struct gsn_t *gsn);
extern int gtp_decaps1c(struct gsn_t *gsn);
extern int gtp_decaps1u(struct gsn_t *gsn);

extern int gtp_echo_req(struct gsn_t *gsn, int version, void *cbp,
			struct in_addr *inetaddrs);

extern int gsna2in_addr(struct in_addr *dst, struct ul16_t *gsna);

extern int gtp_encode_pdp_ctx(uint8_t *buf, unsigned int size, const struct pdp_t *pdp, uint16_t sapi);
extern int gtp_decode_pdp_ctx(const uint8_t *buf, unsigned int size, struct pdp_t *pdp, uint16_t *sapi);

extern const char *imsi_gtp2str(const uint64_t *imsi);

/*! Set the talloc context for internal objects */
void gtp_set_talloc_ctx(void *ctx);

#endif /* !_GTP_H */
