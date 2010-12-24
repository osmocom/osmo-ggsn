/* 
 *  OpenGGSN - Gateway GPRS Support Node
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

#define GTP_DEBUG 0              /* Print debug information */

#define GTP_MODE_GGSN 1
#define GTP_MODE_SGSN 2

#define GTP0_PORT	3386
#define GTP1C_PORT	2123
#define GTP1U_PORT	2152
#define PACKET_MAX      8196

#define GTP_MAX  0xffff         /* TODO: Choose right number */
#define GTP0_HEADER_SIZE 20
#define GTP1_HEADER_SIZE_SHORT  8
#define GTP1_HEADER_SIZE_LONG  12

#define SYSLOG_PRINTSIZE 255
#define ERRMSG_SIZE 255

#define RESTART_FILE "gsn_restart"
#define NAMESIZE 1024

/* GTP version 1 extension header type definitions. */
#define GTP_EXT_PDCP_PDU    0xC0 /* PDCP PDU Number */

/* GTP version 1 message type definitions. Also covers version 0 except *
 * for anonymous PDP context which was superceded in version 1 */

/* 0 For future use. */
#define GTP_ECHO_REQ          1 /* Echo Request */
#define GTP_ECHO_RSP          2 /* Echo Response */
#define GTP_NOT_SUPPORTED     3 /* Version Not Supported */
#define GTP_ALIVE_REQ         4 /* Node Alive Request */
#define GTP_ALIVE_RSP         5 /* Node Alive Response */
#define GTP_REDIR_REQ         6 /* Redirection Request */
#define GTP_REDIR_RSP         7 /* Redirection Response */
/* 8-15 For future use. */
#define GTP_CREATE_PDP_REQ   16 /* Create PDP Context Request */
#define GTP_CREATE_PDP_RSP   17 /* Create PDP Context Response */
#define GTP_UPDATE_PDP_REQ   18 /* Update PDP Context Request */
#define GTP_UPDATE_PDP_RSP   19 /* Update PDP Context Response */
#define GTP_DELETE_PDP_REQ   20 /* Delete PDP Context Request */
#define GTP_DELETE_PDP_RSP   21 /* Delete PDP Context Response */
/* 22-25 For future use. */ /* In version GTP 1 anonomous PDP context */
#define GTP_ERROR            26 /* Error Indication */
#define GTP_PDU_NOT_REQ      27 /* PDU Notification Request */
#define GTP_PDU_NOT_RSP      28 /* PDU Notification Response */
#define GTP_PDU_NOT_REJ_REQ  29 /* PDU Notification Reject Request */
#define GTP_PDU_NOT_REJ_RSP  30 /* PDU Notification Reject Response */
#define GTP_SUPP_EXT_HEADER  31 /* Supported Extension Headers Notification */
#define GTP_SND_ROUTE_REQ    32 /* Send Routeing Information for GPRS Request */
#define GTP_SND_ROUTE_RSP    33 /* Send Routeing Information for GPRS Response */
#define GTP_FAILURE_REQ      34 /* Failure Report Request */
#define GTP_FAILURE_RSP      35 /* Failure Report Response */
#define GTP_MS_PRESENT_REQ   36 /* Note MS GPRS Present Request */
#define GTP_MS_PRESENT_RSP   37 /* Note MS GPRS Present Response */
/* 38-47 For future use. */ 
#define GTP_IDEN_REQ         48 /* Identification Request */
#define GTP_IDEN_RSP         49 /* Identification Response */
#define GTP_SGSN_CONTEXT_REQ 50 /* SGSN Context Request */
#define GTP_SGSN_CONTEXT_RSP 51 /* SGSN Context Response */
#define GTP_SGSN_CONTEXT_ACK 52 /* SGSN Context Acknowledge */
#define GTP_FWD_RELOC_REQ    53 /* Forward Relocation Request */
#define GTP_FWD_RELOC_RSP    54 /* Forward Relocation Response */
#define GTP_FWD_RELOC_COMPL  55 /* Forward Relocation Complete */
#define GTP_RELOC_CANCEL_REQ 56 /* Relocation Cancel Request */
#define GTP_RELOC_CANCEL_RSP 57 /* Relocation Cancel Response */
#define GTP_FWD_SRNS         58 /* Forward SRNS Context */
#define GTP_FWD_RELOC_ACK    59 /* Forward Relocation Complete Acknowledge */
#define GTP_FWD_SRNS_ACK     60 /* Forward SRNS Context Acknowledge */
/* 61-239 For future use. */
#define GTP_DATA_TRAN_REQ   240 /* Data Record Transfer Request */
#define GTP_DATA_TRAN_RSP   241 /* Data Record Transfer Response */
/* 242-254 For future use. */
#define GTP_GPDU            255 /* G-PDU */


/* GTP information element cause codes from 29.060 v3.9.0 7.7 */
/*                                                            */
#define GTPCAUSE_REQ_IMSI                   0 /* Request IMSI */
#define GTPCAUSE_REQ_IMEI                   1 /* Request IMEI */
#define GTPCAUSE_REQ_IMSI_IMEI              2 /* Request IMSI and IMEI */
#define GTPCAUSE_NO_ID_NEEDED               3 /* No identity needed */
#define GTPCAUSE_MS_REFUSES_X               4 /* MS refuses */
#define GTPCAUSE_MS_NOT_RESP_X              5 /* MS is not GPRS responding */
#define GTPCAUSE_006                        6 /* For future use 6-48 */
#define GTPCAUSE_049                       49 /* Cause values reserved for GPRS charging protocol use (See GTP' in GSM 12.15) 49-63 */
#define GTPCAUSE_064                       64 /* For future use 64-127 */
#define GTPCAUSE_ACC_REQ                  128 /* Request accepted */
#define GTPCAUSE_129                      129 /* For future use 129-176 */
#define GTPCAUSE_177                      177 /* Cause values reserved for GPRS charging protocol use (See GTP' In GSM 12.15) 177-191 */
#define GTPCAUSE_NON_EXIST                192 /* Non-existent */
#define GTPCAUSE_INVALID_MESSAGE          193 /* Invalid message format */
#define GTPCAUSE_IMSI_NOT_KNOWN           194 /* IMSI not known */
#define GTPCAUSE_MS_DETACHED              195 /* MS is GPRS detached */
#define GTPCAUSE_MS_NOT_RESP              196 /* MS is not GPRS responding */
#define GTPCAUSE_MS_REFUSES               197 /* MS refuses */
#define GTPCAUSE_198                      198 /* For future use */
#define GTPCAUSE_NO_RESOURCES             199 /* No resources available */
#define GTPCAUSE_NOT_SUPPORTED            200 /* Service not supported */
#define GTPCAUSE_MAN_IE_INCORRECT         201 /* Mandatory IE incorrect */
#define GTPCAUSE_MAN_IE_MISSING           202 /* Mandatory IE missing */
#define GTPCAUSE_OPT_IE_INCORRECT         203 /* Optional IE incorrect */
#define GTPCAUSE_SYS_FAIL                 204 /* System failure */
#define GTPCAUSE_ROAMING_REST             205 /* Roaming Restriction */
#define GTPCAUSE_PTIMSI_MISMATCH          206 /* P-TMSI signature mismatch */
#define GTPCAUSE_CONN_SUSP                207 /* GPRS connection suspended */
#define GTPCAUSE_AUTH_FAIL                208 /* Authentication failure */
#define GTPCAUSE_USER_AUTH_FAIL           209 /* User authentication failed */
#define GTPCAUSE_CONTEXT_NOT_FOUND        210 /* Context not found */
#define GTPCAUSE_ADDR_OCCUPIED            211 /* All dynamic PDP addresses are occupied */
#define GTPCAUSE_NO_MEMORY                212 /* No memory is available */
#define GTPCAUSE_RELOC_FAIL               213 /* Relocation failure */
#define GTPCAUSE_UNKNOWN_MAN_EXTHEADER    214 /* Unknown mandatory extension header */
#define GTPCAUSE_SEM_ERR_TFT              215 /* Semantic error in the TFT operation */
#define GTPCAUSE_SYN_ERR_TFT              216 /* Syntactic error in the TFT operation */
#define GTPCAUSE_SEM_ERR_FILTER           217 /* Semantic errors in packet filter(s) */
#define GTPCAUSE_SYN_ERR_FILTER           218 /* Syntactic errors in packet filter(s) */
#define GTPCAUSE_MISSING_APN              219 /* Missing or unknown APN*/
#define GTPCAUSE_UNKNOWN_PDP              220 /* Unknown PDP address or PDP type */
#define GTPCAUSE_221                      221 /* For Future Use 221-240 */
#define GTPCAUSE_241                      241 /* Cause Values Reserved For Gprs Charging Protocol Use (See Gtp' In Gsm 12.15) 241-255 */



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

struct gtp0_header {    /*    Descriptions from 3GPP 09.60 */
  uint8_t  flags;      /* 01 bitfield, with typical values */
                        /*    000..... Version: 1 (0) */
                        /*    ...1111. Spare (7) */
                        /*    .......0 SNDCP N-PDU Number flag (0) */
  uint8_t  type;	        /* 02 Message type. T-PDU = 0xff */
  uint16_t length;	/* 03 Length (of G-PDU excluding header) */
  uint16_t seq;	        /* 05 Sequence Number */
  uint16_t flow;	        /* 07 Flow Label ( = 0 for signalling) */
  uint8_t  number;	/* 09 SNDCP N-PDU LCC Number ( 0 = 0xff) */
  uint8_t  spare1;	/* 10 Spare */
  uint8_t  spare2;	/* 11 Spare */
  uint8_t  spare3;	/* 12 Spare */
  uint64_t tid;	/* 13 Tunnel ID */
};                      /* 20 */

struct gtp1_header_short { /*    Descriptions from 3GPP 29060 */
  uint8_t  flags;         /* 01 bitfield, with typical values */
                           /*    001..... Version: 1 */
                           /*    ...1.... Protocol Type: GTP=1, GTP'=0 */
                           /*    ....0... Spare = 0 */
                           /*    .....0.. Extension header flag: 0 */
                           /*    ......0. Sequence number flag: 0 */
                           /*    .......0 PN: N-PDU Number flag */
  uint8_t  type;	   /* 02 Message type. T-PDU = 0xff */
  uint16_t length;	   /* 03 Length (of IP packet or signalling) */
  uint32_t tei;           /* 05 - 08 Tunnel Endpoint ID */
};

struct gtp1_header_long {  /*    Descriptions from 3GPP 29060 */
  uint8_t  flags;         /* 01 bitfield, with typical values */
                           /*    001..... Version: 1 */
                           /*    ...1.... Protocol Type: GTP=1, GTP'=0 */
                           /*    ....0... Spare = 0 */
                           /*    .....0.. Extension header flag: 0 */
                           /*    ......1. Sequence number flag: 1 */
                           /*    .......0 PN: N-PDU Number flag */
  uint8_t  type;	   /* 02 Message type. T-PDU = 0xff */
  uint16_t length;	   /* 03 Length (of IP packet or signalling) */
  uint32_t tei;	   /* 05 Tunnel Endpoint ID */
  uint16_t seq;	   /* 10 Sequence Number */
  uint8_t  npdu;	   /* 11 N-PDU Number */
  uint8_t  next;	   /* 12 Next extension header type. Empty = 0 */
};

struct gtp0_packet {
  struct gtp0_header h;
  uint8_t p[GTP_MAX];
} __attribute__((packed));

struct gtp1_packet_short {
  struct gtp1_header_short h;
  uint8_t p[GTP_MAX];
} __attribute__((packed));

struct gtp1_packet_long {
  struct gtp1_header_long h;
  uint8_t p[GTP_MAX];
} __attribute__((packed));

union gtp_packet {
  uint8_t flags;
  struct gtp0_packet        gtp0;
  struct gtp1_packet_short  gtp1s;
  struct gtp1_packet_long   gtp1l;
} __attribute__((packed));




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

struct gsn_t {
  /* Parameters related to the network interface */

  int         fd0;      /* GTP0 file descriptor */
  int         fd1c;     /* GTP1 control plane file descriptor */
  int         fd1u;     /* GTP0 user plane file descriptor */
  int       mode;       /* Mode of operation: GGSN or SGSN */
  struct in_addr gsnc;  /* IP address of this gsn for signalling */
  struct in_addr gsnu;  /* IP address of this gsn for user traffic */

  /* Parameters related to signalling messages */
  uint16_t seq_next;    /* Next sequence number to use */
  int seq_first;        /* First packet in queue (oldest timeout) */
  int seq_last;         /* Last packet in queue (youngest timeout) */

  unsigned char restart_counter; /* Increment on restart. Stored on disk */
  char *statedir;       /* Disk location for permanent storage */

  struct queue_t *queue_req;  /* Request queue */
  struct queue_t *queue_resp; /* Response queue */

  /* Call back functions */
  int (*cb_delete_context) (struct pdp_t*);
  int (*cb_create_context_ind) (struct pdp_t*);
  int (*cb_unsup_ind) (struct sockaddr_in *peer);
  int (*cb_extheader_ind) (struct sockaddr_in *peer);
  int (*cb_conf) (int type, int cause, struct pdp_t *pdp, void* cbp);
  int (*cb_data_ind) (struct pdp_t* pdp, void* pack, unsigned len);
  int (*cb_recovery) (struct sockaddr_in *peer, uint8_t recovery);

  /* Counters */
  
  uint64_t err_socket;      /* Number of socket errors */
  uint64_t err_readfrom;    /* Number of readfrom errors */
  uint64_t err_sendto;      /* Number of sendto errors */
  uint64_t err_memcpy;      /* Number of memcpy */
  uint64_t err_queuefull;   /* Number of times queue was full */
  uint64_t err_seq;         /* Number of seq out of range */
  uint64_t err_address;     /* GSN address conversion failed */
  uint64_t err_unknownpdp;  /* GSN address conversion failed */
  uint64_t err_unknowntid;  /* Application supplied unknown imsi+nsapi */
  uint64_t err_cause;       /* Unexpected cause value received */
  uint64_t err_outofpdp;    /* Out of storage for PDP contexts */

  uint64_t empty;       /* Number of empty packets */
  uint64_t unsup;       /* Number of unsupported version 29.60 11.1.1 */
  uint64_t tooshort;    /* Number of too short headers 29.60 11.1.2 */
  uint64_t unknown;     /* Number of unknown messages 29.60 11.1.3 */
  uint64_t unexpect;    /* Number of unexpected messages 29.60 11.1.4 */
  uint64_t dublicate;   /* Number of dublicate or unsolicited replies */
  uint64_t missing;     /* Number of missing information field messages */
  uint64_t incorrect;   /* Number of incorrect information field messages */
  uint64_t invalid;     /* Number of invalid message format messages */
};


/* External API functions */

extern const char* gtp_version();
extern int gtp_new(struct gsn_t **gsn, char *statedir, struct in_addr *listen,
		   int mode);

extern int gtp_free(struct gsn_t *gsn);

extern int gtp_newpdp(struct gsn_t *gsn, struct pdp_t **pdp,
		      uint64_t imsi, uint8_t nsapi);
extern int gtp_freepdp(struct gsn_t *gsn, struct pdp_t *pdp);

extern int gtp_create_context_req(struct gsn_t *gsn, struct pdp_t *pdp, 
				  void *cbp);

extern int gtp_set_cb_create_context_ind(struct gsn_t *gsn,
	     int (*cb_create_context_ind) (struct pdp_t* pdp));

extern int gtp_create_context_resp(struct gsn_t *gsn, struct pdp_t *pdp, 
				   int cause);

extern int gtp_update_context(struct gsn_t *gsn, struct pdp_t *pdp, 
			      void *cbp, struct in_addr* inetaddr);

extern int gtp_delete_context_req(struct gsn_t *gsn, struct pdp_t *pdp, 
				  void *cbp, int teardown);

extern int gtp_data_req(struct gsn_t *gsn, struct pdp_t *pdp,
			void *pack, unsigned len);

extern int gtp_set_cb_data_ind(struct gsn_t *gsn,
             int (*cb_data_ind) (struct pdp_t* pdp, void* pack, unsigned len));


extern int gtp_fd(struct gsn_t *gsn);
extern int gtp_decaps0(struct gsn_t *gsn);
extern int gtp_decaps1c(struct gsn_t *gsn);
extern int gtp_decaps1u(struct gsn_t *gsn);
extern int gtp_retrans(struct gsn_t *gsn);
extern int gtp_retranstimeout(struct gsn_t *gsn, struct timeval *timeout);

extern int gtp_set_cb_delete_context(struct gsn_t *gsn, 
	     int (*cb_delete_context) (struct pdp_t* pdp));
/*extern int gtp_set_cb_create_context(struct gsn_t *gsn,
  int (*cb_create_context) (struct pdp_t* pdp)); */

extern int gtp_set_cb_unsup_ind(struct gsn_t *gsn,
				int (*cb) (struct sockaddr_in *peer));

extern int gtp_set_cb_extheader_ind(struct gsn_t *gsn,
				    int (*cb) (struct sockaddr_in *peer));


extern int gtp_set_cb_conf(struct gsn_t *gsn,
             int (*cb) (int type, int cause, struct pdp_t* pdp, void *cbp));

int gtp_set_cb_recovery(struct gsn_t *gsn,
		        int (*cb) (struct sockaddr_in *peer, uint8_t recovery));

/* Internal functions (not part of the API */

extern int gtp_echo_req(struct gsn_t *gsn, int version, void *cbp,
			struct in_addr *inetaddrs);
extern int gtp_echo_resp(struct gsn_t *gsn, int version, 
			 struct sockaddr_in *peer, int fd,
			 void *pack, unsigned len);
extern int gtp_echo_ind(struct gsn_t *gsn, int version, 
			struct sockaddr_in *peer, int fd, 
			void *pack, unsigned len);
extern int gtp_echo_conf(struct gsn_t *gsn, int version, 
			 struct sockaddr_in *peer,
			 void *pack, unsigned len);

extern int gtp_unsup_req(struct gsn_t *gsn, int version, 
			 struct sockaddr_in *peer,
			 int fd, void *pack, unsigned len);
extern int gtp_unsup_ind(struct gsn_t *gsn, struct sockaddr_in *peer,
			 void *pack, unsigned len);

extern int gtp_create_pdp_resp(struct gsn_t *gsn, int version, 
			       struct pdp_t *pdp, uint8_t cause);

extern int gtp_create_pdp_ind(struct gsn_t *gsn, int version,
			      struct sockaddr_in *peer, int fd,
			      void *pack, unsigned len);

extern int gtp_create_pdp_conf(struct gsn_t *gsn, int version,
			       struct sockaddr_in *peer,
			       void *pack, unsigned len);

extern int gtp_update_pdp_req(struct gsn_t *gsn, int version, void *cbp,
			      struct in_addr* inetaddr, struct pdp_t *pdp);

extern int gtp_delete_pdp_req(struct gsn_t *gsn, int version, void *cbp,
			      struct pdp_t *pdp);

extern int gtp_delete_pdp_resp(struct gsn_t *gsn, int version,
			       struct sockaddr_in *peer, int fd,
			       void *pack, unsigned len, 
			       struct pdp_t *pdp, struct pdp_t *linked_pdp,
			       uint8_t cause, int teardown);

extern int gtp_delete_pdp_ind(struct gsn_t *gsn, int version,
			      struct sockaddr_in *peer, int fd,
			      void *pack, unsigned len);

extern int gtp_delete_pdp_conf(struct gsn_t *gsn, int version,
			       struct sockaddr_in *peer,
			       void *pack, unsigned len);


extern int ipv42eua(struct ul66_t *eua, struct in_addr *src);
extern int eua2ipv4(struct in_addr *dst, struct ul66_t *eua);
extern int gsna2in_addr(struct in_addr *dst, struct ul16_t *gsna);
extern int in_addr2gsna(struct ul16_t *gsna, struct in_addr *src);

#endif	/* !_GTP_H */
