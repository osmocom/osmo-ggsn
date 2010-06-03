/* 
 *  OpenGGSN - Gateway GPRS Support Node
 *  Copyright (C) 2002, 2003 Mondru AB.
 * 
 *  The contents of this file may be used under the terms of the GNU
 *  General Public License Version 2, provided that the above copyright
 *  notice and this permission notice is included in all copies or
 *  substantial portions of the software.
 * 
 */

#ifndef _PDP_H
#define _PDP_H

#define PDP_MAX 1024             /* Max number of PDP contexts */
#define PDP_MAXNSAPI 16          /* Max number of NSAPI */

#define PDP_DEBUG 0              /* Print debug information */

/* GTP Information elements from 29.060 v3.9.0 7.7 Information Elements */
/* Also covers version 0. Note that version 0 6: QOS Profile was superceded *
 * by 135: QOS Profile in version 1 */


struct sl_t {
unsigned int l;
char *v;
};

struct ul_t {
unsigned int l;
unsigned char *v;
};

struct ul16_t {
unsigned int l;
unsigned char v[16];
};

struct ul66_t {
unsigned int l;
unsigned char v[66];
};

struct ul255_t {
unsigned int l;
unsigned char v[255];
};


/* *****************************************************************
 * Information storage for each PDP context
 *
 * Information storage for each PDP context is defined in 23.060
 * section 13.3 and 03.60. Includes IMSI, MSISDN, APN, PDP-type,
 * PDP-address (IP address), sequence numbers, charging ID.  For the
 * SGSN it also includes radio related mobility information.
 *
 * The following structure is a combination of the storage
 * requirements for each PDP context for the GGSN and SGSN.  It
 * contains both 23.060 as well as 03.60 parameters.  Information is
 * stored in the format for information elements described in 29.060
 * and 09.60.
 * 31 * 4 + 15 structs +  = 120 + 15 structs ~ 2k / context
 * Structs: IP address 16+4 bytes (6), APN 255 bytes (2)
 * QOS: 255 bytes (3), msisdn 16 bytes (1), 
 *
 * TODO: We need to consider who manages the pdp_t hash tables
 * Is it gtp_lib, or is it the application?
 * I suppose that it will be gtp_lib. 
 * SGSN will ask gtplib for new pdp_t. Fill out the fields,
 * and pass it on to gtp_create_pdp_req.
 * GGSN will receive gtp_create_pdp_ind, create new pdp_t and
 * send responce to SGSN.
 * SGSN will receive response and gtplib will find the 
 * original pdp_t corresponding to the request. This will be
 * passed on to the application.
 * Eventually the SGSN will close the connection, and the
 * pdp_t will be freed by gtplib in SGSN and GGSN
 * This means that gtplib need to have functions to
 * allocate, free, sort and find pdp_t
 * (newpdp, freepdp, getpdp)
 * Hash tables: TID, IMSI, IP etc.) 
 *
 *
 * Secondary PDP Context Activation Procedure 
 *
 * With GTP version 1 it is possible to establish multiple PDP
 * contexts with the same IP address. With this scheme the first
 * context is established as normal. Following contexts are
 * established by referencing one of the allready existing ones.  Each
 * context is uniquely identified by IMSI and NSAPI. Each context is
 * allocated an tei_di, but they all share the same tei_c.
 *
 * For Delete PDP Context the context is referenced by tei_c and
 * nsapi. As an option it is possible to include a teardown indicater,
 * in which case all PDP contexts with the same tei_c (IP address) are
 * deleted.
 *
 * For Update PDP Context the context is normally referenced by tei_c
 * and nsapi. If moving from GTP0 to GTP1 during an update the context
 * is referenced instead by IMSI and NSAPI.
 *****************************************************************/

struct pdp_t {
  /* Parameter determining if this PDP is in use. */
  uint8_t     inuse;    /* 0=free. 1=used by somebody */

  /* Pointers related to hash tables */
  struct pdp_t *tidnext;
  struct pdp_t *ipnext;

  /* Parameters shared by all PDP context belonging to the same MS */

  void *ipif;           /* IP network interface */
  void *peer;           /* Pointer to peer protocol */
  void *asap;           /* Application specific service access point */

  uint64_t    imsi;     /* International Mobile Subscriber Identity.*/
  struct ul16_t msisdn; /* The basic MSISDN of the MS. */
  uint8_t     mnrg;     /* Indicates whether the MS is marked as not reachable for PS at the HLR. (1 bit, not transmitted) */
  uint8_t     cch_sub;  /* The charging characteristics for the MS, e.g. normal, prepaid, flat-rate, and/or hot billing subscription. (not transmitted) */
  uint16_t    traceref; /* Identifies a record or a collection of records for a particular trace. */
  uint16_t    tracetype;/* Indicates the type of trace. */
  struct ul_t triggerid;/* Identifies the entity that initiated the trace. */
  struct ul_t omcid;    /* Identifies the OMC that shall receive the trace record(s). */
  uint8_t     rec_hlr;  /* Indicates if HLR or VLR is performing database recovery. (1 bit, not transmitted) */

  /* Parameters specific to each individual PDP context */

  uint8_t     pdp_id;   /* Index of the PDP context. (PDP context identifier) */
  uint8_t     pdp_state;/* PDP State Packet data protocol state, INACTIVE or ACTIVE. (1 bit, not transmitted) */
  /* struct ul_t pdp_type; * PDP type; e.g. PPP or IP. */
  /* struct ul_t pdp_addr; * PDP address; e.g. an IP address. */
  struct ul66_t eua;    /* End user address. PDP type and address combined */
  uint8_t     pdp_dyn;  /* Indicates whether PDP Address is static or dynamic. (1 bit, not transmitted) */
  struct ul255_t apn_req;/* The APN requested. */
  struct ul255_t apn_sub;/* The APN received from the HLR. */
  struct ul255_t apn_use;/* The APN Network Identifier currently used. */
  uint8_t     nsapi;    /* Network layer Service Access Point Identifier. (4 bit) */
  uint16_t    ti;       /* Transaction Identifier. (4 or 12 bit) */

  uint32_t    teic_own; /* (Own Tunnel Endpoint Identifier Control) */
  uint32_t    teid_own; /* (Own Tunnel Endpoint Identifier Data I) */
  uint32_t    teic_gn;  /* Tunnel Endpoint Identifier for the Gn and Gp interfaces. (Control plane) */
  uint32_t    teid_gn;  /* Tunnel Endpoint Identifier for the Gn and Gp interfaces. (Data I) */
  uint32_t    tei_iu;   /* Tunnel Endpoint Identifier for the Iu interface. */

  uint16_t    fllc;     /* (Local Flow Label Control, gtp0) */
  uint16_t    fllu;     /* (Local Flow Label Data I, gtp0) */
  uint16_t    flrc;     /* (Remote gn/gp Flow Label Control, gtp0) */
  uint16_t    flru;     /* (Remote gn/gp Flow Label Data I, gtp0) */

  struct ul255_t tft;   /* Traffic flow template. */
  /*struct ul16_t sgsnc;  * The IP address of the SGSN currently serving this MS. (Control plane) */
  /*struct ul16_t sgsnu;  * The IP address of the SGSN currently serving this MS. (User plane) */
  /*struct ul16_t ggsnc;  * The IP address of the GGSN currently used. (Control plane) */
  /*struct ul16_t ggsnu;  * The IP address of the GGSN currently used. (User plane) */

  struct ul16_t gsnlc;  /* The IP address of the local GSN. (Control plane) */
  struct ul16_t gsnlu;  /* The IP address of the local GSN. (User plane) */
  struct ul16_t gsnrc;  /* The IP address of the remote GSN. (Control plane) */
  struct ul16_t gsnru;  /* The IP address of the remote GSN. (User plane) */

  uint8_t  vplmn_allow; /* Specifies whether the MS is allowed to use the APN in the domain of the HPLMN only, or additionally the APN in the domain of the VPLMN. (1 bit) */
  uint8_t qos_sub0[3];  /* The quality of service profile subscribed. */
  uint8_t qos_req0[3];  /* The quality of service profile requested. */
  uint8_t qos_neg0[3];  /* The quality of service profile negotiated. */
  struct ul255_t qos_sub;  /* The quality of service profile subscribed. */
  struct ul255_t qos_req;  /* The quality of service profile requested. */
  struct ul255_t qos_neg;  /* The quality of service profile negotiated. */
  uint8_t     radio_pri;/* The RLC/MAC radio priority level for uplink user data transmission. (4 bit) */
  uint16_t    flow_id;  /*  Packet flow identifier. */
  /* struct ul_t bssqos_neg; * The aggregate BSS quality of service profile negotiated for the packet flow that this PDP context belongs to. (NOT GTP)*/
  uint8_t     sndcpd;   /* SNDCP sequence number of the next downlink N-PDU to be sent to the MS. */
  uint8_t     sndcpu;   /* SNDCP sequence number of the next uplink N-PDU expected from the MS. */
  uint8_t     rec_sgsn; /* Indicates if the SGSN is performing database recovery. (1 bit, not transmitted) */
/*  uint16_t    gtpsnd;    GTP-U sequence number of the next downlink N-PDU to be sent to the SGSN / received from the GGSN. */
/*  uint16_t    gtpsnu;    GTP-U sequence number of the next uplink N-PDU to be received from the SGSN / sent to the GGSN */
  uint16_t    gtpsntx;  /* GTP-U sequence number of the next downlink N-PDU to be sent (09.60 section 8.1.1.1) */
  uint16_t    gtpsnrx;  /* GTP-U sequence number of the next uplink N-PDU to be received (09.60 section 8.1.1.1) */
  uint8_t     pdcpsndd; /* Sequence number of the next downlink in-sequence PDCP-PDU to be sent to the MS. */
  uint8_t     pdcpsndu; /* Sequence number of the next uplink in-sequence PDCP-PDU expected from the MS. */
  uint32_t    cid;      /* Charging identifier, identifies charging records generated by SGSN and GGSN. */
  uint16_t    cch_pdp;  /* The charging characteristics for this PDP context, e.g. normal, prepaid, flat-rate, and/or hot billing. */
  struct ul16_t rnc_addr;/* The IP address of the RNC currently used. */
  uint8_t     reorder;  /* Specifies whether the GGSN shall reorder N-PDUs received from the SGSN / Specifies whether the SGSN shall reorder N-PDUs before delivering the N-PSUs to the MS. (1 bit) */
  struct ul255_t pco_req;  /* Requested packet control options. */
  struct ul255_t pco_neg;  /* Negotiated packet control options. */
  uint32_t    selmode;  /* Selection mode. */

  /* Additional parameters used by library */

  int         version;  /* Protocol version currently in use. 0 or 1 */

  uint64_t    tid;      /* Combination of imsi and nsapi */
  uint16_t   seq;      /* Sequence number of last request */
  struct sockaddr_in sa_peer; /* Address of last request */
  int fd;               /* File descriptor request was received on */

  uint8_t teic_confirmed; /* 0: Not confirmed. 1: Confirmed */

  /* Parameters used for secondary activation procedure (tei data) */
  /* If (secondary == 1) then teic_own indicates linked PDP context */
  uint8_t secondary;    /* 0: Primary (control). 1: Secondary (data only) */
  uint8_t nodata;       /* 0: User plane PDP context. 1: No user plane */

  /* Secondary contexts of this primary context */
  uint32_t secondary_tei[PDP_MAXNSAPI]; 

  /* IP address used for Create and Update PDP Context Requests */
  struct in_addr hisaddr0;       /* Server address */
  struct in_addr hisaddr1;       /* Server address */

  /* to be used by libgtp callers/users (to attach their own private state) */
  void *priv;
};


/* functions related to pdp_t management */
int pdp_init();
int pdp_newpdp(struct pdp_t **pdp, uint64_t imsi, uint8_t nsapi,
	       struct pdp_t *pdp_old);
int pdp_freepdp(struct pdp_t *pdp);
int pdp_getpdp(struct pdp_t **pdp);

int pdp_getgtp0(struct pdp_t **pdp, uint16_t fl);
int pdp_getgtp1(struct pdp_t **pdp, uint32_t tei);

int pdp_getimsi(struct pdp_t **pdp, uint64_t imsi, uint8_t nsapi);

int pdp_tidhash(uint64_t tid);
int pdp_tidset(struct pdp_t *pdp, uint64_t tid);
int pdp_tiddel(struct pdp_t *pdp);
int pdp_tidget(struct pdp_t **pdp, uint64_t tid);


/*
int pdp_iphash(void* ipif, struct ul66_t *eua);
int pdp_ipset(struct pdp_t *pdp, void* ipif, struct ul66_t *eua);
int pdp_ipdel(struct pdp_t *pdp);
int pdp_ipget(struct pdp_t **pdp, void* ipif, struct ul66_t *eua);
*/

int pdp_ntoeua(struct in_addr *src, struct ul66_t *eua);
int pdp_euaton(struct ul66_t *eua, struct in_addr *dst);
uint64_t pdp_gettid(uint64_t imsi, uint8_t nsapi);
int ulcpy(void* dst, void* src, size_t size);

#endif	/* !_PDP_H */
