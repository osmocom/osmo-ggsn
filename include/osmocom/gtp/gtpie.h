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

#ifndef _GTPIE_H
#define _GTPIE_H

#include <arpa/inet.h>

/* Macroes for conversion between host and network byte order */
#define hton8(x)  (x)
#define ntoh8(x)  (x)
#define hton16(x) htons(x)
#define ntoh16(x) ntohs(x)
#define hton32(x) htonl(x)
#define ntoh32(x) ntohl(x)

#if BYTE_ORDER == LITTLE_ENDIAN
static __inline uint64_t hton64(uint64_t q)
{
	register uint32_t u, l;
	u = q >> 32;
	l = (uint32_t) q;

	return htonl(u) | ((uint64_t) htonl(l) << 32);
}

#define ntoh64(_x)        hton64(_x)

#elif BYTE_ORDER == BIG_ENDIAN

#define hton64(_x)        (_x)
#define ntoh64(_x)        hton64(_x)

#else
#error  "Please fix <machine/endian.h>"
#endif

#define GTPIE_SIZE 256		/* Max number of information elements */
#define GTPIE_MAX  0xffff	/* Max length of information elements */
#define GTPIE_MAX_TV 28		/* Max length of type value pair */
#define GTPIE_MAX_TLV 0xffff-3	/* Max length of TLV (GTP length is 16 bit) */

#define GTPIE_DEBUG 0		/* Print debug information */

/* GTP Information elements from 29.060 v11.8.0 7.7 Information Elements */
/* Also covers version 0. Note that version 0 6: QOS Profile was superceded *
 * by 135: QOS Profile in version 1 */

#define GTPIE_CAUSE           1	/* Cause 1 */
#define GTPIE_IMSI            2	/* International Mobile Subscriber Identity 8 */
#define GTPIE_RAI             3	/* Routing Area Identity (RAI) 8 */
#define GTPIE_TLLI            4	/* Temporary Logical Link Identity (TLLI) 4 */
#define GTPIE_P_TMSI          5	/* Packet TMSI (P-TMSI) 4 */
#define GTPIE_QOS_PROFILE0    6	/* Quality of Service Profile GTP version 0 3 */
						/* 6-7 SPARE *//* 6 is QoS Profile vers 0 */
#define GTPIE_REORDER         8	/* Reordering Required 1 */
#define GTPIE_AUTH_TRIPLET    9	/* Authentication Triplet 28 */
				/* 10 SPARE */
#define GTPIE_MAP_CAUSE      11	/* MAP Cause 1 */
#define GTPIE_P_TMSI_S       12	/* P-TMSI Signature 3 */
#define GTPIE_MS_VALIDATED   13	/* MS Validated 1 */
#define GTPIE_RECOVERY       14	/* Recovery 1 */
#define GTPIE_SELECTION_MODE 15	/* Selection Mode 1 */
#define GTPIE_FL_DI          16	/* Flow Label Data I 2 */
#define GTPIE_TEI_DI         16	/* Tunnel Endpoint Identifier Data I 4 */
#define GTPIE_TEI_C          17	/* Tunnel Endpoint Identifier Control Plane 4 */
#define GTPIE_FL_C           17	/* Flow Label Signalling 2 */
#define GTPIE_TEI_DII        18	/* Tunnel Endpoint Identifier Data II 5 */
#define GTPIE_TEARDOWN       19	/* Teardown Ind 1 */
#define GTPIE_NSAPI          20	/* NSAPI 1 */
#define GTPIE_RANAP_CAUSE    21	/* RANAP Cause 1 */
#define GTPIE_RAB_CONTEXT    22	/* RAB Context 7 */
#define GTPIE_RP_SMS         23	/* Radio Priority SMS 1 */
#define GTPIE_RP             24	/* Radio Priority 1 */
#define GTPIE_PFI            25	/* Packet Flow Id 2 */
#define GTPIE_CHARGING_C     26	/* Charging Characteristics 2 */
#define GTPIE_TRACE_REF      27	/* Trace Reference 2 */
#define GTPIE_TRACE_TYPE     28	/* Trace Type 2 */
#define GTPIE_MS_NOT_REACH   29	/* MS Not Reachable Reason 1 */
				/* 30-116 UNUSED */
/* 117-126 Reserved for the GPRS charging protocol (see GTP' in GSM 12.15 / 32.295) */
#define GTPIE_CHARGING_ID   127	/* Charging ID 4 */
#define GTPIE_EUA           128	/* End User Address */
#define GTPIE_MM_CONTEXT    129	/* MM Context */
#define GTPIE_PDP_CONTEXT   130	/* PDP Context */
#define GTPIE_APN           131	/* Access Point Name */
#define GTPIE_PCO           132	/* Protocol Configuration Options */
#define GTPIE_GSN_ADDR      133	/* GSN Address */
#define GTPIE_MSISDN        134	/* MS International PSTN/ISDN Number */
#define GTPIE_QOS_PROFILE   135	/* Quality of Service Profile */
#define GTPIE_AUTH_QUINTUP  136	/* Authentication Quintuplet */
#define GTPIE_TFT           137	/* Traffic Flow Template */
#define GTPIE_TARGET_INF    138	/* Target Identification */
#define GTPIE_UTRAN_TRANS   139	/* UTRAN Transparent Container */
#define GTPIE_RAB_SETUP     140	/* RAB Setup Information */
#define GTPIE_EXT_HEADER_T  141	/* Extension Header Type List */
#define GTPIE_TRIGGER_ID    142	/* Trigger Id */
#define GTPIE_OMC_ID        143	/* OMC Identity */
#define GTPIE_RAN_T_CONTAIN 144	/* RAN Transparent Container */
#define GTPIE_PDP_CTX_PRIO  145	/* PDP Context Prioritization */
#define GTPIE_ADDL_RAB_S_I  146	/* Additional RAB Setup Information */
#define GTPIE_SGSN_NUMBER   147	/* SGSN Number */
#define GTPIE_COMMON_FLAGS  148	/* Common Flags */
#define GTPIE_APN_RESTR     149	/* APN Restriction */
#define GTPIE_R_PRIO_LCS    150	/* Radio Priority LCS */
#define GTPIE_RAT_TYPE      151	/* Radio Access Technology Type */
#define GTPIE_USER_LOC      152	/* User Location Information  */
#define GTPIE_MS_TZ         153	/* MS Time Zone */
#define GTPIE_IMEI_SV       154	/* IMEI Software Version */
#define GTPIE_CML_CHG_I_CT  155	/* CAMEL Charging Information Container */
#define GTPIE_MBMS_UE_CTX   156	/* MSMS UE Context */
#define GTPIE_TMGI          157	/* Temporary Mobile Group Identity (TMGI) */
#define GTPIE_RIM_ROUT_ADDR 158	/* RIM Routing Address */
#define GTPIE_MBMS_PCO      159	/* MBMS Protocol Configuratin Options */
#define GTPIE_MBMS_SA       160	/* MBMS Service Area */
#define GTPIE_SRNC_PDCP_CTX 161	/* Source RNC PDCP Context Info */
#define GTPIE_ADDL_TRACE    162	/* Additional Trace Info */
#define GTPIE_HOP_CTR       163	/* Hop Counter */
#define GTPIE_SEL_PLMN_ID   164	/* Selected PLMN ID */
#define GTPIE_MBMS_SESS_ID  165	/* MBMS Session Identifier */
#define GTPIE_MBMS_2_3G_IND 166	/* MBMS 2G/3G Indicator */
#define GTPIE_ENH_NSAPI     167	/* Enhanced NSAPI */
#define GTPIE_MBMS_SESS_DUR 168	/* MBMS Session Duration */
#define GTPIE_A_MBMS_TRAC_I 169	/* Additional MBMS Trace Info */
#define GTPIE_MBMS_S_REP_N  170	/* MBMS Session Repetition Number */
#define GTPIE_MBMS_TTDT     171	/* MBMS Time To Data Transfer */
#define GTPIE_PS_HO_REQ_CTX 172	/* PS Handover Request Context */
#define GTPIE_BSS_CONTAINER 173	/* BSS Container */
#define GTPIE_CELL_ID       174	/* Cell Identification */
#define GTPIE_PDU_NUMBERS   175	/* PDU Numbers */
#define GTPIE_BSSGP_CAUSE   176	/* BSSGP Cause */
#define GTPIE_RQD_MBMS_BCAP 177	/* Required MBMS Bearer Capabilities */
#define GTPIE_RIM_RA_DISCR  178	/* RIM Routing Address Discriminator */
#define GTPIE_L_SETUP_PFCS  179	/* List of set-up PFCs */
#define GTPIE_PS_HO_XID_PAR 180	/* PS Handover XID Parameters */
#define GTPIE_MS_CHG_REP_A  181	/* MS Info Change Reporting Action */
#define GTPIE_DIR_TUN_FLAGS 182	/* Direct Tunnel Flags */
#define GTPIE_CORREL_ID     183	/* Correlation-ID */
#define GTPIE_BCM           184	/* Bearer control mode */
#define GTPIE_MBMS_FLOWI    185	/* MBMS Flow Identifier */
#define GTPIE_MBMS_MC_DIST  186	/* MBMS IP Multicast Distribution */
#define GTPIE_MBMS_DIST_ACK 187	/* MBMS Distribution Acknowledgement */
#define GTPIE_R_IRAT_HO_INF 188	/* Reliable INTER RAT HANDOVER INFO */
#define GTPIE_RFSP_IDX      189	/* RFSP Index */
#define GTPIE_FQDN          190	/* FQDN */
#define GTPIE_E_ALL_PRIO_1  191	/* Evolvd Allocation/Retention Priority I */
#define GTPIE_E_ALL_PRIO_2  192	/* Evolvd Allocation/Retention Priority II */
#define GTPIE_E_CMN_FLAGS   193	/* Extended Common Flags */
#define GTPIE_U_CSG_INFO    194	/* User CSG Information (UCI) */
#define GTPIE_CSG_I_REP_ACT 195	/* CSG Information Reporting Action */
#define GTPIE_CSG_ID        196	/* CSG ID */
#define GTPIE_CSG_MEMB_IND  197	/* CSG Membership Indication (CMI) */
#define GTPIE_AMBR          198	/* Aggregate Maximum Bit Rate (AMBR) */
#define GTPIE_UE_NET_CAPA   199	/* UE Network Capability */
#define GTPIE_UE_AMBR       200	/* UE-AMBR */
#define GTPIE_APN_AMBR_NS   201	/* APN-AMBR with NSAPI */
#define GTPIE_GGSN_BACKOFF  202	/* GGSN Back-Off Time */
#define GTPIE_S_PRIO_IND    203	/* Signalling Priority Indication */
#define GTPIE_S_PRIO_IND_NS 204	/* Signalling Priority Indication with NSAPI */
#define GTPIE_H_BR_16MBPS_F 205	/* Higher Bitrates than 16 Mbps flag */
/* 206: Reserved */
#define GTPIE_A_MMCTX_SRVCC 207	/* Additional MM context for SRVCC */
#define GTPIE_A_FLAGS_SRVCC 208	/* Additional flags fro SRVC */
#define GTPIE_STN_SR        209	/* STN-SR */
#define GTPIE_C_MSISDN      210	/* C-MSISDN */
#define GTPIE_E_RANAP_CAUSE 211	/* Extended RANAP Cause */
#define GTPIE_ENODEB_ID     212	/* eNodeB ID */
#define GTPIE_SEL_MODE_NS   213	/* Selection Mode with NSAPI */
#define GTPIE_ULI_TIMESTAMP 214	/* ULI Timestamp */
/* 215-238 Spare. For future use */
/* 239-250 Reserved for the GPRS charging protocol (see GTP' in GSM 12.15 / 32.295) */
#define GTPIE_CHARGING_ADDR 251	/* Charging Gateway Address */
/* 252-254 Reserved for the GPRS charging protocol (see GTP' in GSM 12.15 / 32.295) */
#define GTPIE_PRIVATE       255	/* Private Extension */

/* GTP information element structs in network order */
struct gtpie_ext {		/* Extension header */
	uint8_t t;		/* Type */
	uint8_t l;		/* Length */
	uint8_t *p;		/* Value */
} __attribute__ ((packed));

struct gtpie_tlv {		/* Type length value pair */
	uint8_t t;		/* Type */
	uint16_t l;		/* Length */
	uint8_t v[GTPIE_MAX_TLV];	/* Value */
} __attribute__ ((packed));

struct gtpie_tv0 {		/* 1 byte type value pair */
	uint8_t t;		/* Type */
	uint8_t v[GTPIE_MAX_TV];	/* Pointer to value */
} __attribute__ ((packed));

struct gtpie_tv1 {		/* 1 byte type value pair */
	uint8_t t;		/* Type */
	uint8_t v;		/* Value */
} __attribute__ ((packed));

struct gtpie_tv2 {		/* 2 byte type value pair */
	uint8_t t;		/* Type */
	uint16_t v;		/* Value */
} __attribute__ ((packed));

struct gtpie_tv4 {		/* 4 byte type value pair */
	uint8_t t;		/* Type */
	uint32_t v;		/* Value */
} __attribute__ ((packed));

struct gtpie_tv8 {		/* 8 byte type value pair */
	uint8_t t;		/* Type */
	uint64_t v;		/* Value */
} __attribute__ ((packed));

union gtpie_member {
	uint8_t t;
	struct gtpie_ext ext;
	struct gtpie_tlv tlv;
	struct gtpie_tv0 tv0;
	struct gtpie_tv1 tv1;
	struct gtpie_tv2 tv2;
	struct gtpie_tv4 tv4;
	struct gtpie_tv8 tv8;
} __attribute__ ((packed));

/*
cause
imsi
rai
tlli
p_tmsi
qos_profile0
reorder
auth
map_cause
p_tmsi_s
ms_validated
recovery
selection_mode
tei_di
tei_c
tei_dii
teardown
nsapi
ranap_cause
rab_context
rp_sms
rp
pfi
charging_c
trace_ref
trace_type
ms_not_reach
charging_id
eua
mm_context
pdp_context
apn
pco
gsn_addr
msisdn
qos_profile
auth
tft
target_inf
utran_trans
rab_setup
ext_header_t
trigger_id
omc_id
charging_addr
private
*/

struct tlv1 {
	uint8_t type;
	uint8_t length;
} __attribute__ ((packed));

struct tlv2 {
	uint8_t type;
	uint16_t length;
} __attribute__ ((packed));

extern int gtpie_tlv(void *p, unsigned int *length, unsigned int size,
		     uint8_t t, int l, const void *v);
extern int gtpie_tv0(void *p, unsigned int *length, unsigned int size,
		     uint8_t t, int l, const uint8_t * v);
extern int gtpie_tv1(void *p, unsigned int *length, unsigned int size,
		     uint8_t t, uint8_t v);
extern int gtpie_tv2(void *p, unsigned int *length, unsigned int size,
		     uint8_t t, uint16_t v);
extern int gtpie_tv4(void *p, unsigned int *length, unsigned int size,
		     uint8_t t, uint32_t v);
extern int gtpie_tv8(void *p, unsigned int *length, unsigned int size,
		     uint8_t t, uint64_t v);
extern int gtpie_getie(union gtpie_member * const ie[], int type, int instance);
extern int gtpie_exist(union gtpie_member * const ie[], int type, int instance);
extern int gtpie_gettlv(union gtpie_member * const ie[], int type, int instance,
			unsigned int *length, void *dst, unsigned int size);
extern int gtpie_gettv0(union gtpie_member * const ie[], int type, int instance,
			void *dst, unsigned int size);
extern int gtpie_gettv1(union gtpie_member * const ie[], int type, int instance,
			uint8_t * dst);
extern int gtpie_gettv2(union gtpie_member * const ie[], int type, int instance,
			uint16_t * dst);
extern int gtpie_gettv4(union gtpie_member * const ie[], int type, int instance,
			uint32_t * dst);
extern int gtpie_gettv8(union gtpie_member * const ie[], int type, int instance,
			uint64_t * dst);

extern int gtpie_decaps(union gtpie_member *ie[], int version,
			const void *pack, unsigned len);
extern int gtpie_encaps(union gtpie_member * const ie[], void *pack, unsigned *len);
extern int gtpie_encaps2(const union gtpie_member ie[], unsigned int size,
			 void *pack, unsigned *len);
extern int gtpie_encaps3(union gtpie_member * const ie[], unsigned int ie_len,
		  void *pack, unsigned pack_len, unsigned *encoded_len);

#endif /* !_GTPIE_H */
