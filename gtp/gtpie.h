/* 
 *  OpenGGSN - Gateway GPRS Support Node
 *  Copyright (C) 2002 Mondru AB.
 * 
 *  The contents of this file may be used under the terms of the GNU
 *  General Public License Version 2, provided that the above copyright
 *  notice and this permission notice is included in all copies or
 *  substantial portions of the software.
 * 
 *  The initial developer of the original code is
 *  Jens Jakobsen <jj@openggsn.org>
 * 
 *  Contributor(s):
 * 
 */

#ifndef _GTPIE_H
#define _GTPIE_H

/* Macroes for conversion between host and network byte order */
#define hton8(x)  (x)
#define ntoh8(x)  (x)
#define hton16(x) htons(x)
#define ntoh16(x) ntohs(x)
#define hton32(x) htonl(x)
#define ntoh32(x) ntohl(x)

#define GTPIE_SIZE 256          /* Max number of information elements */
#define GTPIE_MAX  0xffff       /* Max length of information elements */
#define GTPIE_MAX_TV 28         /* Max length of type value pair */
#define GTPIE_MAX_TLV 0xffff-3  /* Max length of TLV (GTP length is 16 bit) */

#define GTPIE_DEBUG 0           /* Print debug information */

/* GTP Information elements from 29.060 v3.9.0 7.7 Information Elements */
/* Also covers version 0. Note that version 0 6: QOS Profile was superceded *
 * by 135: QOS Profile in version 1 */

#define GTPIE_CAUSE           1 /* Cause 1 */
#define GTPIE_IMSI            2 /* International Mobile Subscriber Identity 8 */
#define GTPIE_RAI             3 /* Routing Area Identity (RAI) 8 */
#define GTPIE_TLLI            4 /* Temporary Logical Link Identity (TLLI) 4 */
#define GTPIE_P_TMSI          5 /* Packet TMSI (P-TMSI) 4 */
#define GTPIE_QOS_PROFILE0    6 /* Quality of Service Profile GTP version 0 3*/
                                /* 6-7 SPARE */ /* 6 is QoS Profile vers 0 */ 
#define GTPIE_REORDER         8 /* Reordering Required 1 */
#define GTPIE_AUTH_TRIPLET    9 /* Authentication Triplet 28 */
                                /* 10 SPARE */
#define GTPIE_MAP_CAUSE      11 /* MAP Cause 1 */
#define GTPIE_P_TMSI_S       12 /* P-TMSI Signature 3 */
#define GTPIE_MS_VALIDATED   13 /* MS Validated 1 */
#define GTPIE_RECOVERY       14 /* Recovery 1 */
#define GTPIE_SELECTION_MODE 15 /* Selection Mode 1 */
#define GTPIE_FL_DI          16 /* Flow Label Data I 2 */
#define GTPIE_TEI_DI         16 /* Tunnel Endpoint Identifier Data I 4 */
#define GTPIE_TEI_C          17 /* Tunnel Endpoint Identifier Control Plane 4 */
#define GTPIE_FL_C           17 /* Flow Label Signalling 2 */
#define GTPIE_TEI_DII        18 /* Tunnel Endpoint Identifier Data II 5 */
#define GTPIE_TEARDOWN       19 /* Teardown Ind 1 */
#define GTPIE_NSAPI          20 /* NSAPI 1 */
#define GTPIE_RANAP_CAUSE    21 /* RANAP Cause 1 */
#define GTPIE_RAB_CONTEXT    22 /* RAB Context 7 */
#define GTPIE_RP_SMS         23 /* Radio Priority SMS 1 */
#define GTPIE_RP             24 /* Radio Priority 1 */
#define GTPIE_PFI            25 /* Packet Flow Id 2 */
#define GTPIE_CHARGING_C     26 /* Charging Characteristics 2 */
#define GTPIE_TRACE_REF      27 /* Trace Reference 2 */
#define GTPIE_TRACE_TYPE     28 /* Trace Type 2 */
#define GTPIE_MS_NOT_REACH   29 /* MS Not Reachable Reason 1 */
                                /* 30-116 UNUSED */
/* 117-126 Reserved for the GPRS charging protocol (see GTP' in GSM 12.15) */
#define GTPIE_CHARGING_ID   127 /* Charging ID 4 */
#define GTPIE_EUA           128 /* End User Address */
#define GTPIE_MM_CONTEXT    129 /* MM Context */
#define GTPIE_PDP_CONTEXT   130 /* PDP Context */
#define GTPIE_APN           131 /* Access Point Name */
#define GTPIE_PCO           132 /* Protocol Configuration Options */
#define GTPIE_GSN_ADDR      133 /* GSN Address */
#define GTPIE_MSISDN        134 /* MS International PSTN/ISDN Number */
#define GTPIE_QOS_PROFILE   135 /* Quality of Service Profile */
#define GTPIE_AUTH_QUINTUP  136 /* Authentication Quintuplet */
#define GTPIE_TFT           137 /* Traffic Flow Template */
#define GTPIE_TARGET_INF    138 /* Target Identification */
#define GTPIE_UTRAN_TRANS   139 /* UTRAN Transparent Container */
#define GTPIE_RAB_SETUP     140 /* RAB Setup Information */
#define GTPIE_EXT_HEADER_T  141 /* Extension Header Type List */
#define GTPIE_TRIGGER_ID    142 /* Trigger Id */
#define GTPIE_OMC_ID        143 /* OMC Identity */
/* 239-250 Reserved for the GPRS charging protocol (see GTP' in GSM 12.15) */
#define GTPIE_CHARGING_ADDR 251 /* Charging Gateway Address */
/* 252-254 Reserved for the GPRS charging protocol (see GTP' in GSM 12.15) */
#define GTPIE_PRIVATE       255 /* Private Extension */

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


/* GTP information element structs in network order */
struct gtpie_ext {              /* Extension header */
  u_int8_t t;                   /* Type */
  u_int8_t l;                   /* Length */
  u_int8_t *p;                  /* Value */
} __attribute__((packed));

struct gtpie_tlv {              /* Type length value pair */
  u_int8_t t;                   /* Type */
  u_int16_t l;                  /* Length */
  u_int8_t v[GTPIE_MAX_TLV];    /* Value */
} __attribute__((packed));

struct gtpie_tv0 {              /* 1 byte type value pair */
  u_int8_t t;                   /* Type */
  u_int8_t v[GTPIE_MAX_TV];     /* Pointer to value */
}__attribute__((packed));

struct gtpie_tv1 {              /* 1 byte type value pair */
  u_int8_t t;                   /* Type */
  u_int8_t v;                   /* Value */
}__attribute__((packed));

struct gtpie_tv2 {              /* 2 byte type value pair */
  u_int8_t t;                   /* Type */
  u_int16_t v;                  /* Value */
}__attribute__((packed));

struct gtpie_tv4 {              /* 4 byte type value pair */
  u_int8_t t;                   /* Type */
  u_int32_t v;                  /* Value */
}__attribute__((packed));

struct gtpie_tv8 {              /* 8 byte type value pair */
  u_int8_t t;                   /* Type */
  u_int64_t v;                  /* Value */
}__attribute__((packed));


union gtpie_member {
  u_int8_t t;
  struct gtpie_ext ext;
  struct gtpie_tlv tlv;
  struct gtpie_tv0 tv0;
  struct gtpie_tv1 tv1;
  struct gtpie_tv2 tv2;
  struct gtpie_tv4 tv4;
  struct gtpie_tv8 tv8;
}__attribute__((packed));

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
  u_int8_t  type;
  u_int8_t  length;
}__attribute__((packed));

struct tlv2 {
  u_int8_t  type;
  u_int16_t length;
}__attribute__((packed));

extern int gtpie_tlv(void *p, int *length, int size,
		     u_int8_t t, int l, void *v);
extern int gtpie_tv0(void *p, int *length, int size, 
		     u_int8_t t, int l, u_int8_t *v);
extern int gtpie_tv1(void *p, int *length, int size, u_int8_t t, u_int8_t v);
extern int gtpie_tv2(void *p, int *length, int size, u_int8_t t, u_int16_t v);
extern int gtpie_tv4(void *p, int *length, int size, u_int8_t t, u_int32_t v);
extern int gtpie_tv8(void *p, int *length, int size, u_int8_t t, u_int64_t v);
extern int gtpie_getie(union gtpie_member* ie[], int type, int instance);
extern int gtpie_exist(union gtpie_member* ie[], int type, int instance);
extern int gtpie_gettlv(union gtpie_member* ie[], int type, int instance,
			int *length, void *dst, int size);
extern int gtpie_gettv0(union gtpie_member* ie[], int type, int instance,
			void *dst, int size);
extern int gtpie_gettv1(union gtpie_member* ie[], int type, int instance, 
			uint8_t *dst);
extern int gtpie_gettv2(union gtpie_member* ie[], int type, int instance, 
			uint16_t *dst);
extern int gtpie_gettv4(union gtpie_member* ie[], int type, int instance, 
			uint32_t *dst);

extern int gtpie_decaps(union gtpie_member* ie[], void *pack, unsigned len);
extern int gtpie_encaps(union gtpie_member* ie[], void *pack, unsigned *len);
extern int gtpie_encaps2(union gtpie_member ie[], int size,
		  void *pack, unsigned *len);


#endif	/* !_GTPIE_H */


