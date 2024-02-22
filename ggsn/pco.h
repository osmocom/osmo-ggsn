#pragma once

#include <stdint.h>

#include <osmocom/gtp/pdp.h>

/* 3GPP TS 24.008 10.5.6.3 */
enum pco_protocols {
	PCO_P_LCP		= 0xC021,
	PCO_P_PAP		= 0xC023,
	PCO_P_CHAP		= 0xC223,
	PCO_P_IPCP		= 0x8021,
	PCO_P_PCSCF_ADDR	= 0x0001,
	PCO_P_IM_CN_SS_F	= 0x0002,
	PCO_P_DNS_IPv6_ADDR	= 0x0003,
	PCO_P_POLICY_CTRL_REJ	= 0x0004,	/* only in Network->MS */
	PCO_P_MS_SUP_NETREQ_BCI	= 0x0005,
	/* reserved */
	PCO_P_DSMIPv6_HA_ADDR	= 0x0007,
	PCO_P_DSMIPv6_HN_PREF	= 0x0008,
	PCO_P_DSMIPv6_v4_HA_ADDR= 0x0009,
	PCO_P_IP_ADDR_VIA_NAS	= 0x000a,	/* only MS->Network */
	PCO_P_IPv4_ADDR_VIA_DHCP= 0x000b,	/* only MS->Netowrk */
	PCO_P_PCSCF_IPv4_ADDR	= 0x000c,
	PCO_P_DNS_IPv4_ADDR	= 0x000d,
	PCO_P_MSISDN		= 0x000e,
	PCO_P_IFOM_SUPPORT	= 0x000f,
	PCO_P_IPv4_LINK_MTU	= 0x0010,
	PCO_P_MS_SUPP_LOC_A_TFT	= 0x0011,
	PCO_P_PCSCF_RESEL_SUP	= 0x0012,	/* only MS->Network */
	PCO_P_NBIFOM_REQ	= 0x0013,
	PCO_P_NBIFOM_MODE	= 0x0014,
	PCO_P_NONIP_LINK_MTU	= 0x0015,
	PCO_P_APN_RATE_CTRL_SUP	= 0x0016,
	PCO_P_PS_DATA_OFF_UE	= 0x0017,
	PCO_P_REL_DATA_SVC	= 0x0018,
};

struct pco_element {
	uint16_t protocol_id;	/* network byte order */
	uint8_t length;		/* length of data below */
	uint8_t data[0];
} __attribute__((packed));

/* RFC 1332 IP Control Protocol options, extensions in RFC 1877 */
enum ipcp_options {
	IPCP_OPT_IPADDR = 3, /* RFC 1332 3.3 */
	IPCP_OPT_PRIMARY_DNS = 129, /* RFC 1877 1.1 */
	IPCP_OPT_SECONDARY_DNS = 131,  /* RFC 1877 1.2 */
};

struct ipcp_option_hdr {
	uint8_t type;
	uint8_t len;
	uint8_t data[0];
} __attribute__ ((packed));

struct ipcp_hdr {
	uint8_t code;
	uint8_t id;
	uint16_t len;
	uint8_t options[0];
} __attribute__ ((packed));

/* RFC 1334, section 3.2. Packet Format */
struct pap_element {
	uint8_t code;
	uint8_t id;
	uint16_t len; /* length including header */
	uint8_t data[0];
} __attribute__((packed));

enum pap_code {
	PAP_CODE_AUTH_REQ = 1,
	PAP_CODE_AUTH_ACK = 2,
	PAP_CODE_AUTH_NAK = 3,
};

struct apn_ctx;
void process_pco(const struct apn_ctx *apn, struct pdp_t *pdp);
