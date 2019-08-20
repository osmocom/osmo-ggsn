/*
 * PCO parsing related code
 * Copyright (C) 2002, 2003, 2004 Mondru AB.
 * Copyright (C) 2017-2019 by Harald Welte <laforge@gnumonks.org>
 * Copyright (C) 2019 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

#include <unistd.h>
#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>

#include "pco.h"
#include "ggsn.h"

/* determine if IPCP contains given option */
static const uint8_t *ipcp_contains_option(const struct ipcp_hdr *ipcp, size_t ipcp_len,
					   enum ipcp_options opt, size_t opt_minlen)
{
	const uint8_t *cur_opt = ipcp->options;

	/* iterate over Options and check if protocol contained */
	while (cur_opt + sizeof(struct ipcp_option_hdr) <= (uint8_t*)ipcp + ipcp_len) {
		const struct ipcp_option_hdr *cur_opt_hdr = (const struct ipcp_option_hdr *)cur_opt;
		/* length value includes 2 bytes type/length */
		if (cur_opt_hdr->len < sizeof(struct ipcp_option_hdr))
			return NULL;
		if (cur_opt_hdr->type == opt &&
		    cur_opt_hdr->len >= sizeof(struct ipcp_option_hdr) + opt_minlen)
			return cur_opt;
		cur_opt += cur_opt_hdr->len;
	}
	return NULL;
}


static const char *pap_welcome = "Welcome to OsmoGGSN " PACKAGE_VERSION;

/* Handle PAP protocol according to RFC 1334 */
static void process_pco_element_pap(const struct pco_element *pco_in, struct msgb *resp,
				    const struct apn_ctx *apn, struct pdp_t *pdp)
{
	const struct pap_element *pap_in = (const struct pap_element *) pco_in->data;
	uint16_t pap_in_len;
	uint8_t peer_id_len;
	const uint8_t *peer_id;
	unsigned int pap_welcome_len;
	uint8_t pap_out_size;
	struct pap_element *pap_out;

	if (pco_in->length < sizeof(struct pap_element))
		goto ret_broken;

	pap_in_len = osmo_load16be(&pap_in->len);
	if (pco_in->length < pap_in_len)
		goto ret_broken;
	/* "pco_in->length > pap_in_len" is allowed: RFC1334 2.2 states:
	   "Octets outside the range of the Length field should be treated as
	   Data Link Layer padding and should be ignored on reception."
	 */

	switch (pap_in->code) {
	case PAP_CODE_AUTH_REQ:
		if (pap_in_len < sizeof(struct pap_element) + 1)
			goto ret_broken_auth;
		peer_id_len = pap_in->data[0];
		if (pap_in_len < sizeof(struct pap_element) + 1 + peer_id_len)
			goto ret_broken_auth;
		peer_id = &pap_in->data[1];
		LOGPPDP(LOGL_DEBUG, pdp, "PCO PAP PeerId = %s, ACKing\n",
			osmo_quote_str((const char *)peer_id, peer_id_len));
		/* Password-Length + Password following here, but we don't care */

		/* Prepare response, we ACK all of them: */
		pap_welcome_len = strlen(pap_welcome);
		/* +1: Length field of pap_welcome Message */
		pap_out_size = sizeof(struct pap_element) + 1 + pap_welcome_len;
		pap_out = alloca(pap_out_size);
		pap_out->code = PAP_CODE_AUTH_ACK;
		pap_out->id = pap_in->id;
		pap_out->len = htons(pap_out_size);
		pap_out->data[0] = pap_welcome_len;
		memcpy(pap_out->data+1, pap_welcome, pap_welcome_len);
		msgb_t16lv_put(resp, PCO_P_PAP, pap_out_size, (uint8_t *) pap_out);
		break;
	case PAP_CODE_AUTH_ACK:
	case PAP_CODE_AUTH_NAK:
	default:
		LOGPPDP(LOGL_NOTICE, pdp, "Unsupported PAP PCO Code %u, ignoring\n", pap_in->code);
		break;
	}
	return;

ret_broken_auth:
	LOGPPDP(LOGL_NOTICE, pdp, "Invalid PAP AuthenticateReq: %s, ignoring\n",
		osmo_hexdump_nospc((const uint8_t *)pco_in, pco_in->length));
	return;

ret_broken:
	LOGPPDP(LOGL_NOTICE, pdp, "Invalid PAP PCO Length: %s, ignoring\n",
		osmo_hexdump_nospc((const uint8_t *)pco_in, pco_in->length));
}

static void process_pco_element_ipcp(const struct pco_element *pco_elem, struct msgb *resp,
				     const struct apn_ctx *apn, struct pdp_t *pdp)
{
	struct ippoolm_t *peer_v4 = pdp_get_peer_ipv(pdp, false);
	const struct in46_addr *dns1 = &apn->v4.cfg.dns[0];
	const struct in46_addr *dns2 = &apn->v4.cfg.dns[1];
	uint8_t *start = resp->tail;
	const struct ipcp_hdr *ipcp;
	uint16_t ipcp_len;
	uint8_t *len1, *len2;
	unsigned int len_appended;
	ptrdiff_t consumed;
	size_t remain;

	if (!peer_v4) {
		LOGPPDP(LOGL_ERROR, pdp, "IPCP but no IPv4 type ?!?\n");
		return;
	}

	ipcp = (const struct ipcp_hdr *)pco_elem->data;
	consumed = (pco_elem->data - &pdp->pco_req.v[0]);
	remain = sizeof(pdp->pco_req.v) - consumed;
	ipcp_len = osmo_load16be(&ipcp->len);
	if (remain < 0 || remain < ipcp_len) {
		LOGPPDP(LOGL_ERROR, pdp, "Malformed IPCP, ignoring\n");
		return;
	}

	/* Three byte T16L header */
	msgb_put_u16(resp, 0x8021);	/* IPCP */
	len1 = msgb_put(resp, 1);	/* Length of contents: delay */

	msgb_put_u8(resp, 0x02);	/* ACK */
	msgb_put_u8(resp, ipcp->id);	/* ID: Needs to match request */
	msgb_put_u8(resp, 0x00);	/* Length MSB */
	len2 = msgb_put(resp, 1);	/* Length LSB: delay */

	if (dns1->len == 4 && ipcp_contains_option(ipcp, ipcp_len, IPCP_OPT_PRIMARY_DNS, 4)) {
		msgb_put_u8(resp, 0x81);		/* DNS1 Tag */
		msgb_put_u8(resp, 2 + dns1->len);	/* DNS1 Length, incl. TL */
		msgb_put_u32(resp, ntohl(dns1->v4.s_addr));
	}

	if (dns2->len == 4 && ipcp_contains_option(ipcp, ipcp_len, IPCP_OPT_SECONDARY_DNS, 4)) {
		msgb_put_u8(resp, 0x83);		/* DNS2 Tag */
		msgb_put_u8(resp, 2 + dns2->len);	/* DNS2 Length, incl. TL */
		msgb_put_u32(resp, ntohl(dns2->v4.s_addr));
	}

	/* patch in length values */
	len_appended = resp->tail - start;
	*len1 = len_appended - 3;
	*len2 = len_appended - 3;
}

static void process_pco_element_dns_ipv6(const struct pco_element *pco_elem, struct msgb *resp,
					 const struct apn_ctx *apn, struct pdp_t *pdp)
{
	unsigned int i;
	const uint8_t *tail = resp->tail;

	for (i = 0; i < ARRAY_SIZE(apn->v6.cfg.dns); i++) {
		const struct in46_addr *i46a = &apn->v6.cfg.dns[i];
		if (i46a->len != 16)
			continue;
		msgb_t16lv_put(resp, PCO_P_DNS_IPv6_ADDR, i46a->len, i46a->v6.s6_addr);
	}
	if (resp->tail == tail)
		LOGPPDP(LOGL_NOTICE, pdp, "MS requested IPv6 DNS, but APN has none configured\n");
}

static void process_pco_element_dns_ipv4(const struct pco_element *pco_elem, struct msgb *resp,
					 const struct apn_ctx *apn, struct pdp_t *pdp)
{
	unsigned int i;
	const uint8_t *tail = resp->tail;

	for (i = 0; i < ARRAY_SIZE(apn->v4.cfg.dns); i++) {
		const struct in46_addr *i46a = &apn->v4.cfg.dns[i];
		if (i46a->len != 4)
			continue;
		msgb_t16lv_put(resp, PCO_P_DNS_IPv4_ADDR, i46a->len, (uint8_t *)&i46a->v4);
	}
	if (resp->tail == tail)
		LOGPPDP(LOGL_NOTICE, pdp, "MS requested IPv4 DNS, but APN has none configured\n");
}

static void process_pco_element(const struct pco_element *pco_elem, struct msgb *resp,
				const struct apn_ctx *apn, struct pdp_t *pdp)
{
	uint16_t protocol_id = osmo_load16be(&pco_elem->protocol_id);

	LOGPPDP(LOGL_DEBUG, pdp, "PCO Protocol 0x%04x\n", protocol_id);
	switch (protocol_id) {
	case PCO_P_PAP:
		process_pco_element_pap(pco_elem, resp, apn, pdp);
		break;
	case PCO_P_IPCP:
		process_pco_element_ipcp(pco_elem, resp, apn, pdp);
		break;
	case PCO_P_DNS_IPv6_ADDR:
		process_pco_element_dns_ipv6(pco_elem, resp, apn, pdp);
		break;
	case PCO_P_DNS_IPv4_ADDR:
		process_pco_element_dns_ipv4(pco_elem, resp, apn, pdp);
		break;
	default:
		LOGPPDP(LOGL_INFO, pdp, "Unknown/Unimplemented PCO Protocol 0x%04x: %s\n",
			protocol_id, osmo_hexdump_nospc(pco_elem->data, pco_elem->length));
		break;
	}
}

/* process one PCO request from a MS/UE, putting together the proper responses */
void process_pco(const struct apn_ctx *apn, struct pdp_t *pdp)
{
	struct msgb *resp = msgb_alloc(256, "PCO.resp");
	const struct ul255_t *pco = &pdp->pco_req;
	const struct pco_element *pco_elem;
	const uint8_t *cur;

	/* build the header of the PCO response */
	OSMO_ASSERT(resp);
	msgb_put_u8(resp, 0x80); /* ext-bit + configuration protocol byte */

	/* iterate over the PCO elements in the request; call process_pco_element() for each */
	for (cur = pco->v + 1, pco_elem = (const struct pco_element *) cur;
	     cur + sizeof(struct pco_element) <= pco->v + pco->l;
	     cur += pco_elem->length + sizeof(*pco_elem), pco_elem = (const struct pco_element *) cur) {
		process_pco_element(pco_elem, resp, apn, pdp);
	}

	/* copy the PCO response msgb and copy its contents over to the PDP context */
	if (msgb_length(resp) > 1) {
		memcpy(pdp->pco_neg.v, msgb_data(resp), msgb_length(resp));
		pdp->pco_neg.l = msgb_length(resp);
	} else
		pdp->pco_neg.l = 0;
	msgb_free(resp);
}
