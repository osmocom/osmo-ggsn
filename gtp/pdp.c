/*
 *  OsmoGGSN - Gateway GPRS Support Node
 *  Copyright (C) 2002, 2003, 2004 Mondru AB.
 *  Copyright (C) 2017 Harald Welte <laforge@gnumonks.org>
 *
 *  The contents of this file may be used under the terms of the GNU
 *  General Public License Version 2, provided that the above copyright
 *  notice and this permission notice is included in all copies or
 *  substantial portions of the software.
 *
 */

/*
 * pdp.c:
 *
 */

#include <../config.h>

#include <osmocom/core/logging.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <inttypes.h>
#include "pdp.h"
#include "gtp.h"
#include "lookupa.h"

/* ***********************************************************
 * Functions related to PDP storage
 *
 * Lifecycle
 * For a GGSN pdp context life begins with the reception of a
 * create pdp context request. It normally ends with the reception
 * of a delete pdp context request, but will also end with the
 * reception of an error indication message.
 * Provisions should probably be made for terminating pdp contexts
 * based on either idle timeout, or by sending downlink probe
 * messages (ping?) to see if the MS is still responding.
 *
 * For an SGSN pdp context life begins with the application just
 * before sending off a create pdp context request. It normally
 * ends when a delete pdp context response message is received
 * from the GGSN, but should also end when with the reception of
 * an error indication message.
 *
 *
 * HASH Tables
 *
 * Downlink packets received in the GGSN are identified only by their
 * network interface together with their destination IP address (Two
 * network interfaces can use the same private IP address). Each IMSI
 * (mobile station) can have several PDP contexts using the same IP
 * address. In this case the traffic flow template (TFT) is used to
 * determine the correct PDP context for a particular IMSI. Also it
 * should be possible for each PDP context to use several IP adresses
 * For fixed wireless access a mobile station might need a full class
 * C network. Even in the case of several IP adresses the PDP context
 * should be determined on the basis of the network IP address.
 * Thus we need a hash table based on network interface + IP address.
 *
 * Uplink packets are for GTP0 identified by their IMSI and NSAPI, which
 * is collectively called the tunnel identifier. There is also a 16 bit
 * flow label that can be used for identification of uplink packets. This
 * however is quite useless as it limits the number of contexts to 65536.
 * For GTP1 uplink packets are identified by a Tunnel Endpoint Identifier
 * (32 bit), or in some cases by the combination of IMSI and NSAPI.
 * For GTP1 delete context requests there is a need to find the PDP
 * contexts with the same IP address. This however can be done by using
 * the IP hash table.
 * Thus we need a hash table based on TID (IMSI and NSAPI). The TEID will
 * be used for directly addressing the PDP context.

 * pdp_newpdp
 * Gives you a pdp context with no hash references In some way
 * this should have a limited lifetime.
 *
 * pdp_freepdp
 * Frees a context that was previously allocated with
 * pdp_newpdp
 *
 *
 * pdp_getpdpIP
 * An incoming IP packet is uniquely identified by a pointer
 * to a network connection (void *) and an IP address
 * (struct in_addr)
 *
 * pdp_getpdpGTP
 * An incoming GTP packet is uniquely identified by a the
 * TID (imsi + nsapi (8 octets)) in or by the Flow Label
 * (2 octets) in gtp0 or by the Tunnel Endpoint Identifier
 * (4 octets) in gtp1.
 *
 * This leads to an architecture where the receiving GSN
 * chooses a Flow Label or a Tunnel Endpoint Identifier
 * when the connection is setup.
 * Thus no hash table is needed for GTP lookups.
 *
 *************************************************************/

static struct gsn_t *g_gsn;

int pdp_init(struct gsn_t *gsn)
{
	if(!g_gsn) {
		g_gsn = gsn;
	} else {
		LOGP(DLGTP, LOGL_FATAL, "This interface is depreacted and doesn't support multiple GGSN!");
		return -1;
	}

	return 0;
}

int pdp_newpdp(struct pdp_t **pdp, uint64_t imsi, uint8_t nsapi,
	       struct pdp_t *pdp_old)
{
	return gtp_pdp_newpdp(g_gsn, pdp, imsi, nsapi, pdp_old);
}

int gtp_pdp_newpdp(struct gsn_t *gsn, struct pdp_t **pdp, uint64_t imsi, uint8_t nsapi,
	       struct pdp_t *pdp_old)
{
	struct pdp_t *pdpa = gsn->pdpa;
	int n;
	for (n = 0; n < PDP_MAX; n++) {	/* TODO: Need to do better than linear search */
		if (pdpa[n].inuse == 0) {
			*pdp = &pdpa[n];
			if (NULL != pdp_old)
				memcpy(*pdp, pdp_old, sizeof(struct pdp_t));
			else
				memset(*pdp, 0, sizeof(struct pdp_t));
			(*pdp)->inuse = 1;
			(*pdp)->gsn = gsn;
			(*pdp)->imsi = imsi;
			(*pdp)->nsapi = nsapi;
			(*pdp)->fllc = (uint16_t) n + 1;
			(*pdp)->fllu = (uint16_t) n + 1;
			(*pdp)->teid_own = (uint32_t) n + 1;
			if (!(*pdp)->secondary)
				(*pdp)->teic_own = (uint32_t) n + 1;
			pdp_tidset(*pdp, pdp_gettid(imsi, nsapi));

			/* Insert reference in primary context */
			if (((*pdp)->teic_own > 0)
			    && ((*pdp)->teic_own <= PDP_MAX)) {
				pdpa[(*pdp)->teic_own -
				     1].secondary_tei[(*pdp)->nsapi & 0x0f] =
				    (*pdp)->teid_own;
			}
			/* Default: Generate G-PDU sequence numbers on Tx */
			(*pdp)->tx_gpdu_seq = true;

			return 0;
		}
	}
	return EOF;		/* No more available */
}

int pdp_freepdp(struct pdp_t *pdp)
{
	struct pdp_t *pdpa = pdp->gsn->pdpa;

	pdp_tiddel(pdp);

	/* Remove any references in primary context */
	if ((pdp->secondary) && (pdp->teic_own > 0)
	    && (pdp->teic_own <= PDP_MAX)) {
		pdpa[pdp->teic_own - 1].secondary_tei[pdp->nsapi & 0x0f] = 0;
	}

	memset(pdp, 0, sizeof(struct pdp_t));
	return 0;
}

int pdp_getpdp(struct pdp_t **pdp)
{
	*pdp = &g_gsn->pdpa[0];
	return 0;
}

int pdp_getgtp0(struct pdp_t **pdp, uint16_t fl)
{
	return gtp_pdp_getgtp0(g_gsn, pdp, fl);
}


int gtp_pdp_getgtp0(struct gsn_t *gsn, struct pdp_t **pdp, uint16_t fl)
{
	struct pdp_t *pdpa = gsn->pdpa;

	if ((fl > PDP_MAX) || (fl < 1)) {
		return EOF;	/* Not found */
	} else {
		*pdp = &pdpa[fl - 1];
		if ((*pdp)->inuse)
			return 0;
		else
			return EOF;
		/* Context exists. We do no further validity checking. */
	}
}

int pdp_getgtp1(struct pdp_t **pdp, uint32_t tei)
{
	return gtp_pdp_getgtp1(g_gsn, pdp, tei);
}

int gtp_pdp_getgtp1(struct gsn_t *gsn, struct pdp_t **pdp, uint32_t tei)
{
	struct pdp_t *pdpa = gsn->pdpa;

	if ((tei > PDP_MAX) || (tei < 1)) {
		return EOF;	/* Not found */
	} else {
		*pdp = &pdpa[tei - 1];
		if ((*pdp)->inuse)
			return 0;
		else
			return EOF;
		/* Context exists. We do no further validity checking. */
	}
}

/* get a PDP based on the *peer* address + TEI-Data.  Used for matching inbound Error Ind */
int pdp_getgtp1_peer_d(struct pdp_t **pdp, const struct sockaddr_in *peer, uint32_t teid_gn)
{
	return gtp_pdp_getgtp1_peer_d(g_gsn, pdp, peer, teid_gn);
}

int gtp_pdp_getgtp1_peer_d(struct gsn_t *gsn, struct pdp_t **pdp, const struct sockaddr_in *peer, uint32_t teid_gn)
{
	struct pdp_t *pdpa = gsn->pdpa;
	unsigned int i;

	/* this is O(n) but we don't have (nor want) another hash... */
	for (i = 0; i < PDP_MAX; i++) {
		struct pdp_t *candidate = &pdpa[i];
		if (candidate->inuse && candidate->teid_gn == teid_gn &&
		    candidate->gsnru.l == sizeof(peer->sin_addr) &&
		    !memcmp(&peer->sin_addr, candidate->gsnru.v, sizeof(peer->sin_addr))) {
			*pdp = &pdpa[i];
			return 0;
		}
	}
	return EOF;
}

int pdp_tidhash(uint64_t tid)
{
	return (lookup(&tid, sizeof(tid), 0) % PDP_MAX);
}

int pdp_tidset(struct pdp_t *pdp, uint64_t tid)
{
	struct pdp_t **hashtid = pdp->gsn->hashtid;
	int hash = pdp_tidhash(tid);
	struct pdp_t *pdp2;
	struct pdp_t *pdp_prev = NULL;
	DEBUGP(DLGTP, "Begin pdp_tidset tid = %"PRIx64"\n", tid);
	pdp->tidnext = NULL;
	pdp->tid = tid;
	for (pdp2 = hashtid[hash]; pdp2; pdp2 = pdp2->tidnext)
		pdp_prev = pdp2;
	if (!pdp_prev)
		hashtid[hash] = pdp;
	else
		pdp_prev->tidnext = pdp;
	DEBUGP(DLGTP, "End pdp_tidset\n");
	return 0;
}

int pdp_tiddel(struct pdp_t *pdp)
{
	struct pdp_t **hashtid = pdp->gsn->hashtid;
	int hash = pdp_tidhash(pdp->tid);
	struct pdp_t *pdp2;
	struct pdp_t *pdp_prev = NULL;
	DEBUGP(DLGTP, "Begin pdp_tiddel tid = %"PRIx64"\n", pdp->tid);
	for (pdp2 = hashtid[hash]; pdp2; pdp2 = pdp2->tidnext) {
		if (pdp2 == pdp) {
			if (!pdp_prev)
				hashtid[hash] = pdp2->tidnext;
			else
				pdp_prev->tidnext = pdp2->tidnext;
			DEBUGP(DLGTP, "End pdp_tiddel: PDP found\n");
			return 0;
		}
		pdp_prev = pdp2;
	}
	DEBUGP(DLGTP, "End pdp_tiddel: PDP not found\n");
	return EOF;		/* End of linked list and not found */
}

int pdp_tidget(struct pdp_t **pdp, uint64_t tid)
{
	return gtp_pdp_tidget(g_gsn, pdp, tid);
}

int gtp_pdp_tidget(struct gsn_t *gsn, struct pdp_t **pdp, uint64_t tid)
{
	struct pdp_t **hashtid = gsn->hashtid;
	int hash = pdp_tidhash(tid);
	struct pdp_t *pdp2;
	DEBUGP(DLGTP, "Begin pdp_tidget tid = %"PRIx64"\n", tid);
	for (pdp2 = hashtid[hash]; pdp2; pdp2 = pdp2->tidnext) {
		if (pdp2->tid == tid) {
			*pdp = pdp2;
			DEBUGP(DLGTP, "Begin pdp_tidget. Found\n");
			return 0;
		}
	}
	DEBUGP(DLGTP, "Begin pdp_tidget. Not found\n");
	return EOF;		/* End of linked list and not found */
}

int pdp_getimsi(struct pdp_t **pdp, uint64_t imsi, uint8_t nsapi)
{
	return gtp_pdp_getimsi(g_gsn, pdp, imsi, nsapi);
}

int gtp_pdp_getimsi(struct gsn_t *gsn, struct pdp_t **pdp, uint64_t imsi, uint8_t nsapi)
{
	return gtp_pdp_tidget(gsn, pdp,
			  (imsi & 0x0fffffffffffffffull) +
			  ((uint64_t) nsapi << 60));
}


/* Various conversion functions */

uint64_t pdp_gettid(uint64_t imsi, uint8_t nsapi)
{
	return (imsi & 0x0fffffffffffffffull) + ((uint64_t) nsapi << 60);
}

void pdp_set_imsi_nsapi(struct pdp_t *pdp, uint64_t teid)
{
	pdp->imsi = teid & 0x0fffffffffffffffull;
	pdp->nsapi = (teid & 0xf000000000000000ull) >> 60;
}

/* Count amount of secondary PDP contexts linked to this primary PDP context
 * (itself included). Must be called on a primary PDP context. */
unsigned int pdp_count_secondary(struct pdp_t *pdp)
{
	unsigned int n;
	unsigned int count = 0;
	OSMO_ASSERT(!pdp->secondary);

	for (n = 0; n < PDP_MAXNSAPI; n++)
		if (pdp->secondary_tei[n])
			count++;
	return count;
}
