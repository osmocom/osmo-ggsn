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

/*
 * pdp.c: 
 *
 */

#include <../config.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include "pdp.h"
#include "lookupa.h"

/* ***********************************************************
 * Global variables TODO: most should be moved to gsn_t
 *************************************************************/

struct pdp_t pdpa[PDP_MAX];    /* PDP storage */
struct pdp_t* hashtid[PDP_MAX];/* Hash table for IMSI + NSAPI */
/* struct pdp_t* haship[PDP_MAX];  Hash table for IP and network interface */

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

int pdp_init() {
  memset(&pdpa, 0, sizeof(pdpa));
  memset(&hashtid, 0, sizeof(hashtid));
  /*  memset(&haship, 0, sizeof(haship)); */

  return 0;
}

int pdp_newpdp(struct pdp_t **pdp, uint64_t imsi, uint8_t nsapi, 
	       struct pdp_t *pdp_old){
  int n;
  for (n=0; n<PDP_MAX; n++) { /* TODO: Need to do better than linear search */
    if (pdpa[n].inuse == 0) {
      *pdp = &pdpa[n];
      if (NULL != pdp_old) memcpy(*pdp, pdp_old, sizeof(struct pdp_t));
      else memset(*pdp, 0, sizeof(struct pdp_t));
      (*pdp)->inuse    = 1;
      (*pdp)->imsi     = imsi;
      (*pdp)->nsapi    = nsapi;
      (*pdp)->fllc     = (uint16_t) n + 1;
      (*pdp)->fllu     = (uint16_t) n + 1;
      (*pdp)->teid_own = (uint32_t) n + 1;
      if (!(*pdp)->secondary) (*pdp)->teic_own = (uint32_t) n + 1;
      pdp_tidset(*pdp, pdp_gettid(imsi, nsapi));
      
      /* Insert reference in primary context */
      if (((*pdp)->teic_own > 0 ) && ((*pdp)->teic_own <= PDP_MAX)) {
	pdpa[(*pdp)->teic_own-1].secondary_tei[(*pdp)->nsapi & 0x0f] = 
	  (*pdp)->teid_own;
      }
      
      return 0;
    }
  }
  return EOF; /* No more available */
}

int pdp_freepdp(struct pdp_t *pdp){
  pdp_tiddel(pdp);

  /* Remove any references in primary context */
  if ((pdp->secondary) && (pdp->teic_own > 0 ) && (pdp->teic_own <= PDP_MAX)) {
    pdpa[pdp->teic_own-1].secondary_tei[pdp->nsapi & 0x0f] = 0;
  }

  memset(pdp, 0, sizeof(struct pdp_t));
  return 0;
}

int pdp_getpdp(struct pdp_t **pdp){
  *pdp = &pdpa[0];
  return 0;
}

int pdp_getgtp0(struct pdp_t **pdp, uint16_t fl){
  if ((fl>PDP_MAX) || (fl<1)) {
    return EOF;  /* Not found */
  }
  else {
    *pdp = &pdpa[fl-1];
    if ((*pdp)->inuse) return 0;
    else return EOF; 
    /* Context exists. We do no further validity checking. */
  }
}

int pdp_getgtp1(struct pdp_t **pdp, uint32_t tei){
  if ((tei>PDP_MAX) || (tei<1)) {
    return EOF;  /* Not found */
  }
  else {
    *pdp = &pdpa[tei-1];
    if ((*pdp)->inuse) return 0;
    else return EOF; 
    /* Context exists. We do no further validity checking. */
  }
}


int pdp_tidhash(uint64_t tid) {
  return (lookup(&tid, sizeof(tid), 0) % PDP_MAX);
}

int pdp_tidset(struct pdp_t *pdp, uint64_t tid) {
  int hash = pdp_tidhash(tid);
  struct pdp_t *pdp2;
  struct pdp_t *pdp_prev = NULL;
  if (PDP_DEBUG) printf("Begin pdp_tidset tid = %llx\n", tid);
  pdp->tidnext = NULL;
  pdp->tid = tid;
  for (pdp2 = hashtid[hash]; pdp2; pdp2 = pdp2->tidnext)
    pdp_prev = pdp2;
  if (!pdp_prev) 
    hashtid[hash] = pdp;
  else 
    pdp_prev->tidnext = pdp;
  if (PDP_DEBUG) printf("End pdp_tidset\n");
  return 0;
}

int pdp_tiddel(struct pdp_t *pdp) {
  int hash = pdp_tidhash(pdp->tid);
  struct pdp_t *pdp2;
  struct pdp_t *pdp_prev = NULL;
  if (PDP_DEBUG) printf("Begin pdp_tiddel tid = %llx\n", pdp->tid);
  for (pdp2 = hashtid[hash]; pdp2; pdp2 = pdp2->tidnext) {
    if (pdp2 == pdp) {
      if (!pdp_prev) 
	hashtid[hash] = pdp2->tidnext;
      else 
	pdp_prev->tidnext = pdp2->tidnext;
      if (PDP_DEBUG) printf("End pdp_tiddel: PDP found\n");
      return 0;
    }
    pdp_prev = pdp2;
  }
  if (PDP_DEBUG) printf("End pdp_tiddel: PDP not found\n");
  return EOF; /* End of linked list and not found */
}

int pdp_tidget(struct pdp_t **pdp, uint64_t tid) {
  int hash = pdp_tidhash(tid);
  struct pdp_t *pdp2;
  if (PDP_DEBUG) printf("Begin pdp_tidget tid = %llx\n", tid);
  for (pdp2 = hashtid[hash]; pdp2; pdp2 = pdp2->tidnext) {
    if (pdp2->tid == tid) {
      *pdp = pdp2;
      if (PDP_DEBUG) printf("Begin pdp_tidget. Found\n");
      return 0;
    }
  }
  if (PDP_DEBUG) printf("Begin pdp_tidget. Not found\n");
  return EOF; /* End of linked list and not found */
}

int pdp_getimsi(struct pdp_t **pdp, uint64_t imsi, uint8_t nsapi) {
  return pdp_tidget(pdp, 
		    (imsi & 0x0fffffffffffffffull) + ((uint64_t)nsapi << 60));
}

/*
int pdp_iphash(void* ipif, struct ul66_t *eua) {
  /#printf("IPhash %ld\n", lookup(eua->v, eua->l, ipif) % PDP_MAX);#/
  return (lookup(eua->v, eua->l, ipif) % PDP_MAX);
}
    
int pdp_ipset(struct pdp_t *pdp, void* ipif, struct ul66_t *eua) {
  int hash;
  struct pdp_t *pdp2;
  struct pdp_t *pdp_prev = NULL;

  if (PDP_DEBUG) printf("Begin pdp_ipset %d %d %2x%2x%2x%2x\n",
			(unsigned) ipif, eua->l,
			eua->v[2], eua->v[3], 
			eua->v[4], eua->v[5]);

  pdp->ipnext = NULL;
  pdp->ipif = ipif;
  pdp->eua.l = eua->l;
  memcpy(pdp->eua.v, eua->v, eua->l);

  hash = pdp_iphash(pdp->ipif, &pdp->eua);

  for (pdp2 = haship[hash]; pdp2; pdp2 = pdp2->ipnext)
    pdp_prev = pdp2;
  if (!pdp_prev) 
    haship[hash] = pdp;
  else 
    pdp_prev->ipnext = pdp;
  if (PDP_DEBUG) printf("End pdp_ipset\n");
  return 0;
}

int pdp_ipdel(struct pdp_t *pdp) {
  int hash = pdp_iphash(pdp->ipif, &pdp->eua);
  struct pdp_t *pdp2;
  struct pdp_t *pdp_prev = NULL;
  if (PDP_DEBUG) printf("Begin pdp_ipdel\n");
  for (pdp2 = haship[hash]; pdp2; pdp2 = pdp2->ipnext) {
    if (pdp2 == pdp) {
      if (!pdp_prev) 
	haship[hash] = pdp2->ipnext;
      else 
	pdp_prev->ipnext = pdp2->ipnext;
      if (PDP_DEBUG) printf("End pdp_ipdel: PDP found\n");
      return 0;
    }
    pdp_prev = pdp2;
  }
  if (PDP_DEBUG) printf("End pdp_ipdel: PDP not found\n");
  return EOF; /# End of linked list and not found #/
}

int pdp_ipget(struct pdp_t **pdp, void* ipif, struct ul66_t *eua) {
  int hash = pdp_iphash(ipif, eua);
  struct pdp_t *pdp2;
  /#printf("Begin pdp_ipget %d %d %2x%2x%2x%2x\n", (unsigned)ipif, eua->l, 
    eua->v[2],eua->v[3],eua->v[4],eua->v[5]);#/
  for (pdp2 = haship[hash]; pdp2; pdp2 = pdp2->ipnext) {
    if ((pdp2->ipif == ipif) && (pdp2->eua.l == eua->l) && 
	(memcmp(&pdp2->eua.v, &eua->v, eua->l) == 0)) {
      *pdp = pdp2;
      /#printf("End pdp_ipget. Found\n");#/
      return 0;
    }
  }
  if (PDP_DEBUG) printf("End pdp_ipget Notfound %d %d %2x%2x%2x%2x\n", 
	 (unsigned)ipif, eua->l, eua->v[2],eua->v[3],eua->v[4],eua->v[5]);
  return EOF; /# End of linked list and not found #/
}
*/
/* Various conversion functions */

int pdp_ntoeua(struct in_addr *src, struct ul66_t *eua) {
  eua->l=6;
  eua->v[0]=0xf1; /* IETF */
  eua->v[1]=0x21; /* IPv4 */
  memcpy(&eua->v[2], src, 4); /* Copy a 4 byte address */
  return 0;
}

int pdp_euaton(struct ul66_t *eua, struct in_addr *dst) {
  if((eua->l!=6) || (eua->v[0]!=0xf1) || (eua->v[1]!=0x21)) {
    return EOF;
  }
  memcpy(dst, &eua->v[2], 4); /* Copy a 4 byte address */
  return 0;
}

uint64_t pdp_gettid(uint64_t imsi, uint8_t nsapi) {
  return (imsi & 0x0fffffffffffffffull) + ((uint64_t)nsapi << 60);
}

int ulcpy(void* dst, void* src, size_t size) {
  if (((struct ul255_t*)src)->l <= size) {
    ((struct ul255_t*)dst)->l = ((struct ul255_t*)src)->l;
    memcpy(((struct ul255_t*)dst)->v, ((struct ul255_t*)src)->v, 
	   ((struct ul255_t*)dst)->l);
    return 0;
  }
  else return EOF;
}
