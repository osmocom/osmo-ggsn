/* 
 *  OpenGGSN - Gateway GPRS Support Node
 *  Copyright (C) 2002 Mondru AB.
 * 
 *  The contents of this file may be used under the terms of the GNU
 *  General Public License Version 2, provided that the above copyright
 *  notice and this permission notice is included in all copies or
 *  substantial portions of the software.
 * 
 */

/*
 * gtpie.c: Contains functions to encapsulate and decapsulate GTP 
 * information elements 
 *
 *
 * Encapsulation
 * - gtpie_tlv, gtpie_tv0, gtpie_tv1, gtpie_tv2 ... Adds information
 * elements to a buffer.
 *
 * Decapsulation
 *  - gtpie_decaps: Returns array with pointers to information elements.
 *  - getie_getie: Returns the pointer of a particular element.
 *  - gtpie_gettlv: Copies tlv information element. Return 0 on success.
 *  - gtpie_gettv: Copies tv information element. Return 0 on success.
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

#include "gtpie.h"

int gtpie_tlv(void *p, unsigned int *length, unsigned int size, uint8_t t, int l, void *v) {
  if ((*length + 3 + l) >= size) return 1;
  ((union gtpie_member*) (p + *length))->tlv.t = hton8(t);
  ((union gtpie_member*) (p + *length))->tlv.l = hton16(l);
  memcpy((void*) (p + *length +3), v, l);
  *length += 3 + l;
  return 0;
}

int gtpie_tv0(void *p, unsigned int *length, unsigned int size, uint8_t t, int l, uint8_t *v) {
  if ((*length + 1 + l) >= size) return 1;
  ((union gtpie_member*) (p + *length))->tv0.t = hton8(t);
  memcpy((void*) (p + *length +1), v, l);
  *length += 1 + l;
  return 0;
}

int gtpie_tv1(void *p, unsigned int *length, unsigned int size, uint8_t t, uint8_t v) {
  if ((*length + 2) >= size) return 1;
  ((union gtpie_member*) (p + *length))->tv1.t = hton8(t);
  ((union gtpie_member*) (p + *length))->tv1.v = hton8(v);
  *length += 2;
  return 0;
}

int gtpie_tv2(void *p, unsigned int *length, unsigned int size, uint8_t t, uint16_t v) {
  if ((*length + 3) >= size) return 1;
  ((union gtpie_member*) (p + *length))->tv2.t = hton8(t);
  ((union gtpie_member*) (p + *length))->tv2.v = hton16(v);
  *length += 3;
  return 0;
}

int gtpie_tv4(void *p, unsigned int *length, unsigned int size, uint8_t t, uint32_t v) {
  if ((*length + 5) >= size) return 1;
  ((union gtpie_member*) (p + *length))->tv4.t = hton8(t);
  ((union gtpie_member*) (p + *length))->tv4.v = hton32(v);
  *length += 5;
  return 0;
}

int gtpie_tv8(void *p, unsigned int *length, unsigned int size, uint8_t t, uint64_t v) {
  if ((*length + 9) >= size) return 1;
  ((union gtpie_member*) (p + *length))->tv8.t = hton8(t);
  ((union gtpie_member*) (p + *length))->tv8.v = hton64(v);
  *length += 9;
  return 0;
}

int gtpie_getie(union gtpie_member* ie[], int type, int instance) {
  int j;
  for (j=0; j< GTPIE_SIZE; j++) {
    if ((ie[j] != 0) && (ie[j]->t == type)) {
      if (instance-- == 0) return j;
    }
  }
  return -1;
}

int gtpie_exist(union gtpie_member* ie[], int type, int instance) {
  int j;
  for (j=0; j< GTPIE_SIZE; j++) {
    if ((ie[j] != 0) && (ie[j]->t == type)) {
      if (instance-- == 0) return 1;
    }
  }
  return 0;
}

int gtpie_gettlv(union gtpie_member* ie[], int type, int instance,
		 unsigned int *length, void *dst, unsigned int size){
  int ien;
  ien = gtpie_getie(ie, type, instance);
  if (ien>=0) {
    *length = ntoh16(ie[ien]->tlv.l);
    if (*length <= size)
      memcpy(dst, ie[ien]->tlv.v, *length);
    else
      return EOF;
  }
  return 0;
}

int gtpie_gettv0(union gtpie_member* ie[], int type, int instance,
		void *dst, unsigned int size){
  int ien;
  ien = gtpie_getie(ie, type, instance);
  if (ien>=0)
    memcpy(dst, ie[ien]->tv0.v, size);
  else
    return EOF;
  return 0;
}

int gtpie_gettv1(union gtpie_member* ie[], int type, int instance, 
		 uint8_t *dst){
  int ien;
  ien = gtpie_getie(ie, type, instance);
  if (ien>=0)
    *dst = ntoh8(ie[ien]->tv1.v);
  else
    return EOF;
  return 0;
}

int gtpie_gettv2(union gtpie_member* ie[], int type, int instance, 
		 uint16_t *dst){
  int ien;
  ien = gtpie_getie(ie, type, instance);
  if (ien>=0)
    *dst = ntoh16(ie[ien]->tv2.v);
  else
    return EOF;
  return 0;
}

int gtpie_gettv4(union gtpie_member* ie[], int type, int instance, 
		 uint32_t *dst){
  int ien;
  ien = gtpie_getie(ie, type, instance);
  if (ien>=0)
    *dst = ntoh32(ie[ien]->tv4.v);
  else
    return EOF;
  return 0;
}

int gtpie_gettv8(union gtpie_member* ie[], int type, int instance, 
		 uint64_t *dst){
  int ien;
  ien = gtpie_getie(ie, type, instance);
  if (ien>=0)
    *dst = ntoh64(ie[ien]->tv8.v);
  else
    return EOF;
  return 0;
}

int gtpie_decaps(union gtpie_member* ie[], int version, void *pack, unsigned len) {
  int i;
  int j = 0;
  unsigned char *p;
  unsigned char *end;

  end = (unsigned char*) pack + len;
  p = pack;

  memset(ie, 0, sizeof(union gtpie_member *) * GTPIE_SIZE);

  while ((p<end) && (j<GTPIE_SIZE)) {
    if (GTPIE_DEBUG) {
      printf("The packet looks like this:\n");
      for( i=0; i<(end-p); i++) {
	printf("%02x ", (unsigned char)*(char *)(p+i));
	if (!((i+1)%16)) printf("\n");
      };
      printf("\n");
    }
    
    switch (*p) {
    case GTPIE_CAUSE:             /* TV GTPIE types with value length 1 */
    case GTPIE_REORDER:
    case GTPIE_MAP_CAUSE:
    case GTPIE_MS_VALIDATED:
    case GTPIE_RECOVERY:
    case GTPIE_SELECTION_MODE:
    case GTPIE_TEARDOWN:
    case GTPIE_NSAPI:
    case GTPIE_RANAP_CAUSE:
    case GTPIE_RP_SMS:
    case GTPIE_RP:
    case GTPIE_MS_NOT_REACH:
      if (j<GTPIE_SIZE) {
	ie[j] = (union gtpie_member*) p;
	if (GTPIE_DEBUG) printf("GTPIE TV1 found. Type %d, value %d\n", 
				ie[j]->tv1.t, ie[j]->tv1.v);
	p+= 1 + 1;
	j++;
      }
      break;
    case GTPIE_FL_DI:           /* TV GTPIE types with value length 2 or 4 */
    case GTPIE_FL_C:
      if (version != 0) {
	if (j<GTPIE_SIZE) {     /* GTPIE_TEI_DI & GTPIE_TEI_C with length 4 */
	  /* case GTPIE_TEI_DI: gtp1 */
	  /* case GTPIE_TEI_C:  gtp1 */
	  ie[j] = (union gtpie_member*) p;
	  if (GTPIE_DEBUG) printf("GTPIE TV 4 found. Type %d, value %d\n",
				  ie[j]->tv4.t, ie[j]->tv4.v);
	  p+= 1 + 4;
	  j++;
	}
	break;
      }
    case GTPIE_PFI:             /* TV GTPIE types with value length 2 */
    case GTPIE_CHARGING_C:
    case GTPIE_TRACE_REF:
    case GTPIE_TRACE_TYPE:
      if (j<GTPIE_SIZE) {
	ie[j] = (union gtpie_member*) p;
	if (GTPIE_DEBUG) printf("GTPIE TV2 found. Type %d, value %d\n", 
	       ie[j]->tv2.t, ie[j]->tv2.v);
	p+= 1 + 2;
	j++;
      }
      break;
    case GTPIE_QOS_PROFILE0:    /* TV GTPIE types with value length 3 */
    case GTPIE_P_TMSI_S:
      if (j<GTPIE_SIZE) {
	ie[j] = (union gtpie_member*) p;
	if (GTPIE_DEBUG) printf("GTPIE TV 3 found. Type %d, value %d, %d, %d\n", 
				ie[j]->tv0.t, ie[j]->tv0.v[0], 
				ie[j]->tv0.v[1], ie[j]->tv0.v[2]);
	p+= 1 + 3;
	j++;
      }
      break;
    case GTPIE_TLLI:            /* TV GTPIE types with value length 4 */
    case GTPIE_P_TMSI:
    case GTPIE_CHARGING_ID:
      /* case GTPIE_TEI_DI: Handled by GTPIE_FL_DI */
      /* case GTPIE_TEI_C:  Handled by GTPIE_FL_DI */
      if (j<GTPIE_SIZE) {
	ie[j] = (union gtpie_member*) p;
	if (GTPIE_DEBUG) printf("GTPIE TV 4 found. Type %d, value %d\n",
				ie[j]->tv4.t, ie[j]->tv4.v);
	p+= 1 + 4;
	j++;
      }
      break;
    case GTPIE_TEI_DII:         /* TV GTPIE types with value length 5 */
      if (j<GTPIE_SIZE) {
	ie[j] = (union gtpie_member*) p;
	if (GTPIE_DEBUG) printf("GTPIE TV 5 found. Type %d\n", ie[j]->tv0.t);
	p+= 1 + 5;
	j++;
      }
      break;
    case GTPIE_RAB_CONTEXT:     /* TV GTPIE types with value length 7 */
      if (j<GTPIE_SIZE) {
	ie[j] = (union gtpie_member*) p;
	if (GTPIE_DEBUG) printf("GTPIE TV 7 found. Type %d\n", ie[j]->tv0.t);
	p+= 1 + 7;
	j++;
      }
      break;
    case GTPIE_IMSI:            /* TV GTPIE types with value length 8 */
    case GTPIE_RAI:
      if (j<GTPIE_SIZE) {
	ie[j] = (union gtpie_member*) p;
	if (GTPIE_DEBUG) printf("GTPIE TV 8 found. Type %d, value 0x%llx\n",
				ie[j]->tv0.t, ie[j]->tv8.v);
	p+= 1 + 8;
	j++;
      }
      break;
    case GTPIE_AUTH_TRIPLET:    /* TV GTPIE types with value length 28 */
      if (j<GTPIE_SIZE) {
	ie[j] = (union gtpie_member*) p;
	if (GTPIE_DEBUG) printf("GTPIE TV 28 found. Type %d\n", ie[j]->tv0.t);
	p+= 1 + 28;
	j++;
      }
      break;
    case GTPIE_EXT_HEADER_T:   /* GTP extension header */
      if (j<GTPIE_SIZE) {
	ie[j] = (union gtpie_member*) p;
	if (GTPIE_DEBUG) printf("GTPIE GTP extension header found. Type %d\n",
				ie[j]->ext.t);
	p+= 2 + ntoh8(ie[j]->ext.l);
	j++;
      }
      break;
    case GTPIE_EUA:            /* TLV GTPIE types with variable length */
    case GTPIE_MM_CONTEXT:
    case GTPIE_PDP_CONTEXT:
    case GTPIE_APN:
    case GTPIE_PCO:
    case GTPIE_GSN_ADDR:
    case GTPIE_MSISDN:
    case GTPIE_QOS_PROFILE:
    case GTPIE_AUTH_QUINTUP:
    case GTPIE_TFT:
    case GTPIE_TARGET_INF:
    case GTPIE_UTRAN_TRANS:
    case GTPIE_RAB_SETUP:
    case GTPIE_TRIGGER_ID:
    case GTPIE_OMC_ID:
    case GTPIE_CHARGING_ADDR:
    case GTPIE_PRIVATE:
      if (j<GTPIE_SIZE) {
	ie[j] = (union gtpie_member*) p;
	if (GTPIE_DEBUG) printf("GTPIE TLV found. Type %d\n", ie[j]->tlv.t);
	p+= 3 + ntoh16(ie[j]->tlv.l);
	j++;
      }
      break;
    default:
      if (GTPIE_DEBUG) printf("GTPIE something unknown. Type %d\n", *p);
      return EOF; /* We received something unknown */
    }	
  }
  if (p==end) {
    if (GTPIE_DEBUG) printf("GTPIE normal return. %lx %lx\n",
			    (unsigned long) p, (unsigned long) end);
    return 0; /* We landed at the end of the packet: OK */
  }
  else if (!(j<GTPIE_SIZE)) {
    if (GTPIE_DEBUG) printf("GTPIE too many elements.\n");
    return EOF; /* We received too many information elements */
  }
  else {
    if (GTPIE_DEBUG) printf("GTPIE exceeded end of packet. %lx %lx\n",
			    (unsigned long) p, (unsigned long) end);
    return EOF; /* We exceeded the end of the packet: Error */
  }
}

int gtpie_encaps(union gtpie_member *ie[], void *pack, unsigned *len) {
  int i;
  unsigned char *p;
  unsigned char *end;
  union gtpie_member *m;
  int iesize;
  
  p = pack;

  memset(pack, 0, GTPIE_MAX);
  end = p + GTPIE_MAX;
  for (i=1; i<GTPIE_SIZE; i++) if (ie[i] != 0) {
    if (GTPIE_DEBUG) printf("gtpie_encaps. Type %d\n", i); 
    m=(union gtpie_member *)p;
    switch (i) {
    case GTPIE_CAUSE:             /* TV GTPIE types with value length 1 */
    case GTPIE_REORDER:
    case GTPIE_MAP_CAUSE:
    case GTPIE_MS_VALIDATED:
    case GTPIE_RECOVERY:
    case GTPIE_SELECTION_MODE:
    case GTPIE_TEARDOWN:
    case GTPIE_NSAPI:
    case GTPIE_RANAP_CAUSE:
    case GTPIE_RP_SMS:
    case GTPIE_RP:
    case GTPIE_MS_NOT_REACH:
      iesize = 2;
      break;
    case GTPIE_FL_DI:           /* TV GTPIE types with value length 2 */
    case GTPIE_FL_C:
    case GTPIE_PFI:
    case GTPIE_CHARGING_C:
    case GTPIE_TRACE_REF:
    case GTPIE_TRACE_TYPE:
      iesize = 3;
      break;
    case GTPIE_QOS_PROFILE0:    /* TV GTPIE types with value length 3 */
    case GTPIE_P_TMSI_S:
      iesize = 4;
      break;
    case GTPIE_TLLI:            /* TV GTPIE types with value length 4 */
    case GTPIE_P_TMSI:
      /* case GTPIE_TEI_DI: only in gtp1*/
      /* case GTPIE_TEI_C: only in gtp1*/
    case GTPIE_CHARGING_ID:
      iesize = 5;
      break;
    case GTPIE_TEI_DII:         /* TV GTPIE types with value length 5 */
      iesize = 6;
      break;
    case GTPIE_RAB_CONTEXT:     /* TV GTPIE types with value length 7 */
      iesize = 8;
      break;
    case GTPIE_IMSI:            /* TV GTPIE types with value length 8 */
    case GTPIE_RAI:
      iesize = 9;
      break;
    case GTPIE_AUTH_TRIPLET:    /* TV GTPIE types with value length 28 */
      iesize = 29;
      break;
    case GTPIE_EXT_HEADER_T:   /* GTP extension header */
      iesize = 2 + hton8(ie[i]->ext.l);
      break;
    case GTPIE_EUA:            /* TLV GTPIE types with length length 2 */
    case GTPIE_MM_CONTEXT:
    case GTPIE_PDP_CONTEXT:
    case GTPIE_APN:
    case GTPIE_PCO:
    case GTPIE_GSN_ADDR:
    case GTPIE_MSISDN:
    case GTPIE_QOS_PROFILE:
    case GTPIE_AUTH_QUINTUP:
    case GTPIE_TFT:
    case GTPIE_TARGET_INF:
    case GTPIE_UTRAN_TRANS:
    case GTPIE_RAB_SETUP:
    case GTPIE_TRIGGER_ID:
    case GTPIE_OMC_ID:
    case GTPIE_CHARGING_ADDR:
    case GTPIE_PRIVATE:
      iesize = 3 + hton16(ie[i]->tlv.l);
      break;
    default:
      return 2; /* We received something unknown */
    }
    if (p+iesize < end) {
      memcpy(p, ie[i], iesize);
      p += iesize;
      *len += iesize;
    }
    else return 2;              /* Out of space */
  }
  return 0;
}

int gtpie_encaps2(union gtpie_member ie[], unsigned int size,
		  void *pack, unsigned *len) {
  unsigned int i, j;
  unsigned char *p;
  unsigned char *end;
  union gtpie_member *m;
  int iesize;
  
  p = pack;

  memset(pack, 0, GTPIE_MAX);
  end = p + GTPIE_MAX;
  for (j=0; j<GTPIE_SIZE; j++) for (i=0; i<size; i++) if (ie[i].t == j) {
    if (GTPIE_DEBUG) printf("gtpie_encaps. Number %d, Type %d\n", i, ie[i].t); 
    m=(union gtpie_member *)p;
    switch (ie[i].t) {
    case GTPIE_CAUSE:             /* TV GTPIE types with value length 1 */
    case GTPIE_REORDER:
    case GTPIE_MAP_CAUSE:
    case GTPIE_MS_VALIDATED:
    case GTPIE_RECOVERY:
    case GTPIE_SELECTION_MODE:
    case GTPIE_TEARDOWN:
    case GTPIE_NSAPI:
    case GTPIE_RANAP_CAUSE:
    case GTPIE_RP_SMS:
    case GTPIE_RP:
    case GTPIE_MS_NOT_REACH:
      iesize = 2;
      break;
    case GTPIE_PFI:             /* TV GTPIE types with value length 2 */
    case GTPIE_CHARGING_C:
    case GTPIE_TRACE_REF:
    case GTPIE_TRACE_TYPE:
      iesize = 3;
      break;
    case GTPIE_QOS_PROFILE0:    /* TV GTPIE types with value length 3 */
    case GTPIE_P_TMSI_S:
      iesize = 4;
      break;
    case GTPIE_TLLI:            /* TV GTPIE types with value length 4 */
    case GTPIE_P_TMSI:
    case GTPIE_TEI_DI:
    case GTPIE_TEI_C:
      iesize = 5;
      break;
    case GTPIE_TEI_DII:         /* TV GTPIE types with value length 5 */
      iesize = 6;
      break;
    case GTPIE_RAB_CONTEXT:     /* TV GTPIE types with value length 7 */
      iesize = 8;
      break;
    case GTPIE_IMSI:            /* TV GTPIE types with value length 8 */
    case GTPIE_RAI:
      iesize = 9;
      break;
    case GTPIE_AUTH_TRIPLET:    /* TV GTPIE types with value length 28 */
      iesize = 29;
      break;
    case GTPIE_EXT_HEADER_T:   /* GTP extension header */
      iesize = 2 + hton8(ie[i].ext.l);
      break;
    case GTPIE_CHARGING_ID:    /* TLV GTPIE types with length length 2 */
    case GTPIE_EUA:
    case GTPIE_MM_CONTEXT:
    case GTPIE_PDP_CONTEXT:
    case GTPIE_APN:
    case GTPIE_PCO:
    case GTPIE_GSN_ADDR:
    case GTPIE_MSISDN:
    case GTPIE_QOS_PROFILE:
    case GTPIE_AUTH_QUINTUP:
    case GTPIE_TFT:
    case GTPIE_TARGET_INF:
    case GTPIE_UTRAN_TRANS:
    case GTPIE_RAB_SETUP:
    case GTPIE_TRIGGER_ID:
    case GTPIE_OMC_ID:
    case GTPIE_CHARGING_ADDR:
    case GTPIE_PRIVATE:
      iesize = 3 + hton16(ie[i].tlv.l);
      break;
    default:
      return 2; /* We received something unknown */
    }
    if (p+iesize < end) {
      memcpy(p, &ie[i], iesize);
      p += iesize;
      *len += iesize;
    }
    else return 2;              /* Out of space */
  }
  return 0;
}
