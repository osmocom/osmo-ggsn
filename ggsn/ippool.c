/* 
 * IP address pool functions.
 * Copyright (C) 2003 Mondru AB.
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 * The initial developer of the original code is
 * Jens Jakobsen <jj@openggsn.org>
 * 
 * Contributor(s):
 * 
 */

#include <netinet/in.h> /* in_addr */
#include <stdlib.h>     /* calloc */
#include <stdio.h>      /* sscanf */

#include "ippool.h"


/*
--------------------------------------------------------------------
Public domain by From Bob Jenkins, December 1996.
mix -- mix 3 32-bit values reversibly.
For every delta with one or two bit set, and the deltas of all three
  high bits or all three low bits, whether the original value of a,b,c
  is almost all zero or is uniformly distributed,
* If mix() is run forward or backward, at least 32 bits in a,b,c
  have at least 1/4 probability of changing.
* If mix() is run forward, every bit of c will change between 1/3 and
  2/3 of the time.  (Well, 22/100 and 78/100 for some 2-bit deltas.)
mix() was built out of 36 single-cycle latency instructions in a 
  structure that could supported 2x parallelism, like so:
      a -= b; 
      a -= c; x = (c>>13);
      b -= c; a ^= x;
      b -= a; x = (a<<8);
      c -= a; b ^= x;
      c -= b; x = (b>>13);
      ...
  Unfortunately, superscalar Pentiums and Sparcs can't take advantage 
  of that parallelism.  They've also turned some of those single-cycle
  latency instructions into multi-cycle latency instructions.  Still,
  this is the fastest good hash I could find.  There were about 2^^68
  to choose from.  I only looked at a billion or so.
--------------------------------------------------------------------
*/
#define mix(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}
/*
--------------------------------------------------------------------
lookup() -- hash a variable-length key into a 32-bit value
  k     : the key (the unaligned variable-length array of bytes)
  len   : the length of the key, counting by bytes
  level : can be any 4-byte value
Returns a 32-bit value.  Every bit of the key affects every bit of
the return value.  Every 1-bit and 2-bit delta achieves avalanche.
About 6len+35 instructions.

The best hash table sizes are powers of 2.  There is no need to do
mod a prime (mod is sooo slow!).  If you need less than 32 bits,
use a bitmask.  For example, if you need only 10 bits, do
  h = (h & hashmask(10));
In which case, the hash table should have hashsize(10) elements.

If you are hashing n strings (ub1 **)k, do it like this:
  for (i=0, h=0; i<n; ++i) h = lookup( k[i], len[i], h);

By Bob Jenkins, 1996.  bob_jenkins@burtleburtle.net.  You may use this
code any way you wish, private, educational, or commercial.

See http://burtleburtle.net/bob/hash/evahash.html
Use for hash table lookup, or anything where one collision in 2^32 is
acceptable.  Do NOT use for cryptographic purposes.
--------------------------------------------------------------------
*/

unsigned long int lookup( k, length, level)
register unsigned char *k;           /* the key */
register unsigned long int length;   /* the length of the key */
register unsigned long int level;    /* the previous hash, or an arbitrary value */
{
   register unsigned long int a,b,c,len;

   /* Set up the internal state */
   len = length;
   a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
   c = level;           /* the previous hash value */

   /*---------------------------------------- handle most of the key */
   while (len >= 12)
   {
      a += (k[0] +((ub4)k[1]<<8) +((ub4)k[2]<<16) +((ub4)k[3]<<24));
      b += (k[4] +((ub4)k[5]<<8) +((ub4)k[6]<<16) +((ub4)k[7]<<24));
      c += (k[8] +((ub4)k[9]<<8) +((ub4)k[10]<<16)+((ub4)k[11]<<24));
      mix(a,b,c);
      k += 12; len -= 12;
   }

   /*------------------------------------- handle the last 11 bytes */
   c += length;
   switch(len)              /* all the case statements fall through */
   {
   case 11: c+=((ub4)k[10]<<24);
   case 10: c+=((ub4)k[9]<<16);
   case 9 : c+=((ub4)k[8]<<8);
      /* the first byte of c is reserved for the length */
   case 8 : b+=((ub4)k[7]<<24);
   case 7 : b+=((ub4)k[6]<<16);
   case 6 : b+=((ub4)k[5]<<8);
   case 5 : b+=k[4];
   case 4 : a+=((ub4)k[3]<<24);
   case 3 : a+=((ub4)k[2]<<16);
   case 2 : a+=((ub4)k[1]<<8);
   case 1 : a+=k[0];
     /* case 0: nothing left to add */
   }
   mix(a,b,c);
   /*-------------------------------------------- report the result */
   return c;
}

/*
End of public domain code by From Bob Jenkins, December 1996.
--------------------------------------------------------------------
*/

int ippool_printaddr(struct ippool_t *this) {
  int n;
  printf("ippool_printaddr\n");
  printf("First %d\n", this->first - this->member);
  printf("Last %d\n",  this->last - this->member);
  printf("Listsize %d\n",  this->listsize);

  for (n=0; n<this->listsize; n++) {
    printf("Unit %d inuse %d prev %d next %d addr %x\n", 
	   n,
	   this->member[n].inuse,
	   this->member[n].prev - this->member,
	   this->member[n].next - this->member,
	   this->member[n].addr.s_addr
	   );
  }
  return 0;
}


unsigned long int ippool_hash4(struct in_addr *addr) {
  return lookup(&addr->s_addr, sizeof(addr->s_addr), 0);
}

#ifndef IPPOOL_NOIP6
unsigned long int ippool_hash6(struct in6_addr *addr) {
  return lookup(addr->u6_addr8, sizeof(addr->u6_addr8), 0);
}
#endif


/* Get IP address and mask */
int ippool_aton(struct in_addr *addr, struct in_addr *mask,
		char *pool, int number) {

  /* Parse only first instance of network for now */
  /* Eventually "number" will indicate the token which we want to parse */

  unsigned int a1, a2, a3, a4;
  unsigned int m1, m2, m3, m4;
  int c;
  unsigned int m;
  int masklog;

  c = sscanf(pool, "%u.%u.%u.%u/%u.%u.%u.%u",
	     &a1, &a2, &a3, &a4,
	     &m1, &m2, &m3, &m4);
  switch (c) {
  case 4:
    if (a1 == 0 && a2 == 0 && a3 == 0 && a4 == 0) /* Full Internet */
      mask->s_addr = 0x00000000;
    else if (a2 == 0 && a3 == 0 && a4 == 0)       /* class A */
      mask->s_addr = htonl(0xff000000);
    else if (a3 == 0 && a4 == 0)	          /* class B */
      mask->s_addr = htonl(0xffff0000);
    else if (a4 == 0)	                          /* class C */
      mask->s_addr = htonl(0xffffff00);
    else
      mask->s_addr = 0xffffffff;
    break;
  case 5:
    if (m1 < 0 || m1 > 32) {
      return -1; /* Invalid mask */
    }
    mask->s_addr = htonl(0xffffffff << (32 - m1));
    break;
  case 8:
    if (m1 >= 256 ||  m2 >= 256 || m3 >= 256 || m4 >= 256)
      return -1; /* Wrong mask format */
    m = m1 * 0x1000000 + m2 * 0x10000 + m3 * 0x100 + m4;
    for (masklog = 0; ((1 << masklog) < ((~m)+1)); masklog++);
    if (((~m)+1) != (1 << masklog))
      return -1; /* Wrong mask format (not all ones followed by all zeros)*/
    mask->s_addr = htonl(m);
    break;
  default:
    return -1; /* Invalid mask */
  }

  if (a1 >= 256 ||  a2 >= 256 || a3 >= 256 || a4 >= 256)
    return -1; /* Wrong IP address format */
  else
    addr->s_addr = htonl(a1 * 0x1000000 + a2 * 0x10000 + a3 * 0x100 + a4);

  return 0;
}

/* Create new address pool */
int ippool_new(struct ippool_t **this, char *pool, int flags) {

  /* Parse only first instance of network for now */

  int i;
  struct ippoolm_t *p;
  struct ippoolm_t *p_prev = NULL; 
  uint32_t hash;
  struct in_addr addr;
  struct in_addr mask;
  unsigned int m;
  unsigned int listsize;

  if (ippool_aton(&addr, &mask, pool, 0))
    return 0; /* Failed to parse pool */

  m = ntohl(mask.s_addr);
  listsize = ((~m)+1);
  if (flags & IPPOOL_NONETWORK)   /* Exclude network address from pool */
    listsize--;
  if (flags & IPPOOL_NOBROADCAST) /* Exclude broadcast address from pool */
    listsize--;

  if (!(*this = calloc(sizeof(struct ippool_t), 1))) {
    /* Failed to allocate memory for ippool */
    return -1;
  }
  
  (*this)->listsize += listsize;
  if (!((*this)->member = calloc(sizeof(struct ippoolm_t), (*this)->listsize))){
    /* Failed to allocate memory for members in ippool */
    return -1;
  }
  
  for ((*this)->hashlog = 0; 
       ((1 << (*this)->hashlog) < listsize);
       (*this)->hashlog++);

  /*   printf ("Hashlog %d %d %d\n", (*this)->hashlog, listsize, (1 << (*this)->hashlog)); */

  /* Determine hashsize */
  (*this)->hashsize = 1 << (*this)->hashlog; /* Fails if mask=0: All Internet*/
  (*this)->hashmask = (*this)->hashsize -1;
  
  /* Allocate hash table */
  if (!((*this)->hash = calloc(sizeof(struct ippoolm_t), (*this)->hashsize))){
    /* Failed to allocate memory for hash members in ippool */
    return -1;
  }
  
  (*this)->first = NULL;
  (*this)->last = NULL;
  for (i = 0; i<(*this)->listsize; i++) {

    if (flags & IPPOOL_NONETWORK)
      (*this)->member[i].addr.s_addr = htonl(ntohl(addr.s_addr) + i + 1);
    else
      (*this)->member[i].addr.s_addr = htonl(ntohl(addr.s_addr) + i);

    (*this)->member[i].inuse = 0;
    (*this)->member[i].parent = *this;

    /* Insert into list of unused */
    (*this)->member[i].prev = (*this)->last;
    if ((*this)->last) {
      (*this)->last->next = &((*this)->member[i]);
    }
    else {
      (*this)->first = &((*this)->member[i]);
    }
    (*this)->last = &((*this)->member[i]);
    (*this)->member[i].next = NULL; /* Redundant */

    /* Insert into hash table */
    hash = ippool_hash4(&(*this)->member[i].addr) & (*this)->hashmask;
    for (p = (*this)->hash[hash]; p; p = p->nexthash)
      p_prev = p;
    if (!p_prev)
      (*this)->hash[hash] = &((*this)->member[i]);
    else 
      p_prev->nexthash = &((*this)->member[i]);
  }
  /*ippool_printaddr(*this);*/
  return 0;
}

/* Delete existing address pool */
int ippool_free(struct ippool_t *this) {
  free(this->hash);
  free(this->member);
  free(this);
  return 0; /* Always OK */
}

/* Find an IP address in the pool */
int ippool_getip(struct ippool_t *this, struct ippoolm_t **member,
		 struct in_addr *addr) {
  struct ippoolm_t *p;
  uint32_t hash;

  /* Find in hash table */
  hash = ippool_hash4(addr) & this->hashmask;
  for (p = this->hash[hash]; p; p = p->nexthash) {
    if ((p->addr.s_addr == addr->s_addr) && (p->inuse)) {
      *member = p;
      return 0;
    }
  }
  *member = NULL;
  return -1; /* Address could not be found */
}


/* Get an IP address. If addr = 0.0.0.0 get a dynamic IP address. Otherwise
   check to see if the given address is available */
int ippool_newip(struct ippool_t *this, struct ippoolm_t **member,
		 struct in_addr *addr) {
  struct ippoolm_t *p;
  struct ippoolm_t *p2 = NULL;
  uint32_t hash;

  /*ippool_printaddr(this);*/

  if ((addr) && (addr->s_addr)) { /* IP address given */
    /* Find in hash table */
    hash = ippool_hash4(addr) & this->hashmask;
    for (p = this->hash[hash]; p; p = p->nexthash) {
      if ((p->addr.s_addr == addr->s_addr)) {
	p2 = p;
	break;
      }
    }
  }
  else { /* No ip address given */
    p2 = this -> first;
  }

  if (!p2) return -1; /* Not found */
  if (p2->inuse) return -1; /* Allready in use / Should not happen */
  
  /* Found new address. Remove from queue */
  if (p2->prev) 
    p2->prev->next = p2->next;
  else
    this->first = p2->next;
  if (p2->next) 
    p2->next->prev = p2->prev;
  else
    this->last = p2->prev;
  p2->next = NULL;
  p2->prev = NULL;
  p2->inuse = 1;
  
  *member = p2;
  /*ippool_printaddr(this);*/
  return 0; /* Success */
}


int ippool_freeip(struct ippoolm_t *member) {
  struct ippool_t *this = member->parent;
  
  /*ippool_printaddr(this);*/

  if (!member->inuse) return -1; /* Not in use: Should not happen */

  /* Insert into list of unused */
  member->prev = this->last;
  if (this->last) {
    this->last->next = member;
  }
  else {
    this->first = member;
  }
  this->last = member;

  member->inuse = 0;
  /*ippool_printaddr(this);*/
  
  return 0; /* Success */
}


#ifndef IPPOOL_NOIP6
extern unsigned long int ippool_hash6(struct in6_addr *addr);
extern int ippool_getip6(struct ippool_t *this, struct in6_addr *addr);
extern int ippool_returnip6(struct ippool_t *this, struct in6_addr *addr);
#endif
