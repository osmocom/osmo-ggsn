/*
 * IP address pool functions.
 * Copyright (C) 2003, 2004 Mondru AB.
 * Copyright (C) 2017 by Harald Welte <laforge@gnumonks.org>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

#include <sys/types.h>
#include <netinet/in.h>		/* in_addr */
#include <stdlib.h>		/* calloc */
#include <stdio.h>		/* sscanf */
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "syserr.h"
#include "ippool.h"
#include "lookup.h"

int ippool_printaddr(struct ippool_t *this)
{
	unsigned int n;
	printf("ippool_printaddr\n");
	printf("Firstdyn %d\n", this->firstdyn - this->member);
	printf("Lastdyn %d\n", this->lastdyn - this->member);
	printf("Firststat %d\n", this->firststat - this->member);
	printf("Laststat %d\n", this->laststat - this->member);
	printf("Listsize %d\n", this->listsize);

	for (n = 0; n < this->listsize; n++) {
		char s[256];
		in46a_ntop(&this->member[n].addr, s, sizeof(s));
		printf("Unit %d inuse %d prev %d next %d addr %s\n",
		       n,
		       this->member[n].inuse,
		       this->member[n].prev - this->member,
		       this->member[n].next - this->member,
		       s);
	}
	return 0;
}

int ippool_hashadd(struct ippool_t *this, struct ippoolm_t *member)
{
	uint32_t hash;
	struct ippoolm_t *p;
	struct ippoolm_t *p_prev = NULL;

	/* Insert into hash table */
	hash = ippool_hash(&member->addr) & this->hashmask;
	for (p = this->hash[hash]; p; p = p->nexthash)
		p_prev = p;
	if (!p_prev)
		this->hash[hash] = member;
	else
		p_prev->nexthash = member;
	return 0;		/* Always OK to insert */
}

int ippool_hashdel(struct ippool_t *this, struct ippoolm_t *member)
{
	uint32_t hash;
	struct ippoolm_t *p;
	struct ippoolm_t *p_prev = NULL;

	/* Find in hash table */
	hash = ippool_hash(&member->addr) & this->hashmask;
	for (p = this->hash[hash]; p; p = p->nexthash) {
		if (p == member) {
			break;
		}
		p_prev = p;
	}

	if (p != member) {
		SYS_ERR(DIP, LOGL_ERROR, 0,
			"ippool_hashdel: Tried to delete member not in hash table");
		return -1;
	}

	if (!p_prev)
		this->hash[hash] = p->nexthash;
	else
		p_prev->nexthash = p->nexthash;

	return 0;
}

static unsigned long int ippool_hash4(struct in_addr *addr)
{
	return lookup((unsigned char *)&addr->s_addr, sizeof(addr->s_addr), 0);
}

static unsigned long int ippool_hash6(struct in6_addr *addr, unsigned int len)
{
	/* TODO: Review hash spread for IPv6 */
	return lookup((unsigned char *)addr->s6_addr, len, 0);
}

unsigned long int ippool_hash(struct in46_addr *addr)
{
	if (addr->len == 4)
		return ippool_hash4(&addr->v4);
	else
		return ippool_hash6(&addr->v6, addr->len);
}

/* Get IP address and mask */
int ippool_aton(struct in46_addr *addr, size_t *prefixlen, const char *pool_in, int number)
{
	struct addrinfo *ai;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = 0,
		.ai_protocol = 0
	};
	char pool[strlen(pool_in)+1];

	strcpy(pool, pool_in);

	int err;

	/* Find '/' and point to first char after it */
	char *prefixlen_str = strchr(pool, '/');
	if (prefixlen_str) {
		*prefixlen_str = '\0';
		prefixlen_str++;
		if (*prefixlen_str == '\0') {
			SYS_ERR(DIP, LOGL_ERROR, 0, "Empty prefix length specified");
			return -1;
		}
	}

	/* convert address */
	if ((err = getaddrinfo(pool, NULL, &hints, &ai))) {
		SYS_ERR(DIP, LOGL_ERROR, 0, "Bad address");
		return -1;
	}

	/* Copy address, set lengths */
	if (ai->ai_family == AF_INET) {
		*prefixlen = 32;
		addr->len = sizeof(struct in_addr);
		addr->v4 = ((struct sockaddr_in*)ai->ai_addr)->sin_addr;
	} else {
		*prefixlen = 128;
		addr->len = sizeof(struct in6_addr);
		addr->v6 = ((struct sockaddr_in6*)ai->ai_addr)->sin6_addr;
	}
	freeaddrinfo(ai);

	/* parse prefixlen */
	if (prefixlen_str) {
		char *e;
		*prefixlen = strtol(prefixlen_str, &e, 10);
		if (*e != '\0') {
			SYS_ERR(DIP, LOGL_ERROR, 0, "Prefixlen is not an int");
			return -1;
		}
	}

	if (*prefixlen > (addr->len * 8)) {
		SYS_ERR(DIP, LOGL_ERROR, 0, "Perfixlen too big");
		return -1;
	}

	return 0;
}

/* Increase IPv4/IPv6 address by 1 */
void in46a_inc(struct in46_addr *addr)
{
	size_t addrlen;
	uint8_t *a = (uint8_t *)&addr->v6;
	for (addrlen = addr->len; addrlen > 0; addrlen--) {
		if (++a[addrlen-1])
			break;
	}
}

static bool addr_in_prefix_list(struct in46_addr *addr, struct in46_prefix *list, size_t list_size)
{
	int i;
	for (i = 0; i < list_size; i++) {
		if (in46a_prefix_equal(addr, &list[i].addr))
			return true;
	}
	return false;
}

/* Create new address pool */
int ippool_new(struct ippool_t **this, const struct in46_prefix *dyn, const struct in46_prefix *stat,
	       int flags, struct in46_prefix *blacklist, size_t blacklist_size)
{

	/* Parse only first instance of pool for now */

	int i;
	struct in46_addr addr;
	size_t addrprefixlen;
	struct in46_addr stataddr;
	size_t stataddrprefixlen;
	int listsize;
	int dynsize;
	unsigned int statsize;

	if (!dyn || dyn->addr.len == 0) {
		dynsize = 0;
	} else {
		addr = dyn->addr;
		addrprefixlen = dyn->prefixlen;
		/* we want to work with /64 prefixes, i.e. allocate /64 prefixes rather
		 * than /128 (single IPv6 addresses) */
		if (addr.len == sizeof(struct in6_addr))
			addr.len = 64/8;

		dynsize = (1 << (addr.len*8 - addrprefixlen));
		if (flags & IPPOOL_NONETWORK)	/* Exclude network address from pool */
			dynsize--;
		if (flags & IPPOOL_NOBROADCAST)	/* Exclude broadcast address from pool */
			dynsize--;
		/* Exclude included blacklist addresses from pool */
		for (i = 0; i < blacklist_size; i++) {
			if (in46a_within_mask(&blacklist[i].addr, &addr, addrprefixlen))
				dynsize--;
		}
	}

	if (!stat || stat->addr.len == 0) {
		statsize = 0;
		stataddr.len = 0;
		stataddrprefixlen = 0;
	} else {
		stataddr = stat->addr;
		stataddrprefixlen = stat->prefixlen;

		statsize = (1 << (addr.len - stataddrprefixlen + 1)) -1;
		if (statsize > IPPOOL_STATSIZE)
			statsize = IPPOOL_STATSIZE;
	}

	listsize = dynsize + statsize;	/* Allocate space for static IP addresses */

	if (!(*this = calloc(sizeof(struct ippool_t), 1))) {
		SYS_ERR(DIP, LOGL_ERROR, 0,
			"Failed to allocate memory for ippool");
		return -1;
	}

	(*this)->allowdyn = dyn ? 1 : 0;
	(*this)->allowstat = stat ? 1 : 0;
	if (stataddr.len > 0)
		(*this)->stataddr = stataddr;
	(*this)->stataddrprefixlen = stataddrprefixlen;

	(*this)->listsize += listsize;
	if (!((*this)->member = calloc(sizeof(struct ippoolm_t), listsize))) {
		SYS_ERR(DIP, LOGL_ERROR, 0,
			"Failed to allocate memory for members in ippool");
		return -1;
	}

	for ((*this)->hashlog = 0;
	     ((1 << (*this)->hashlog) < listsize); (*this)->hashlog++) ;

	/*   printf ("Hashlog %d %d %d\n", (*this)->hashlog, listsize, (1 << (*this)->hashlog)); */

	/* Determine hashsize */
	(*this)->hashsize = 1 << (*this)->hashlog;	/* Fails if mask=0: All Internet */
	(*this)->hashmask = (*this)->hashsize - 1;

	/* Allocate hash table */
	if (!
	    ((*this)->hash =
	     calloc(sizeof(struct ippoolm_t), (*this)->hashsize))) {
		SYS_ERR(DIP, LOGL_ERROR, 0,
			"Failed to allocate memory for hash members in ippool");
		return -1;
	}

	(*this)->firstdyn = NULL;
	(*this)->lastdyn = NULL;
	if (flags & IPPOOL_NONETWORK) {
		in46a_inc(&addr);
	}
	for (i = 0; i < dynsize; i++) {
		if (addr_in_prefix_list(&addr, blacklist, blacklist_size)) {
			SYS_ERR(DIP, LOGL_DEBUG, 0,
				"addr blacklisted from pool: %s", in46a_ntoa(&addr));
			in46a_inc(&addr);
			i--;
			continue;
		}
		(*this)->member[i].addr = addr;
		in46a_inc(&addr);

		(*this)->member[i].inuse = 0;
		(*this)->member[i].pool = *this;

		/* Insert into list of unused */
		(*this)->member[i].prev = (*this)->lastdyn;
		if ((*this)->lastdyn) {
			(*this)->lastdyn->next = &((*this)->member[i]);
		} else {
			(*this)->firstdyn = &((*this)->member[i]);
		}
		(*this)->lastdyn = &((*this)->member[i]);
		(*this)->member[i].next = NULL;	/* Redundant */

		(void)ippool_hashadd(*this, &(*this)->member[i]);
	}

	(*this)->firststat = NULL;
	(*this)->laststat = NULL;
	for (i = dynsize; i < listsize; i++) {
		struct in46_addr *i6al = &(*this)->member[i].addr;
		memset(i6al, 0, sizeof(*i6al));
		(*this)->member[i].inuse = 0;
		(*this)->member[i].pool = *this;

		/* Insert into list of unused */
		(*this)->member[i].prev = (*this)->laststat;
		if ((*this)->laststat) {
			(*this)->laststat->next = &((*this)->member[i]);
		} else {
			(*this)->firststat = &((*this)->member[i]);
		}
		(*this)->laststat = &((*this)->member[i]);
		(*this)->member[i].next = NULL;	/* Redundant */
	}

	if (0)
		(void)ippool_printaddr(*this);
	return 0;
}

/* Delete existing address pool */
int ippool_free(struct ippool_t *this)
{
	free(this->hash);
	free(this->member);
	free(this);
	return 0;		/* Always OK */
}

/* Find an IP address in the pool */
int ippool_getip(struct ippool_t *this, struct ippoolm_t **member,
		 struct in46_addr *addr)
{
	struct ippoolm_t *p;
	uint32_t hash;

	/* Find in hash table */
	hash = ippool_hash(addr) & this->hashmask;
	for (p = this->hash[hash]; p; p = p->nexthash) {
		if (in46a_prefix_equal(&p->addr, addr)) {
			if (member)
				*member = p;
			return 0;
		}
	}
	if (member)
		*member = NULL;
	/*SYS_ERR(DIP, LOGL_ERROR, 0, "Address could not be found"); */
	return -1;
}

/**
 * ippool_newip
 * Get an IP address. If addr = 0.0.0.0 get a dynamic IP address. Otherwise
 * check to see if the given address is available. If available within
 * dynamic address space allocate it there, otherwise allocate within static
 * address space.
**/
int ippool_newip(struct ippool_t *this, struct ippoolm_t **member,
		 struct in46_addr *addr, int statip)
{
	struct ippoolm_t *p;
	struct ippoolm_t *p2 = NULL;
	uint32_t hash;

	/* If static:
	 *   Look in dynaddr.
	 *     If found remove from firstdyn/lastdyn linked list.
	 *   Else allocate from stataddr.
	 *    Remove from firststat/laststat linked list.
	 *    Insert into hash table.
	 *
	 * If dynamic
	 *   Remove from firstdyn/lastdyn linked list.
	 *
	 */

	if (0)
		(void)ippool_printaddr(this);

	int specified = 0;
	if (addr) {
		if (addr->len == 4 && addr->v4.s_addr)
			specified = 1;
		if (addr->len == 16 && !IN6_IS_ADDR_UNSPECIFIED(&addr->v6))
			specified = 1;
	}

	/* First check to see if this type of address is allowed */
	if (specified && statip) {	/* IP address given */
		if (!this->allowstat) {
			SYS_ERR(DIP, LOGL_ERROR, 0,
				"Static IP address not allowed");
			return -GTPCAUSE_NOT_SUPPORTED;
		}
		if (!in46a_within_mask(addr, &this->stataddr, this->stataddrprefixlen)) {
			SYS_ERR(DIP, LOGL_ERROR, 0, "Static out of range");
			return -1;
		}
	} else {
		if (!this->allowdyn) {
			SYS_ERR(DIP, LOGL_ERROR, 0,
				"Dynamic IP address not allowed");
			return -GTPCAUSE_NOT_SUPPORTED;
		}
	}

	/* If IP address given try to find it in dynamic address pool */
	if (specified) {	/* IP address given */
		/* Find in hash table */
		hash = ippool_hash(addr) & this->hashmask;
		for (p = this->hash[hash]; p; p = p->nexthash) {
			if (in46a_prefix_equal(&p->addr, addr)) {
				p2 = p;
				break;
			}
		}
	}

	/* If IP was already allocated we can not use it */
	if ((!statip) && (p2) && (p2->inuse)) {
		p2 = NULL;
	}

	/* If not found yet and dynamic IP then allocate dynamic IP */
	if ((!p2) && (!statip)) {
		if (!this->firstdyn) {
			SYS_ERR(DIP, LOGL_ERROR, 0,
				"No more IP addresses available");
			return -GTPCAUSE_ADDR_OCCUPIED;
		} else
			p2 = this->firstdyn;
	}

	if (p2) {		/* Was allocated from dynamic address pool */
		if (p2->inuse) {
			SYS_ERR(DIP, LOGL_ERROR, 0,
				"IP address allready in use");
			return -GTPCAUSE_SYS_FAIL;	/* Allready in use / Should not happen */
		}

		if (p2->addr.len != addr->len && !(addr->len == 16 && p2->addr.len == 8)) {
			SYS_ERR(DIP, LOGL_ERROR, 0, "MS requested unsupported PDP context type");
			return -GTPCAUSE_UNKNOWN_PDP;
		}

		/* Remove from linked list of free dynamic addresses */
		if (p2->prev)
			p2->prev->next = p2->next;
		else
			this->firstdyn = p2->next;
		if (p2->next)
			p2->next->prev = p2->prev;
		else
			this->lastdyn = p2->prev;
		p2->next = NULL;
		p2->prev = NULL;
		p2->inuse = 1;	/* Dynamic address in use */

		*member = p2;
		if (0)
			(void)ippool_printaddr(this);
		return 0;	/* Success */
	}

	/* It was not possible to allocate from dynamic address pool */
	/* Try to allocate from static address space */

	if (specified  && (statip)) {	/* IP address given */
		if (!this->firststat) {
			SYS_ERR(DIP, LOGL_ERROR, 0,
				"No more IP addresses available");
			return -GTPCAUSE_ADDR_OCCUPIED;	/* No more available */
		} else
			p2 = this->firststat;

		if (p2->addr.len != addr->len) {
			SYS_ERR(DIP, LOGL_ERROR, 0, "MS requested unsupported PDP context type");
			return -GTPCAUSE_UNKNOWN_PDP;
		}

		/* Remove from linked list of free static addresses */
		if (p2->prev)
			p2->prev->next = p2->next;
		else
			this->firststat = p2->next;
		if (p2->next)
			p2->next->prev = p2->prev;
		else
			this->laststat = p2->prev;
		p2->next = NULL;
		p2->prev = NULL;
		p2->inuse = 2;	/* Static address in use */
		memcpy(&p2->addr, addr, sizeof(addr));
		*member = p2;
		(void)ippool_hashadd(this, *member);
		if (0)
			(void)ippool_printaddr(this);
		return 0;	/* Success */
	}

	SYS_ERR(DIP, LOGL_ERROR, 0,
		"Could not allocate IP address");
	return -GTPCAUSE_SYS_FAIL;		/* Should never get here. TODO: Bad code */
}

int ippool_freeip(struct ippool_t *this, struct ippoolm_t *member)
{

	if (0)
		(void)ippool_printaddr(this);

	if (!member->inuse) {
		SYS_ERR(DIP, LOGL_ERROR, 0, "Address not in use");
		return -1;	/* Not in use: Should not happen */
	}

	switch (member->inuse) {
	case 0:		/* Not in use: Should not happen */
		SYS_ERR(DIP, LOGL_ERROR, 0, "Address not in use");
		return -1;
	case 1:		/* Allocated from dynamic address space */
		/* Insert into list of unused */
		member->prev = this->lastdyn;
		if (this->lastdyn) {
			this->lastdyn->next = member;
		} else {
			this->firstdyn = member;
		}
		this->lastdyn = member;

		member->inuse = 0;
		member->peer = NULL;
		if (0)
			(void)ippool_printaddr(this);
		return 0;
	case 2:		/* Allocated from static address space */
		if (ippool_hashdel(this, member))
			return -1;
		/* Insert into list of unused */
		member->prev = this->laststat;
		if (this->laststat) {
			this->laststat->next = member;
		} else {
			this->firststat = member;
		}
		this->laststat = member;

		member->inuse = 0;
		memset(&member->addr, 0, sizeof(member->addr));
		member->peer = NULL;
		member->nexthash = NULL;
		if (0)
			(void)ippool_printaddr(this);
		return 0;
	default:		/* Should not happen */
		SYS_ERR(DIP, LOGL_ERROR, 0,
			"Could not free IP address");
		return -1;
	}
}
