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
 * Queue.c
 * Reliable delivery of signalling messages
 */

#ifndef _QUEUE_H
#define _QUEUE_H

#define QUEUE_DEBUG 0     /* Print debug information */

#define QUEUE_SIZE 1024   /* Size of retransmission queue */
#define QUEUE_HASH_SIZE 65536 /* Size of hash table (2^16) */

struct qmsg_t {           /* Holder for queued packets */
  int state;              /* 0=empty, 1=full */
  uint16_t seq;           /* The sequence number */
  uint8_t type;           /* The type of packet */
  void *cbp;              /* Application specific pointer */
  union gtp_packet p;     /* The packet stored */
  int l;                  /* Length of the packet */
  int fd;                 /* Socket packet was sent to / received from */
  struct sockaddr_in peer;/* Address packet was sent to / received from */
  struct qmsg_t *seqnext; /* Pointer to next in sequence hash list */
  int next;               /* Pointer to the next in queue. -1: Last */
  int prev;               /* Pointer to the previous in queue. -1: First */
  int this;               /* Pointer to myself */
  time_t timeout;         /* When do we retransmit this packet? */
  int retrans;            /* How many times did we retransmit this? */
};

struct queue_t {
  struct qmsg_t qmsga[QUEUE_SIZE]; /* Array holding signalling messages */
  void *hashseq[QUEUE_HASH_SIZE];    /* Hash array */
  int next;               /* Next location in queue to use */
  int first;              /* First packet in queue (oldest timeout) */
  int last;               /* Last packet in queue (youngest timeout) */
};


/*  Allocates and initialises new queue structure */
int queue_new(struct queue_t **queue);
/*  Deallocates queue structure */
int queue_free(struct queue_t *queue);
/* Find a new queue element. Return EOF if allready full */
int queue_newmsg(struct queue_t *queue, struct qmsg_t **qmsg,
		 struct sockaddr_in *peer, uint16_t seq);
/* Remove an element from the queue. */
int queue_freemsg(struct queue_t *queue, struct qmsg_t *qmsg);
/* Move an element to the back of the queue */
int queue_back(struct queue_t *queue, struct qmsg_t *qmsg);
/* Get the first element in the queue (oldest) */
int queue_getfirst(struct queue_t *queue, struct qmsg_t **qmsg);
/* Get the element with a particular sequence number */
int queue_seqget(struct queue_t *queue, struct qmsg_t **qmsg,
		 struct sockaddr_in  *peer, uint16_t seq);
/* Free message based on sequence number */
int queue_freemsg_seq(struct queue_t *queue, struct sockaddr_in *peer,
		      uint16_t seq, uint8_t *type, void **cbp);


#endif	/* !_QUEUE_H */

