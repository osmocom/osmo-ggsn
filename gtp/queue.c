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
 * Queue.c
 * Reliable delivery of signalling messages
 */

#include <../config.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <string.h>
#include "pdp.h"
#include "gtp.h"
#include "queue.h"

int queue_print(struct queue_t *queue) {
  int n;
  printf("Queue: %x Next: %d First: %d Last: %d\n", (int) queue, queue->next, queue->first, queue->last);
  printf("# State seq next prev timeout retrans\n");
  for (n=0; n<QUEUE_SIZE; n++) {
    printf("%d %d %d %d %d %d %d\n",
	   n,
	   queue->qmsga[n].state,
	   queue->qmsga[n].seq,
	   queue->qmsga[n].next,
	   queue->qmsga[n].prev,
	   (int) queue->qmsga[n].timeout,
	   queue->qmsga[n].retrans);
  }
  return 0;
}

int queue_seqhash(struct sockaddr_in *peer, uint16_t seq) {
  /* With QUEUE_HASH_SIZE = 2^16 this describes all possible
     seq values. Thus we have perfect hash for the request queue.
     For the response queue we might have collisions, but not very
     often.
     For performance optimisation we should remove the modulus
     operator, but this is only valid for QUEUE_HASH_SIZE = 2^16 */
  return seq % QUEUE_HASH_SIZE;
}

int queue_seqset(struct queue_t *queue, struct qmsg_t *qmsg,
		 struct sockaddr_in *peer, uint16_t seq) {
  int hash = queue_seqhash(peer, seq);
  struct qmsg_t *qmsg2;
  struct qmsg_t *qmsg_prev = NULL;

  if (QUEUE_DEBUG) printf("Begin queue_seqset seq = %d\n", (int) seq);
  if (QUEUE_DEBUG) printf("SIZEOF PEER %d, *PEER %d\n", sizeof(peer), sizeof(*peer));

  qmsg->seq = seq;
  memcpy(&qmsg->peer, peer, sizeof(*peer));

  for (qmsg2 = queue->hashseq[hash]; qmsg2; qmsg2 = qmsg2->seqnext)
    qmsg_prev = qmsg2;
  if (!qmsg_prev) 
    queue->hashseq[hash] = qmsg;
  else
    qmsg_prev->seqnext = qmsg;
  if (QUEUE_DEBUG) printf("End queue_seqset\n");
  return 0;
}


int queue_seqdel(struct queue_t *queue, struct qmsg_t *qmsg) {
  int hash = queue_seqhash(&qmsg->peer, qmsg->seq);
  struct qmsg_t *qmsg2;
  struct qmsg_t *qmsg_prev = NULL;
  if (QUEUE_DEBUG) printf("Begin queue_seqdel seq = %d\n", (int) qmsg->seq);

  for (qmsg2 = queue->hashseq[hash]; qmsg2; qmsg2 = qmsg2->seqnext) {
    if (qmsg == qmsg) {
      if (!qmsg_prev) 
	queue->hashseq[hash] = qmsg2->seqnext;
      else 
	qmsg_prev->seqnext = qmsg2->seqnext;
      if (QUEUE_DEBUG) printf("End queue_seqset: SEQ found\n");
      return 0;
    }
    qmsg_prev = qmsg2;
  }
  printf("End queue_seqset: SEQ not found\n");
  return EOF; /* End of linked list and not found */
}


/*  Allocates and initialises new queue structure */
int queue_new(struct queue_t **queue) {
  if (QUEUE_DEBUG) printf("queue_new\n");
  *queue = calloc(1, sizeof(struct queue_t));
  (*queue)->next = 0;
  (*queue)->first = -1;
  (*queue)->last = -1;

  if (QUEUE_DEBUG) queue_print(*queue);
  if (*queue) return 0;
  else return EOF;
}

/*  Deallocates queue structure */
int queue_free(struct queue_t *queue) {
  if (QUEUE_DEBUG) printf("queue_free\n");
  if (QUEUE_DEBUG) queue_print(queue);
  free(queue);
  return 0;
}

int queue_newmsg(struct queue_t *queue, struct qmsg_t **qmsg,
		 struct sockaddr_in *peer, uint16_t seq) {
  if (QUEUE_DEBUG) printf("queue_newmsg %d\n", (int) seq);
  if (queue->qmsga[queue->next].state == 1) {
    return EOF; /* Queue is full */
  }
  else {
    *qmsg = &queue->qmsga[queue->next];
    queue_seqset(queue, *qmsg, peer, seq);
    (*qmsg)->state = 1;    /* Space taken */
    (*qmsg)->this = queue->next;
    (*qmsg)->next=-1;       /* End of the queue */
    (*qmsg)->prev=queue->last; /* Link to the previous */
    if (queue->last != -1)
      queue->qmsga[queue->last].next=queue->next; /* Link previous to us */
    queue->last = queue->next;                  /* End of queue */
    if (queue->first == -1) queue->first = queue->next;
    queue->next = (queue->next+1) % QUEUE_SIZE;   /* Increment */
    if (QUEUE_DEBUG) queue_print(queue);
    return 0;
  }
}

int queue_freemsg(struct queue_t *queue, struct qmsg_t *qmsg) {
  if (QUEUE_DEBUG) printf("queue_freemsg\n");
  if (qmsg->state != 1) { 
    return EOF; /* Not in queue */
  }

  queue_seqdel(queue, qmsg);

  if (qmsg->next == -1) /* Are we the last in queue? */
    queue->last = qmsg->prev;
  else
    queue->qmsga[qmsg->next].prev = qmsg->prev;
    
  if (qmsg->prev == -1) /* Are we the first in queue? */
    queue->first = qmsg->next;
  else
    queue->qmsga[qmsg->prev].next = qmsg->next;

  memset(qmsg, 0, sizeof(struct qmsg_t)); /* Just to be safe */

  if (QUEUE_DEBUG) queue_print(queue);

  return 0;
}

int queue_back(struct queue_t *queue, struct qmsg_t *qmsg) {
  if (QUEUE_DEBUG) printf("queue_back\n");
  if (qmsg->state != 1) { 
    return EOF; /* Not in queue */
  }

  /* Insert stuff to maintain hash table */

  if (qmsg->next != -1) {/* Only swop if there are others */
    queue->qmsga[qmsg->next].prev = qmsg->prev;
    queue->first = qmsg->next;
    
    qmsg->next = -1;
    qmsg->prev = queue->last;
    if (queue->last != -1) queue->qmsga[queue->last].next = qmsg->this; 
    queue->last = qmsg->this;
  }
  if (QUEUE_DEBUG) queue_print(queue);
  return 0;
}

/* Get the element with a particular sequence number */
int queue_getfirst(struct queue_t *queue, struct qmsg_t **qmsg) {
  /*printf("queue_getfirst\n");*/
  if (queue->first == -1) {
    *qmsg = NULL;
    return EOF; /* End of queue = queue is empty. */
  }
  *qmsg = &queue->qmsga[queue->first];
  if (QUEUE_DEBUG) queue_print(queue);
  return 0;
}

int queue_getseqx(struct queue_t *queue, struct qmsg_t **qmsg,
		 struct sockaddr_in *peer, uint16_t seq) {
  int n;
  if (QUEUE_DEBUG) printf("queue_getseq, %d\n", (int) seq);
  if (QUEUE_DEBUG) queue_print(queue);
  for (n=0; n<QUEUE_SIZE; n++) {
    if ((queue->qmsga[n].seq == seq) &&
	(!memcmp(&queue->qmsga[n].peer, peer, sizeof(*peer)))) {
      *qmsg = &queue->qmsga[n];
      return 0;
    }
  }
  return EOF; /* Not found */
}

int queue_seqget(struct queue_t *queue, struct qmsg_t **qmsg,
		 struct sockaddr_in *peer, uint16_t seq) {
  int hash = queue_seqhash(peer, seq);
  struct qmsg_t *qmsg2;
  if (QUEUE_DEBUG) printf("Begin queue_seqget seq = %d\n", (int) seq);
  for (qmsg2 = queue->hashseq[hash]; qmsg2; qmsg2 = qmsg2->seqnext) {
    if ((qmsg2->seq == seq) && 
	(!memcmp(&qmsg2->peer, peer, sizeof(*peer)))) {
      *qmsg = qmsg2;
      if (QUEUE_DEBUG) printf("End queue_seqget. Found\n");
      return 0;
    }
  }
  if (QUEUE_DEBUG) printf("End queue_seqget. Not found\n");
  return EOF; /* End of linked list and not found */
}

int queue_freemsg_seq(struct queue_t *queue, struct sockaddr_in *peer, 
		      uint16_t seq, uint8_t *type, void **cbp) {
  struct qmsg_t *qmsg;
  if (queue_seqget(queue, &qmsg, peer, seq)) {
    *cbp = NULL;
    *type = 0;
    return EOF;
  }
  *cbp = qmsg->cbp;
  *type = qmsg->type;
  if (queue_freemsg(queue, qmsg)) {
    return EOF;
  }
  return 0;
}
