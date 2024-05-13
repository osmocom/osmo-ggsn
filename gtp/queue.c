/*
 *  OsmoGGSN - Gateway GPRS Support Node
 *  Copyright (C) 2002, 2003, 2004 Mondru AB.
 *  Copyright (C) 2011 Harald Welte <laforge@gnumonks.org>
 *  Copyright (C) 2016 sysmocom - s.f.m.c. GmbH
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

#include <osmocom/gtp/pdp.h>
#include <osmocom/gtp/gtp.h>

#include "queue.h"

/*! \brief dump a queue_t to stdout */
static int queue_print(struct queue_t *queue)
{
	int n;
	printf("Queue: %p Next: %d First: %d Last: %d\n", queue,
	       queue->next, queue->first, queue->last);
	printf("# State seq next prev timeout retrans\n");
	for (n = 0; n < QUEUE_SIZE; n++) {
		printf("%d %d %d %d %d %d %d\n",
		       n,
		       queue->qmsga[n].state,
		       queue->qmsga[n].seq,
		       queue->qmsga[n].next,
		       queue->qmsga[n].prev,
		       (int)queue->qmsga[n].timeout, queue->qmsga[n].retrans);
	}
	return 0;
}

/*! \brief compute the hash function */
static int queue_seqhash(struct sockaddr_in *peer, uint16_t seq)
{
	/* With QUEUE_HASH_SIZE = 2^16 this describes all possible
	   seq values. Thus we have perfect hash for the request queue.
	   For the response queue we might have collisions, but not very
	   often.
	   For performance optimisation we should remove the modulus
	   operator, but this is only valid for QUEUE_HASH_SIZE = 2^16 */
	return seq % QUEUE_HASH_SIZE;
}

/*! \brief Insert a message with given sequence number into the hash.
 *
 * This function sets the peer and the seq of the qmsg and then inserts
 * the qmsg into the queue hash.  To do so, it does a hashtable lookup
 * and appends the new entry as the last into the double-linked list of
 * entries for this sequence number.
 */
static int queue_seqset(struct queue_t *queue, struct qmsg_t *qmsg,
		 	struct sockaddr_in *peer, uint16_t seq)
{
	int hash = queue_seqhash(peer, seq);
	struct qmsg_t *qmsg2;
	struct qmsg_t *qmsg_prev = NULL;

	if (QUEUE_DEBUG)
		printf("Begin queue_seqset seq = %d\n", (int)seq);
	if (QUEUE_DEBUG)
		printf("SIZEOF PEER %zu, *PEER %zu\n", sizeof(peer),
		       sizeof(*peer));

	qmsg->seq = seq;
	memcpy(&qmsg->peer, peer, sizeof(*peer));

	for (qmsg2 = queue->hashseq[hash]; qmsg2; qmsg2 = qmsg2->seqnext)
		qmsg_prev = qmsg2;
	if (!qmsg_prev)
		queue->hashseq[hash] = qmsg;
	else
		qmsg_prev->seqnext = qmsg;
	if (QUEUE_DEBUG)
		printf("End queue_seqset\n");
	return 0;
}

/*! \brief Remove a given qmsg_t from the queue hash */
static int queue_seqdel(struct queue_t *queue, struct qmsg_t *qmsg)
{
	int hash = queue_seqhash(&qmsg->peer, qmsg->seq);
	struct qmsg_t *qmsg2;
	struct qmsg_t *qmsg_prev = NULL;
	if (QUEUE_DEBUG)
		printf("Begin queue_seqdel seq = %d\n", (int)qmsg->seq);

	for (qmsg2 = queue->hashseq[hash]; qmsg2; qmsg2 = qmsg2->seqnext) {
		if (qmsg == qmsg2) {
			if (!qmsg_prev)
				queue->hashseq[hash] = qmsg2->seqnext;
			else
				qmsg_prev->seqnext = qmsg2->seqnext;
			if (QUEUE_DEBUG)
				printf("End queue_seqdel: SEQ found\n");
			return 0;
		}
		qmsg_prev = qmsg2;
	}
	printf("End queue_seqdel: SEQ not found\n");
	return EOF;		/* End of linked list and not found */
}

/*! Allocates and initialises new queue structure.
 *  \param[out] queue pointer where to store the allocated object. Must be freed with queue_free
 *  \returns zero on success, non-zero on error
 */
int queue_new(struct queue_t **queue)
{
	if (QUEUE_DEBUG)
		printf("queue_new\n");
	*queue = calloc(1, sizeof(struct queue_t));
	if (!(*queue))
		return EOF;
	(*queue)->next = 0;
	(*queue)->first = -1;
	(*queue)->last = -1;

	if (QUEUE_DEBUG)
		queue_print(*queue);
	return 0;
}

/*! Deallocates queue structure.
 *  \param[in] queue pointer previously allocated by queue_new
 *  \returns zero on success, non-zero on error.
 */
int queue_free(struct queue_t *queue)
{
	if (QUEUE_DEBUG)
		printf("queue_free\n");
	if (QUEUE_DEBUG)
		queue_print(queue);
	free(queue);
	return 0;
}

/*! Add a new message to the queue.
 *  \param[in] queue pointer previously allocated by queue_new
 *  \param[out] qmsg first message from the queue (if succeeds)
 *  \param[in] peer who sent the message to add
 *  \param[in] seq sequence number of the message to add
 *  \returns zero on success, non-zero on error.
 */
int queue_newmsg(struct queue_t *queue, struct qmsg_t **qmsg,
		 struct sockaddr_in *peer, uint16_t seq)
{
	if (QUEUE_DEBUG)
		printf("queue_newmsg %d\n", (int)seq);
	if (queue->qmsga[queue->next].state == 1) {
		return EOF;	/* Queue is full */
	} else {
		*qmsg = &queue->qmsga[queue->next];
		queue_seqset(queue, *qmsg, peer, seq);
		INIT_LLIST_HEAD(&(*qmsg)->entry);
		(*qmsg)->state = 1;	/* Space taken */
		(*qmsg)->this = queue->next;
		(*qmsg)->next = -1;	/* End of the queue */
		(*qmsg)->prev = queue->last;	/* Link to the previous */
		if (queue->last != -1)
			queue->qmsga[queue->last].next = queue->next;	/* Link previous to us */
		queue->last = queue->next;	/* End of queue */
		if (queue->first == -1)
			queue->first = queue->next;
		queue->next = (queue->next + 1) % QUEUE_SIZE;	/* Increment */
		if (QUEUE_DEBUG)
			queue_print(queue);
		return 0;
	}
}


/*! Remove an element from the queue.
 *  \param[in] queue pointer previously allocated by queue_new
 *  \param[in] qmsg message to free
 *  \returns zero on success, non-zero on error.
 *
 * Internally, we first delete the entry from the queue, and then update
 * up our global queue->first / queue->last pointers.  Finally,
 * the qmsg_t is re-initialized with zero bytes.  No memory is released.
 */
int queue_freemsg(struct queue_t *queue, struct qmsg_t *qmsg)
{
	if (QUEUE_DEBUG)
		printf("queue_freemsg\n");
	if (qmsg->state != 1) {
		return EOF;	/* Not in queue */
	}

	llist_del(&qmsg->entry);

	queue_seqdel(queue, qmsg);

	if (qmsg->next == -1)	/* Are we the last in queue? */
		queue->last = qmsg->prev;
	else
		queue->qmsga[qmsg->next].prev = qmsg->prev;

	if (qmsg->prev == -1)	/* Are we the first in queue? */
		queue->first = qmsg->next;
	else
		queue->qmsga[qmsg->prev].next = qmsg->next;

	memset(qmsg, 0, sizeof(struct qmsg_t));	/* Just to be safe */

	if (QUEUE_DEBUG)
		queue_print(queue);

	return 0;
}

/*! Move a given qmsg_t to the end of the queue.
 *  \param[in] queue pointer previously allocated by queue_new
 *  \param[in] qmsg message to move to the end of the queue
 *  \returns zero on success, non-zero on error.
 */
int queue_back(struct queue_t *queue, struct qmsg_t *qmsg)
{
	if (QUEUE_DEBUG)
		printf("queue_back\n");
	if (qmsg->state != 1) {
		return EOF;	/* Not in queue */
	}

	/* Insert stuff to maintain hash table */

	if (qmsg->next != -1) {	/* Only swop if there are others */
		queue->qmsga[qmsg->next].prev = qmsg->prev;
		queue->first = qmsg->next;

		qmsg->next = -1;
		qmsg->prev = queue->last;
		if (queue->last != -1)
			queue->qmsga[queue->last].next = qmsg->this;
		queue->last = qmsg->this;
	}
	if (QUEUE_DEBUG)
		queue_print(queue);
	return 0;
}

/*! Get the first element in the entire queue.
 *  \param[in] queue pointer previously allocated by queue_new
 *  \param[out] qmsg first message from the queue (if succeeds)
 *  \returns zero on success, non-zero on error.
 */
int queue_getfirst(struct queue_t *queue, struct qmsg_t **qmsg)
{
	/*printf("queue_getfirst\n"); */
	if (queue->first == -1) {
		*qmsg = NULL;
		return EOF;	/* End of queue = queue is empty. */
	}
	*qmsg = &queue->qmsga[queue->first];
	if (QUEUE_DEBUG)
		queue_print(queue);
	return 0;
}

/*! Get a queue entry for a given peer + seq.
 *  \param[in] queue pointer previously allocated by queue_new
 *  \param[out] qmsg first message from the queue (if succeeds)
 *  \param[in] peer who sent the message to retrieve
 *  \param[in] seq sequence number of the message to retrive
 *  \returns zero on success, non-zero on error.
 */
int queue_seqget(struct queue_t *queue, struct qmsg_t **qmsg,
		 struct sockaddr_in *peer, uint16_t seq)
{
	int hash = queue_seqhash(peer, seq);
	struct qmsg_t *qmsg2;
	if (QUEUE_DEBUG)
		printf("Begin queue_seqget seq = %d\n", (int)seq);
	for (qmsg2 = queue->hashseq[hash]; qmsg2; qmsg2 = qmsg2->seqnext) {
		if ((qmsg2->seq == seq) &&
		    (!memcmp(&qmsg2->peer, peer, sizeof(*peer)))) {
			*qmsg = qmsg2;
			if (QUEUE_DEBUG)
				printf("End queue_seqget. Found\n");
			return 0;
		}
	}
	if (QUEUE_DEBUG)
		printf("End queue_seqget. Not found\n");
	return EOF;		/* End of linked list and not found */
}

/*! look-up a given seq/peer, return cbp + type and free entry.
 *  \param[in] queue pointer previously allocated by queue_new
 *  \param[in] peer who sent the message to retrieve
 *  \param[in] seq sequence number of the message to retrive
 *  \param[out] type GTP message type
 *  \param[out] type callback pointer of the message
 *  \returns zero on success, non-zero on error.
 */
int queue_freemsg_seq(struct queue_t *queue, struct sockaddr_in *peer,
		      uint16_t seq, uint8_t * type, void **cbp)
{
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
