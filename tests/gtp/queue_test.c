#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/bits.h>

#include "../../lib/syserr.h"
#include "../../gtp/queue.h"

static const struct qmsg_t qmsg_zero;

static void queue_print(struct queue_t *queue, char* str)
{
	int n;
	printf("=== [Queue %s] Next: %d First: %d Last: %d\n", str,
		queue->next, queue->first, queue->last);
	printf("#\tseq\tnext\tprev\ttimeout\tretrans\ttype\tcbp\n");
	for (n = 0; n < QUEUE_SIZE; n++) {
		if (queue->qmsga[n].state == 0) {
			/* Nothing there, validate everything is zeroed */
			OSMO_ASSERT(memcmp(&qmsg_zero, &queue->qmsga[n], sizeof(qmsg_zero)) == 0);
			continue;
		}
		printf("%d\t%d\t%d\t%d\t%d\t%d\t%u\t%" PRIuPTR "\n",
		       n,
		       queue->qmsga[n].seq,
		       queue->qmsga[n].next,
		       queue->qmsga[n].prev,
		       (int)queue->qmsga[n].timeout,
		       queue->qmsga[n].retrans,
		       queue->qmsga[n].type,
		       (uintptr_t)queue->qmsga[n].cbp
		);
	}
	printf("======================================================\n");
}

static void test_queue_empty()
{
	printf("***** Testing %s()\n", __func__);
	struct queue_t *queue = NULL;
	struct qmsg_t *qmsg = NULL;
	uint16_t seq = 23;
	uint8_t type = 0;
	void *cbp = NULL;
	struct sockaddr_in peer;
	int rc;

	rc = inet_pton(AF_INET, "127.0.0.1", &(peer.sin_addr));
	OSMO_ASSERT(rc == 1);

	rc = queue_new(&queue);
	OSMO_ASSERT(rc == 0);
	queue_print(queue, "created");

	rc = queue_getfirst(queue, &qmsg);
	OSMO_ASSERT(rc == EOF);
	rc = queue_seqget(queue, &qmsg, &peer, seq);
	OSMO_ASSERT(rc == EOF);
	rc = queue_freemsg_seq(queue, &peer, seq, &type, &cbp);
	OSMO_ASSERT(rc==EOF);

	queue_print(queue, "pre-delete");
	rc = queue_free(queue);
	OSMO_ASSERT(rc == 0);
}

static void test_queue_one()
{
	printf("***** Testing %s()\n", __func__);
	struct queue_t *queue = NULL;
	struct qmsg_t *qmsg = NULL, *qmsg2 = NULL;;
	uint16_t seq = 23;
	uint8_t type = 0;
	void *cbp = NULL;
	struct sockaddr_in peer, peer2;
	int rc;

	rc = inet_pton(AF_INET, "127.0.0.1", &(peer.sin_addr));
	OSMO_ASSERT(rc == 1);
	rc = inet_pton(AF_INET, "127.0.0.2", &(peer2.sin_addr));
	OSMO_ASSERT(rc == 1);

	rc = queue_new(&queue);
	OSMO_ASSERT(rc == 0);
	queue_print(queue, "created");

	rc = queue_newmsg(queue, &qmsg, &peer, seq);
	OSMO_ASSERT(rc == 0);
	queue_print(queue, "first added");
	qmsg->type = GTP_ECHO_REQ;
	qmsg->cbp = (void*) 0x13243546;
	qmsg->seq = seq;

	rc = queue_getfirst(queue, &qmsg2);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(qmsg == qmsg2);

	rc = queue_seqget(queue, &qmsg2, &peer, seq);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(qmsg == qmsg2);
	rc = queue_seqget(queue, &qmsg, &peer2, seq);
	OSMO_ASSERT(rc == EOF);
	rc = queue_seqget(queue, &qmsg, &peer, seq + 1);
	OSMO_ASSERT(rc == EOF);
	queue_print(queue, "after-get");

	rc = queue_back(queue, qmsg);
	OSMO_ASSERT(rc == 0);
	queue_print(queue, "after-back");

	rc = queue_freemsg_seq(queue, &peer2, seq, &type, &cbp);
	OSMO_ASSERT(rc == EOF);
	rc = queue_freemsg_seq(queue, &peer, seq + 1, &type, &cbp);
	OSMO_ASSERT(rc == EOF);
	queue_print(queue, "pree-freemsg");
	rc = queue_freemsg_seq(queue, &peer, seq, &type, &cbp);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(type == GTP_ECHO_REQ);
	OSMO_ASSERT(cbp == (void*)0x13243546);

	queue_print(queue, "pre-delete");
	rc = queue_free(queue);
	OSMO_ASSERT(rc == 0);
}

#define newmsg_fill(queue, qmsg_ptr, peer_ptr, seq) \
	do { \
		int rc = queue_newmsg(queue, &(qmsg_ptr), peer_ptr, seq); \
		OSMO_ASSERT(rc == 0); \
		OSMO_ASSERT(qmsg_ptr); \
		qmsg_ptr->type = GTP_CREATE_PDP_REQ; \
		qmsg_ptr->cbp = (void*)(uintptr_t)seq; \
	} while (0);

#define freemsg_verify(seq, type, cbp) \
	do { \
		OSMO_ASSERT(type == GTP_CREATE_PDP_REQ); \
		OSMO_ASSERT(cbp == (void*)(uintptr_t)seq); \
	} while (0);

static void test_queue_full()
{
	/* queue_newmsg until we receive EOF. Try moving back then. */
	printf("***** Testing %s()\n", __func__);
	struct queue_t *queue = NULL;
	struct qmsg_t *qmsg = NULL;
	uint8_t type = 0;
	void *cbp = NULL;
	struct sockaddr_in peer;
	int rc;
	int i;

	rc = inet_pton(AF_INET, "127.0.0.1", &(peer.sin_addr));
	OSMO_ASSERT(rc == 1);

	rc = queue_new(&queue);
	OSMO_ASSERT(rc == 0);
	queue_print(queue, "created");

	for (i = 0; i < QUEUE_SIZE - 1; i++) {
		newmsg_fill(queue, qmsg, &peer, i);
	}
	queue_print(queue, "after-fill");

	/* There's one slot left at the end, let's use first()->back() */
	rc = queue_getfirst(queue, &qmsg);
	OSMO_ASSERT(rc == 0);
	rc = queue_back(queue, qmsg);
	OSMO_ASSERT(rc == 0);
	queue_print(queue, "after-back");

	/* Now let's fill last empty slot */
	newmsg_fill(queue, qmsg, &peer, QUEUE_SIZE - 1);
	queue_print(queue, "after-full");

	/* queue is now full, it should fail */
	rc = queue_newmsg(queue, &qmsg, &peer, QUEUE_SIZE);
	OSMO_ASSERT(rc == EOF);
	queue_print(queue, "after-failing-full");

	/* Remove 1before-last msg (the one moved back) and make sure we can
	   re-add it at the end of the list */
	rc = queue_seqget(queue, &qmsg, &peer, 0);
	OSMO_ASSERT(rc == 0);
	rc = queue_freemsg(queue, qmsg);
	queue_print(queue, "after-freeing-0");
	OSMO_ASSERT(rc == 0);
	/* Now let's fill last empty slot which should be at the end */
	newmsg_fill(queue, qmsg, &peer, 0);
	queue_print(queue, "after-refilling-0");

	/* Now free first half seq set in increasing order */
	for (i = 0; i < QUEUE_SIZE / 2; i++) {
		rc = queue_freemsg_seq(queue, &peer, i, &type, &cbp);
		OSMO_ASSERT(rc == 0);
		freemsg_verify(i, type, cbp);
	}
	queue_print(queue, "after-first-half-free");

	/* Now free second half seq set in decreasing order */
	for (i = QUEUE_SIZE - 1; i >= QUEUE_SIZE / 2; i--) {
		rc = queue_freemsg_seq(queue, &peer, i, &type, &cbp);
		OSMO_ASSERT(rc == 0);
		freemsg_verify(i, type, cbp);
	}
	queue_print(queue, "after-second-half-free");

	rc = queue_free(queue);
	OSMO_ASSERT(rc == 0);
}

int main(int argc, char **argv)
{
	void *tall_ctx = talloc_named_const(NULL, 1, "Root context");
	msgb_talloc_ctx_init(tall_ctx, 0);
	osmo_init_logging2(tall_ctx, &log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);

	test_queue_empty();
	test_queue_one();
	test_queue_full();

	return 0;
}
