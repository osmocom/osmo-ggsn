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
 * gtp.c: Contains all GTP functionality. Should be able to handle multiple
 * tunnels in the same program. 
 *
 * TODO:
 *  - Do we need to handle fragmentation?
 */


#ifdef __linux__
#define _GNU_SOURCE 1
#endif

#include "../config.h"
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <arpa/inet.h>

/* #include <stdint.h>  ISO C99 types */

#include "pdp.h"
#include "gtp.h"
#include "gtpie.h"
#include "queue.h"


/* Error reporting functions */

void gtp_err(int priority, char *filename, int linenum, char *fmt, ...) {
  va_list args;
  char buf[ERRMSG_SIZE];

  va_start(args, fmt);
  vsnprintf(buf, ERRMSG_SIZE, fmt, args);
  va_end(args);
  buf[ERRMSG_SIZE-1] = 0;
  syslog(priority, "%s: %d: %s", filename, linenum, buf); 
}

void gtp_errpack(int pri, char *fn, int ln, struct sockaddr_in *peer,
		 void *pack, unsigned len, char *fmt, ...) {
  
  va_list args;
  char buf[ERRMSG_SIZE];
  char buf2[ERRMSG_SIZE];
  unsigned int n;
  int pos;
  
  va_start(args, fmt);
  vsnprintf(buf, ERRMSG_SIZE, fmt, args);
  va_end(args);
  buf[ERRMSG_SIZE-1] = 0;

  snprintf(buf2, ERRMSG_SIZE, "Packet from %s:%u, length: %d, content:",
	   inet_ntoa(peer->sin_addr),
	   ntohs(peer->sin_port),
	   len);
  buf2[ERRMSG_SIZE-1] = 0;
  pos = strlen(buf2);
  for(n=0; n<len; n++) {
    if ((pos+4)<ERRMSG_SIZE) {
      sprintf((buf2+pos), " %02hhx", ((unsigned char*)pack)[n]);
      pos += 3;
    }
  }
  buf2[pos] = 0;
  
  syslog(pri, "%s: %d: %s. %s", fn, ln, buf, buf2);

}




/* API Functions */

const char* gtp_version()
{
  return VERSION;
}

/* gtp_new */
/* gtp_free */

int gtp_newpdp(struct gsn_t* gsn, struct pdp_t **pdp, 
	       uint64_t imsi, uint8_t nsapi) {
  return pdp_newpdp(pdp, imsi, nsapi, NULL);
}

int gtp_freepdp(struct gsn_t* gsn, struct pdp_t *pdp) {
  return pdp_freepdp(pdp);
}

/* gtp_gpdu */

extern int gtp_fd(struct gsn_t *gsn) {
  return gsn->fd0;
}

/* gtp_decaps */
/* gtp_retrans */
/* gtp_retranstimeout */


int gtp_set_cb_unsup_ind(struct gsn_t *gsn,
			 int (*cb) (struct sockaddr_in *peer)) {
  gsn->cb_unsup_ind = cb;
  return 0;
}

int gtp_set_cb_extheader_ind(struct gsn_t *gsn,
			     int (*cb) (struct sockaddr_in *peer)) {
  gsn->cb_extheader_ind = cb;
  return 0;
}


/* API: Initialise delete context callback */
/* Called whenever a pdp context is deleted for any reason */
int gtp_set_cb_delete_context(struct gsn_t *gsn,
      int (*cb) (struct pdp_t* pdp)) 
{
  gsn->cb_delete_context = cb;
  return 0;
}

int gtp_set_cb_conf(struct gsn_t *gsn,
		    int (*cb) (int type, int cause, 
			       struct pdp_t* pdp, void *cbp)) {
  gsn->cb_conf = cb;
  return 0;
}

extern int gtp_set_cb_data_ind(struct gsn_t *gsn,
			   int (*cb_data_ind) (struct pdp_t* pdp,
					   void* pack,
					   unsigned len)) 
{
  gsn->cb_data_ind = cb_data_ind;
  return 0;
}

/**
 * get_default_gtp()
 * Generate a GPRS Tunneling Protocol signalling packet header, depending
 * on GTP version and message type. pdp is used for teid/flow label.
 * *packet must be allocated by the calling function, and be large enough
 * to hold the packet header.
 * returns the length of the header. 0 on error.
 **/
static unsigned int get_default_gtp(int version, uint8_t type, void *packet) {
  struct gtp0_header *gtp0_default = (struct gtp0_header*) packet;
  struct gtp1_header_long *gtp1_default = (struct gtp1_header_long*) packet;
  switch (version) {
  case 0:
    /* Initialise "standard" GTP0 header */
    memset(gtp0_default, 0, sizeof(struct gtp0_header));
    gtp0_default->flags=0x1e;
    gtp0_default->type=hton8(type);
    gtp0_default->spare1=0xff;
    gtp0_default->spare2=0xff;
    gtp0_default->spare3=0xff;
    gtp0_default->number=0xff;
    return GTP0_HEADER_SIZE;
  case 1:
    /* Initialise "standard" GTP1 header */
    /* 29.060: 8.2: S=1 and PN=0 */
    /* 29.060 9.3.1: For GTP-U messages Echo Request, Echo Response */
    /* and Supported Extension Headers Notification, the S field shall be */
    /* set to 1 */
    /* Currently extension headers are not supported */
    memset(gtp1_default, 0, sizeof(struct gtp1_header_long));
    gtp1_default->flags=0x32; /* No extension, enable sequence, no N-PDU */
    gtp1_default->type=hton8(type);
    return GTP1_HEADER_SIZE_LONG;
  default:
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Unknown GTP packet version");
    return 0;
  }
}

/**
 * get_seq()
 * Get sequence number of a packet.
 * Returns 0 on error
 **/
static uint16_t get_seq(void *pack) {
  union gtp_packet *packet = (union gtp_packet *) pack;

  if ((packet->flags & 0xe0) == 0x00) { /* Version 0 */
    return ntoh16(packet->gtp0.h.seq);
  }
  else if ((packet->flags & 0xe2) == 0x22) { /* Version 1 with seq */
    return ntoh16(packet->gtp1l.h.seq);
  } else {
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Unknown packet flag");
    return 0;
  }
}

/**
 * get_tid()
 * Get tunnel identifier of a packet.
 * Returns 0 on error
 **/
static uint64_t get_tid(void *pack) {
  union gtp_packet *packet = (union gtp_packet *) pack;
  
  if ((packet->flags & 0xe0) == 0x00) { /* Version 0 */
    return packet->gtp0.h.tid;
  }
  return 0;
}

/**
 * get_hlen()
 * Get the header length of a packet.
 * Returns 0 on error
 **/
static uint16_t get_hlen(void *pack) {
  union gtp_packet *packet = (union gtp_packet *) pack;

  if ((packet->flags & 0xe0) == 0x00) { /* Version 0 */
    return GTP0_HEADER_SIZE;
  }
  else if ((packet->flags & 0xe2) == 0x22) { /* Version 1 with seq */
    return GTP1_HEADER_SIZE_LONG;
  }
  else if ((packet->flags & 0xe7) == 0x20) { /* Short version 1 */
    return GTP1_HEADER_SIZE_SHORT;
  } else {
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Unknown packet flag");
    return 0;
  }
}

/**
 * get_tei()
 * Get the tunnel endpoint identifier (flow label) of a packet.
 * Returns 0xffffffff on error.
 **/
static uint32_t get_tei(void *pack) {
  union gtp_packet *packet = (union gtp_packet *) pack;

  if ((packet->flags & 0xe0) == 0x00) { /* Version 0 */
    return ntoh16(packet->gtp0.h.flow);
  }
  else if ((packet->flags & 0xe0) == 0x20) { /* Version 1 */
    return ntoh32(packet->gtp1l.h.tei);
  }
  else {
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Unknown packet flag");
    return 0xffffffff;
  }
}


int print_packet(void *packet, unsigned len)
{
  unsigned int i;
  printf("The packet looks like this (%d bytes):\n", len);
  for( i=0; i<len; i++) {
    printf("%02x ", (unsigned char)*(char *)(packet+i));
    if (!((i+1)%16)) printf("\n");
  };
  printf("\n"); 
  return 0;
}

char* snprint_packet(struct gsn_t *gsn, struct sockaddr_in *peer,
		     void *pack, unsigned len, char *buf, int size) {
  unsigned int n;
  int pos;
  snprintf(buf, size, "Packet from %s:%u, length: %d, content:",
	   inet_ntoa(peer->sin_addr),
	   ntohs(peer->sin_port),
	   len);
  buf[size-1] = 0;
  pos = strlen(buf);
  for(n=0; n<len; n++) {
    if ((pos+4)<size) {
      sprintf((buf+pos), " %02hhx", ((unsigned char*)pack)[n]);
      pos += 3;
    }
  }
  buf[pos] = 0;
  return buf;
}


/* ***********************************************************
 * Reliable delivery of signalling messages
 * 
 * Sequence numbers are used for both signalling messages and
 * data messages.
 *
 * For data messages each tunnel maintains a sequence counter,
 * which is incremented by one each time a new data message
 * is sent. The sequence number starts at (0) zero at tunnel
 * establishment, and wraps around at 65535 (29.060 9.3.1.1 
 * and 09.60 8.1.1.1). The sequence numbers are either ignored,
 * or can be used to check the validity of the message in the
 * receiver, or for reordering af packets.
 *
 * For signalling messages the sequence number is used by 
 * signalling messages for which a response is defined. A response
 * message should copy the sequence from the corresponding request
 * message. The sequence number "unambiguously" identifies a request
 * message within a given path, with a path being defined as a set of
 * two endpoints (29.060 8.2, 29.060 7.6, 09.60 7.8). "All request
 * messages shall be responded to, and all response messages associated
 * with a certain request shall always include the same information"
 *
 * We take this to mean that the GSN transmitting a request is free to
 * choose the sequence number, as long as it is unique within a given path.
 * It means that we are allowed to count backwards, or roll over at 17
 * if we prefer that. It also means that we can use the same counter for
 * all paths. This has the advantage that the transmitted request sequence
 * numbers are unique within each GSN, and also we dont have to mess around
 * with path setup and teardown.
 *
 * If a response message is lost, the request will be retransmitted, and
 * the receiving GSN will receive a "duplicated" request. The standard 
 * requires the receiving GSN to send a response, with the same information
 * as in the original response. For most messages this happens automatically:
 *
 * Echo: Automatically dublicates the original response
 * Create pdp context: The SGSN may send create context request even if
 *   a context allready exist (imsi+nsapi?). This means that the reply will
     automatically dublicate the original response. It might however have
 *   side effects in the application which is asked twice to validate
 *   the login.
 * Update pdp context: Automatically dublicates the original response???
 * Delete pdp context. Automatically in gtp0, but in gtp1 will generate
 *   a nonexist reply message.
 *
 * The correct solution will be to make a queue containing response messages.
 * This queue should be checked whenever a request is received. If the 
 * response is allready in the queue that response should be transmitted.
 * It should be possible to find messages in this queue on the basis of
 * the sequence number and peer GSN IP address (The sequense number is unique
 * within each path). This need to be implemented by a hash table. Furthermore
 * it should be possibly to delete messages based on a timeout. This can be
 * achieved by means of a linked list. The timeout value need to be larger
 * than T3-RESPONSE * N3-REQUESTS (recommended value 5). These timers are 
 * set in the peer GSN, so there is no way to know these parameters. On the
 * other hand the timeout value need to be so small that we do not receive
 * wraparound sequence numbere before the message is deleted. 60 seconds is
 * probably not a bad choise.
 * 
 * This queue however is first really needed from gtp1.
 *
 * gtp_req: 
 *   Send off a signalling message with appropiate sequence
 *   number. Store packet in queue.
 * gtp_conf:
 *   Remove an incoming confirmation from the queue
 * gtp_resp:
 *   Send off a response to a request. Use the same sequence
 *   number in the response as in the request.
 * gtp_notification:
 *   Send off a notification message. This is neither a request nor
 *   a response. Both TEI and SEQ are zero.
 * gtp_retrans:
 *   Retransmit any outstanding packets which have exceeded
 *   a predefined timeout.
 *************************************************************/

int gtp_req(struct gsn_t *gsn, int version, struct pdp_t *pdp,
	    union gtp_packet *packet, int len, 
	    struct in_addr *inetaddr, void *cbp) {
  struct sockaddr_in addr;
  struct qmsg_t *qmsg;
  int fd;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = *inetaddr;
#if defined(__FreeBSD__) || defined(__APPLE__)
  addr.sin_len = sizeof(addr);
#endif

  if ((packet->flags & 0xe0) == 0x00) { /* Version 0 */
    addr.sin_port = htons(GTP0_PORT);
    packet->gtp0.h.length = hton16(len - GTP0_HEADER_SIZE);
    packet->gtp0.h.seq = hton16(gsn->seq_next);
    if (pdp)
      packet->gtp0.h.tid = (pdp->imsi & 0x0fffffffffffffffull) + 
	((uint64_t)pdp->nsapi << 60);
    if (pdp && ((packet->gtp0.h.type == GTP_GPDU) ||
		(packet->gtp0.h.type == GTP_ERROR)))
      packet->gtp0.h.flow=hton16(pdp->flru);
    else if (pdp)
      packet->gtp0.h.flow=hton16(pdp->flrc);
    fd = gsn->fd0;
  }
  else if ((packet->flags & 0xe2) == 0x22) { /* Version 1 with seq */
    addr.sin_port = htons(GTP1C_PORT);
    packet->gtp1l.h.length = hton16(len - GTP1_HEADER_SIZE_SHORT);
    packet->gtp1l.h.seq = hton16(gsn->seq_next);
    if (pdp && ((packet->gtp1l.h.type == GTP_GPDU) ||
		(packet->gtp1l.h.type == GTP_ERROR)))
      packet->gtp1l.h.tei=hton32(pdp->teid_gn);
    else if (pdp)
      packet->gtp1l.h.tei=hton32(pdp->teic_gn);
    fd = gsn->fd1c;
  } else {
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Unknown packet flag");
    return -1;
  }
  
  if (sendto(fd, packet, len, 0,
	     (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    gsn->err_sendto++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Sendto(fd=%d, msg=%lx, len=%d) failed: Error = %s", fd, (unsigned long) &packet, len, strerror(errno));
    return -1;
  }

  /* Use new queue structure */
  if (queue_newmsg(gsn->queue_req, &qmsg, &addr, gsn->seq_next)) {
    gsn->err_queuefull++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Retransmit queue is full");
  }
  else {
    memcpy(&qmsg->p, packet, sizeof(union gtp_packet));
    qmsg->l = len;
    qmsg->timeout = time(NULL) + 3; /* When to timeout */
    qmsg->retrans = 0;   /* No retransmissions so far */
    qmsg->cbp = cbp;
    qmsg->type = ntoh8(packet->gtp0.h.type);
    qmsg->fd = fd;
  }
  gsn->seq_next++; /* Count up this time */
  return 0;
}

/* gtp_conf
 * Remove signalling packet from retransmission queue.
 * return 0 on success, EOF if packet was not found */

int gtp_conf(struct gsn_t *gsn, int version, struct sockaddr_in *peer,
	     union gtp_packet *packet, int len, uint8_t *type, void **cbp) {

  uint16_t seq;

  if ((packet->gtp0.h.flags & 0xe0) == 0x00)
    seq = ntoh16(packet->gtp0.h.seq);
  else if ((packet->gtp1l.h.flags & 0xe2) == 0x22)
    seq = ntoh16(packet->gtp1l.h.seq);
  else {
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, packet, len,
		"Unknown GTP packet version");
    return EOF;
  }

  if (queue_freemsg_seq(gsn->queue_req, peer, seq, type, cbp)) {
    gsn->err_seq++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, packet, len,
		"Confirmation packet not found in queue");
    return EOF;
  }

  return 0;
}

int gtp_retrans(struct gsn_t *gsn) {
  /* Retransmit any outstanding packets */
  /* Remove from queue if maxretrans exceeded */
  time_t now;
  struct qmsg_t *qmsg;
  now = time(NULL);
  /*printf("Retrans: New beginning %d\n", (int) now);*/

  while ((!queue_getfirst(gsn->queue_req, &qmsg)) &&
	 (qmsg->timeout <= now)) {
    /*printf("Retrans timeout found: %d\n", (int) time(NULL));*/
    if (qmsg->retrans > 3) { /* To many retrans */
      if (gsn->cb_conf) gsn->cb_conf(qmsg->type, EOF, NULL, qmsg->cbp);
      queue_freemsg(gsn->queue_req, qmsg);
    }
    else {
      if (sendto(qmsg->fd, &qmsg->p, qmsg->l, 0,
		 (struct sockaddr *) &qmsg->peer, sizeof(struct sockaddr_in)) < 0) {
	gsn->err_sendto++;
	gtp_err(LOG_ERR, __FILE__, __LINE__, "Sendto(fd0=%d, msg=%lx, len=%d) failed: Error = %s", gsn->fd0, (unsigned long) &qmsg->p, qmsg->l, strerror(errno));
      }
      queue_back(gsn->queue_req, qmsg);
      qmsg->timeout = now + 3;
      qmsg->retrans++;
    }
  } 

  /* Also clean up reply timeouts */
  while ((!queue_getfirst(gsn->queue_resp, &qmsg)) &&
	 (qmsg->timeout < now)) {
    /*printf("Retrans (reply) timeout found: %d\n", (int) time(NULL));*/
    queue_freemsg(gsn->queue_resp, qmsg);
  }

  return 0;
}

int gtp_retranstimeout(struct gsn_t *gsn, struct timeval *timeout) {
  time_t now, later;
  struct qmsg_t *qmsg;

  if (queue_getfirst(gsn->queue_req, &qmsg)) {
    timeout->tv_sec = 10;
    timeout->tv_usec = 0;
  }
  else {
    now = time(NULL);
    later = qmsg->timeout;
    timeout->tv_sec = later - now;
    timeout->tv_usec = 0;
    if (timeout->tv_sec < 0) timeout->tv_sec = 0; /* No negative allowed */
    if (timeout->tv_sec > 10) timeout->tv_sec = 10; /* Max sleep for 10 sec*/
  }
  return 0;
}

int gtp_resp(int version, struct gsn_t *gsn, struct pdp_t *pdp, 
	     union gtp_packet *packet, int len,
	     struct sockaddr_in *peer, int fd, 
	     uint16_t seq, uint64_t tid) {
  struct qmsg_t *qmsg;

  if ((packet->flags & 0xe0) == 0x00) { /* Version 0 */
    packet->gtp0.h.length = hton16(len - GTP0_HEADER_SIZE);
    packet->gtp0.h.seq = hton16(seq);
    packet->gtp0.h.tid = tid;
    if (pdp && ((packet->gtp0.h.type == GTP_GPDU) ||
		(packet->gtp0.h.type == GTP_ERROR)))
      packet->gtp0.h.flow=hton16(pdp->flru);
    else if (pdp)
      packet->gtp0.h.flow=hton16(pdp->flrc);
  }
  else if ((packet->flags & 0xe2) == 0x22) { /* Version 1 with seq */
    packet->gtp1l.h.length = hton16(len - GTP1_HEADER_SIZE_SHORT);
    packet->gtp1l.h.seq = hton16(seq);
    if (pdp && (fd == gsn->fd1u))
      packet->gtp1l.h.tei=hton32(pdp->teid_gn);
    else if (pdp)
      packet->gtp1l.h.tei=hton32(pdp->teic_gn);
  }
  else {
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Unknown packet flag");
    return -1;
  }
  
  if (fcntl(fd, F_SETFL, 0)) {
    gtp_err(LOG_ERR, __FILE__, __LINE__, "fnctl()");
    return -1;
  }

  if (sendto(fd, packet, len, 0,
	     (struct sockaddr *) peer, sizeof(struct sockaddr_in)) < 0) {
    gsn->err_sendto++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Sendto(fd=%d, msg=%lx, len=%d) failed: Error = %s", fd, (unsigned long) &packet, len, strerror(errno));
    return -1;
  }

  /* Use new queue structure */
  if (queue_newmsg(gsn->queue_resp, &qmsg, peer, seq)) {
    gsn->err_queuefull++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Retransmit queue is full");
  }
  else {
    memcpy(&qmsg->p, packet, sizeof(union gtp_packet));
    qmsg->l = len;
    qmsg->timeout = time(NULL) + 60; /* When to timeout */
    qmsg->retrans = 0;   /* No retransmissions so far */
    qmsg->cbp = NULL;
    qmsg->type = 0;
    qmsg->fd = fd;
  }
  return 0;
}

int gtp_notification(struct gsn_t *gsn, int version,
		     union gtp_packet *packet, int len,
		     struct sockaddr_in *peer, int fd, 
		     uint16_t seq) {

  struct sockaddr_in addr;
  
  memcpy(&addr, peer, sizeof(addr));

  /* In GTP0 notifications are treated as replies. In GTP1 they
     are requests for which there is no reply */

  if (fd == gsn->fd1c)
    addr.sin_port = htons(GTP1C_PORT);
  else if (fd == gsn->fd1u)
    addr.sin_port = htons(GTP1C_PORT);

  if ((packet->flags & 0xe0) == 0x00) { /* Version 0 */
    packet->gtp0.h.length = hton16(len - GTP0_HEADER_SIZE);
    packet->gtp0.h.seq = hton16(seq);
  }
  else if ((packet->flags & 0xe2) == 0x22) { /* Version 1 with seq */
    packet->gtp1l.h.length = hton16(len - GTP1_HEADER_SIZE_SHORT);
    packet->gtp1l.h.seq = hton16(seq);
  }
  else {
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Unknown packet flag");
    return -1;
  }
  
  if (fcntl(fd, F_SETFL, 0)) {
    gtp_err(LOG_ERR, __FILE__, __LINE__, "fnctl()");
    return -1;
  }

  if (sendto(fd, packet, len, 0,
	     (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) < 0) {
    gsn->err_sendto++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Sendto(fd=%d, msg=%lx, len=%d) failed: Error = %s", fd, (unsigned long) &packet, len, strerror(errno));
    return -1;
  }
  return 0;
}

int gtp_dublicate(struct gsn_t *gsn, int version,  
		  struct sockaddr_in *peer, uint16_t seq) {
  struct qmsg_t *qmsg;

  if(queue_seqget(gsn->queue_resp, &qmsg, peer, seq)) {
    return EOF; /* Notfound */
  }

  if (fcntl(qmsg->fd, F_SETFL, 0)) {
    gtp_err(LOG_ERR, __FILE__, __LINE__, "fnctl()");
    return -1;
  }
  
  if (sendto(qmsg->fd, &qmsg->p, qmsg->l, 0,
	     (struct sockaddr *) peer, sizeof(struct sockaddr_in)) < 0) {
    gsn->err_sendto++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Sendto(fd=%d, msg=%lx, len=%d) failed: Error = %s", qmsg->fd, (unsigned long) &qmsg->p, qmsg->l, strerror(errno));
  }
  return 0;
}



/* Perform restoration and recovery error handling as described in 29.060 */
static void log_restart(struct gsn_t *gsn) {
	FILE *f;
	int i;
	int counter = 0;
	char filename[NAMESIZE];

	filename[NAMESIZE-1] = 0; /* No null term. guarantee by strncpy */ 
	strncpy(filename, gsn->statedir, NAMESIZE-1);
	strncat(filename, RESTART_FILE, 
		NAMESIZE-1-sizeof(RESTART_FILE));

	i = umask(022);

	/* We try to open file. On failure we will later try to create file */
	if (!(f = fopen(filename, "r"))) {

	  gtp_err(LOG_ERR, __FILE__, __LINE__, "State information file (%s) not found. Creating new file.", filename);
	}
	else {
	  umask(i);
	  fscanf(f, "%d", &counter);
	  if (fclose(f)) {
	    gtp_err(LOG_ERR, __FILE__, __LINE__, "fclose failed: Error = %s", strerror(errno));
	  }
	}
	
	gsn->restart_counter = (unsigned char) counter;
	gsn->restart_counter++;
	
	if (!(f = fopen(filename, "w"))) {
	  gtp_err(LOG_ERR, __FILE__, __LINE__, "fopen(path=%s, mode=%s) failed: Error = %s", filename, "w", strerror(errno));
	  return;
	}

	umask(i);
	fprintf(f, "%d\n", gsn->restart_counter);
	if (fclose(f)) {
	  gtp_err(LOG_ERR, __FILE__, __LINE__, "fclose failed: Error = %s", strerror(errno));
	  return;
	}
}



int gtp_new(struct gsn_t **gsn, char *statedir, struct in_addr *listen,
	    int mode) 
{
  struct sockaddr_in addr;
  
  syslog(LOG_ERR, "GTP: gtp_newgsn() started");

  *gsn = calloc(sizeof(struct gsn_t), 1); /* TODO */

  (*gsn)->statedir = statedir;
  log_restart(*gsn);

  /* Initialise sequence number */
  (*gsn)->seq_next = (*gsn)->restart_counter * 1024;
  
  /* Initialise request retransmit queue */
  queue_new(&(*gsn)->queue_req);
  queue_new(&(*gsn)->queue_resp);
  
  /* Initialise pdp table */
  pdp_init();

  /* Initialise call back functions */
  (*gsn)->cb_create_context_ind = 0;
  (*gsn)->cb_delete_context = 0;
  (*gsn)->cb_unsup_ind = 0;
  (*gsn)->cb_conf = 0;
  (*gsn)->cb_data_ind = 0;

  /* Store function parameters */
  (*gsn)->gsnc = *listen;
  (*gsn)->gsnu = *listen;
  (*gsn)->mode = mode;


  /* Create GTP version 0 socket */
  if (((*gsn)->fd0 = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
    (*gsn)->err_socket++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "socket(domain=%d, type=%d, protocol=%d) failed: Error = %s", AF_INET, SOCK_DGRAM, 0, strerror(errno));
    return -1;
  }
    
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = *listen;  /* Same IP for user traffic and signalling*/
  addr.sin_port = htons(GTP0_PORT);
#if defined(__FreeBSD__) || defined(__APPLE__)
  addr.sin_len = sizeof(addr);
#endif
  
  if (bind((*gsn)->fd0, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    (*gsn)->err_socket++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "bind(fd0=%d, addr=%lx, len=%d) failed: Error = %s", (*gsn)->fd0, (unsigned long) &addr, sizeof(addr), strerror(errno));
    return -1;
  }

  /* Create GTP version 1 control plane socket */
  if (((*gsn)->fd1c = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
    (*gsn)->err_socket++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "socket(domain=%d, type=%d, protocol=%d) failed: Error = %s", AF_INET, SOCK_DGRAM, 0, strerror(errno));
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = *listen;  /* Same IP for user traffic and signalling*/
  addr.sin_port = htons(GTP1C_PORT);
#if defined(__FreeBSD__) || defined(__APPLE__)
  addr.sin_len = sizeof(addr);
#endif
  
  if (bind((*gsn)->fd1c, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    (*gsn)->err_socket++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "bind(fd1c=%d, addr=%lx, len=%d) failed: Error = %s", (*gsn)->fd1c, (unsigned long) &addr, sizeof(addr), strerror(errno));
    return -1;
  }

  /* Create GTP version 1 user plane socket */
  if (((*gsn)->fd1u = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
    (*gsn)->err_socket++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "socket(domain=%d, type=%d, protocol=%d) failed: Error = %s", AF_INET, SOCK_DGRAM, 0, strerror(errno));
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = *listen;  /* Same IP for user traffic and signalling*/
  addr.sin_port = htons(GTP1U_PORT);
#if defined(__FreeBSD__) || defined(__APPLE__)
  addr.sin_len = sizeof(addr);
#endif
  
  if (bind((*gsn)->fd1u, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    (*gsn)->err_socket++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "bind(fd1c=%d, addr=%lx, len=%d) failed: Error = %s", (*gsn)->fd1c, (unsigned long) &addr, sizeof(addr), strerror(errno));
    return -1;
  }

  return 0;
}

int gtp_free(struct gsn_t *gsn) {

  /* Clean up retransmit queues */
  queue_free(gsn->queue_req);
  queue_free(gsn->queue_resp);
  
  close(gsn->fd0);
  close(gsn->fd1c);
  close(gsn->fd1u);

  free(gsn);
  return 0;
}

/* ***********************************************************
 * Path management messages
 * Messages: echo and version not supported.
 * A path is connection between two UDP/IP endpoints
 *
 * A path is either using GTP0 or GTP1. A path can be
 * established by any kind of GTP message??

 * Which source port to use?
 * GTP-C request destination port is 2123/3386
 * GTP-U request destination port is 2152/3386
 * T-PDU destination port is 2152/3386.
 * For the above messages the source port is locally allocated.
 * For response messages src=rx-dst and dst=rx-src.
 * For simplicity we should probably use 2123+2152/3386 as
 * src port even for the cases where src can be locally
 * allocated. This also means that we have to listen only to
 * the same ports.
 * For response messages we need to be able to respond to
 * the relevant src port even if it is locally allocated by
 * the peer.
 * 
 * The need for path management!
 * We might need to keep a list of active paths. This might
 * be in the form of remote IP address + UDP port numbers.
 * (We will consider a path astablished if we have a context
 * with the node in question)
 *************************************************************/

/* Send off an echo request */
int gtp_echo_req(struct gsn_t *gsn, int version, void *cbp,
		 struct in_addr *inetaddr)
{
  union gtp_packet packet;
  unsigned int length = get_default_gtp(version, GTP_ECHO_REQ, &packet);
  return gtp_req(gsn, version, NULL, &packet, length, inetaddr, cbp);
}

/* Send off an echo reply */
int gtp_echo_resp(struct gsn_t *gsn, int version,
		  struct sockaddr_in *peer, int fd,
		  void *pack, unsigned len)
{
  union gtp_packet packet;
  unsigned int length = get_default_gtp(version, GTP_ECHO_RSP, &packet);
  gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_RECOVERY, gsn->restart_counter);
  return gtp_resp(version, gsn, NULL, &packet, length, peer, fd, 
		  get_seq(pack), get_tid(pack));
}


/* Handle a received echo request */
int gtp_echo_ind(struct gsn_t *gsn, int version, struct sockaddr_in *peer, 
		 int fd, void *pack, unsigned len) {

  /* Check if it was a dublicate request */
  if(!gtp_dublicate(gsn, 0, peer, get_seq(pack))) return 0;

  /* Send off reply to request */
  return gtp_echo_resp(gsn, version, peer, fd, pack, len);
}

/* Handle a received echo reply */
int gtp_echo_conf(struct gsn_t *gsn, int version, struct sockaddr_in *peer,
		  void *pack, unsigned len) {
  union gtpie_member *ie[GTPIE_SIZE];
  unsigned char recovery;
  void *cbp = NULL;
  uint8_t type = 0;
  int hlen = get_hlen(pack);

  /* Remove packet from queue */
  if (gtp_conf(gsn, version, peer, pack, len, &type, &cbp)) return EOF;

  /* Extract information elements into a pointer array */
  if (gtpie_decaps(ie, version, pack+hlen, len-hlen)) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, NULL, cbp);
    return EOF;
  }
  
  if (gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory field");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, NULL, cbp);
    return EOF;
  }

  /* Echo reply packages does not have a cause information element */
  /* Instead we return the recovery number in the callback function */
  if (gsn->cb_conf) gsn->cb_conf(type, recovery, NULL, cbp);

  return 0;
}

/* Send off a Version Not Supported message */
/* This message is somewhat special in that it actually is a
 * response to some other message with unsupported GTP version
 * For this reason it has parameters like a response, and does
 * its own message transmission. No signalling queue is used 
 * The reply is sent to the peer IP and peer UDP. This means that
 * the peer will be receiving a GTP0 message on a GTP1 port! 
 * In practice however this will never happen as a GTP0 GSN will
 * only listen to the GTP0 port, and therefore will never receive
 * anything else than GTP0 */

int gtp_unsup_req(struct gsn_t *gsn, int version, struct sockaddr_in *peer,
		  int fd, void *pack, unsigned len)
{
  union gtp_packet packet;

  /* GTP 1 is the highest supported protocol */
  unsigned int length = get_default_gtp(1, GTP_NOT_SUPPORTED, &packet);
  return gtp_notification(gsn, version, &packet, length, 
			  peer, fd, 0);
}

/* Handle a Version Not Supported message */
int gtp_unsup_ind(struct gsn_t *gsn, struct sockaddr_in *peer, 
		  void *pack, unsigned len) {

  if (gsn->cb_unsup_ind) gsn->cb_unsup_ind(peer);
  
  return 0;
}

/* Send off an Supported Extension Headers Notification */
int gtp_extheader_req(struct gsn_t *gsn, int version, struct sockaddr_in *peer,
		      int fd, void *pack, unsigned len)
{
  union gtp_packet packet;
  unsigned int length = get_default_gtp(version, GTP_SUPP_EXT_HEADER, &packet);

  uint8_t pdcp_pdu = GTP_EXT_PDCP_PDU;

  if (version < 1)
    return 0;

  /* We report back that we support only PDCP PDU headers */
  gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_EXT_HEADER_T, sizeof(pdcp_pdu), 
	    &pdcp_pdu);

  return gtp_notification(gsn, version, &packet, length, 
			  peer, fd, get_seq(pack));
}

/* Handle a Supported Extension Headers Notification */
int gtp_extheader_ind(struct gsn_t *gsn, struct sockaddr_in *peer, 
		      void *pack, unsigned len) {

  if (gsn->cb_extheader_ind) gsn->cb_extheader_ind(peer);
  
  return 0;
}


/* ***********************************************************
 * Session management messages
 * Messages: create, update and delete PDP context
 *
 * Information storage
 * Information storage for each PDP context is defined in 
 * 23.060 section 13.3. Includes IMSI, MSISDN, APN, PDP-type,
 * PDP-address (IP address), sequence numbers, charging ID.
 * For the SGSN it also includes radio related mobility
 * information.
 *************************************************************/

/* API: Send Create PDP Context Request (7.3.1) */
extern int gtp_create_context_req(struct gsn_t *gsn, struct pdp_t *pdp, 
				  void *cbp) {
  union gtp_packet packet;
  unsigned int length = get_default_gtp(pdp->version, GTP_CREATE_PDP_REQ, &packet);
  struct pdp_t *linked_pdp = NULL;

  /* TODO: Secondary PDP Context Activation Procedure */
  /* In secondary activation procedure the PDP context is identified
     by tei in the header. The following fields are omitted: Selection
     mode, IMSI, MSISDN, End User Address, Access Point Name and
     Protocol Configuration Options */

  if (pdp->secondary) {
    if (pdp_getgtp1(&linked_pdp, pdp->teic_own)) {
      gtp_err(LOG_ERR, __FILE__, __LINE__, "Unknown linked PDP context");
      return EOF;
    }
  }

  if (pdp->version == 0) {
    gtpie_tv0(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE0, 
	      sizeof(pdp->qos_req0), pdp->qos_req0);
  }

  /* Section 7.7.2 */
  if (pdp->version == 1) {
    if (!pdp->secondary) /* Not Secondary PDP Context Activation Procedure */
      gtpie_tv0(&packet, &length, GTP_MAX, GTPIE_IMSI, 
		sizeof(pdp->imsi), (uint8_t*) &pdp->imsi);
  }

  /* Section 7.7.11 */
  gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_RECOVERY, 
	    gsn->restart_counter);

  /* Section 7.7.12 */
  if (!pdp->secondary) /* Not Secondary PDP Context Activation Procedure */
    gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_SELECTION_MODE,
	      pdp->selmode);

  if (pdp->version == 0) {
    gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_DI, 
	      pdp->fllu);
    gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_C,
	      pdp->fllc);
  }

  /* Section 7.7.13 */
  if (pdp->version == 1) {
    gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_DI,
	      pdp->teid_own);

    /* Section 7.7.14 */
    if (!pdp->teic_confirmed) 
      gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_C,
		pdp->teic_own);

    /* Section 7.7.17 */
    gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_NSAPI, 
	      pdp->nsapi);

    /* Section 7.7.17 */
    if (pdp->secondary) /* Secondary PDP Context Activation Procedure */
      gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_NSAPI, 
		linked_pdp->nsapi);

    /* Section 7.7.23 */
    if (pdp->cch_pdp) /* Only include charging if flags are set */
      gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_CHARGING_C, 
		pdp->cch_pdp);
  }

  /* TODO 
  gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_TRACE_REF,
	    pdp->traceref);
  gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_TRACE_TYPE,
	    pdp->tracetype); */

  /* Section 7.7.27 */
  if (!pdp->secondary) /* Not Secondary PDP Context Activation Procedure */
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_EUA, 
	      pdp->eua.l, pdp->eua.v);
  

  /* Section 7.7.30 */
  if (!pdp->secondary) /* Not Secondary PDP Context Activation Procedure */
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_APN, 
	      pdp->apn_use.l, pdp->apn_use.v);

  /* Section 7.7.31 */
  if (!pdp->secondary) /* Not Secondary PDP Context Activation Procedure */
    if (pdp->pco_req.l)
      gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_PCO, 
		pdp->pco_req.l, pdp->pco_req.v);
  
  /* Section 7.7.32 */
  gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	    pdp->gsnlc.l, pdp->gsnlc.v);
  /* Section 7.7.32 */
  gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	    pdp->gsnlu.l, pdp->gsnlu.v);

  /* Section 7.7.33 */
  if (!pdp->secondary) /* Not Secondary PDP Context Activation Procedure */
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_MSISDN,
	      pdp->msisdn.l, pdp->msisdn.v);

  /* Section 7.7.34 */
  if (pdp->version == 1) 
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE,
	      pdp->qos_req.l, pdp->qos_req.v);

  /* Section 7.7.36 */
  if ((pdp->version == 1) && pdp->tft.l)
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_TFT,
	      pdp->tft.l, pdp->tft.v);
  
  /* Section 7.7.41 */
  if ((pdp->version == 1) && pdp->triggerid.l)
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_TRIGGER_ID,
	      pdp->triggerid.l, pdp->triggerid.v);
  
  /* Section 7.7.42 */
  if ((pdp->version == 1) && pdp->omcid.l)
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_OMC_ID,
	      pdp->omcid.l, pdp->omcid.v);
  
  /* TODO hisaddr0 */
  gtp_req(gsn, pdp->version, pdp, &packet, length, &pdp->hisaddr0, cbp);

  return 0;
}

/* API: Application response to context indication */
int gtp_create_context_resp(struct gsn_t *gsn, struct pdp_t *pdp, int cause) {

  /* Now send off a reply to the peer */
  gtp_create_pdp_resp(gsn, pdp->version, pdp, cause);
 
  if (cause != GTPCAUSE_ACC_REQ) {
    pdp_freepdp(pdp);
  }
  
  return 0;
}

/* API: Register create context indication callback */
int gtp_set_cb_create_context_ind(struct gsn_t *gsn,
      int (*cb_create_context_ind) (struct pdp_t* pdp)) 
{
  gsn->cb_create_context_ind = cb_create_context_ind;
  return 0;
}


/* Send Create PDP Context Response */
int gtp_create_pdp_resp(struct gsn_t *gsn, int version, struct pdp_t *pdp, 
			uint8_t cause) {
  union gtp_packet packet;
  unsigned int length = get_default_gtp(version, GTP_CREATE_PDP_RSP, &packet);

  gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_CAUSE, cause);

  if (cause == GTPCAUSE_ACC_REQ) {

    if (version == 0) 
      gtpie_tv0(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE0, 
		sizeof(pdp->qos_neg0), pdp->qos_neg0);

    gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_REORDER,
	      pdp->reorder);
    gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_RECOVERY, 
	      gsn->restart_counter);

    if (version == 0) {
      gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_DI, 
		pdp->fllu);
      gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_C,
		pdp->fllc);
    }

    if (version == 1) {
      gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_DI, 
		pdp->teid_own);
      gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_C,
		pdp->teic_own);
    }

    /* TODO: We use teic_own as charging ID */
    gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_CHARGING_ID,
	      pdp->teic_own);

    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_EUA, 
	      pdp->eua.l, pdp->eua.v);

    if (pdp->pco_neg.l) { /* Optional PCO */
      gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_PCO,
		pdp->pco_neg.l, pdp->pco_neg.v);
    }

    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	      pdp->gsnlc.l, pdp->gsnlc.v);
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	      pdp->gsnlu.l, pdp->gsnlu.v);

    if (version == 1)
      gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE,
		pdp->qos_neg.l, pdp->qos_neg.v);

    /* TODO: Charging gateway address */
  }

  return gtp_resp(version, gsn, pdp, &packet, length, &pdp->sa_peer, 
		  pdp->fd, pdp->seq, pdp->tid);
}

/* Handle Create PDP Context Request */
int gtp_create_pdp_ind(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, int fd, 
			void *pack, unsigned len) {
  struct pdp_t *pdp, *pdp_old; 
  struct pdp_t pdp_buf;
  union gtpie_member* ie[GTPIE_SIZE];
  uint8_t recovery;

  uint16_t seq = get_seq(pack);
  int hlen = get_hlen(pack);
  uint8_t linked_nsapi = 0;
  struct pdp_t *linked_pdp = NULL;

  if(!gtp_dublicate(gsn, version, peer, seq)) return 0;

  pdp = &pdp_buf;
  memset(pdp, 0, sizeof(struct pdp_t));

  if (version == 0) {
    pdp->imsi = ((union gtp_packet*)pack)->gtp0.h.tid & 0x0fffffffffffffffull;
    pdp->nsapi = (((union gtp_packet*)pack)->gtp0.h.tid & 0xf000000000000000ull) >> 60;
  }

  pdp->seq = seq;
  pdp->sa_peer = *peer;
  pdp->fd = fd;
  pdp->version = version;

  /* Decode information elements */
  if (gtpie_decaps(ie, version, pack+hlen, len-hlen)) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    if (0 == version)
      return EOF;
    else
      return gtp_create_pdp_resp(gsn, version, pdp, GTPCAUSE_INVALID_MESSAGE);
  }

  if (version == 1) {
    /* Linked NSAPI (conditional) */
    /* If included this is the Secondary PDP Context Activation Procedure */
    /* In secondary activation IMSI is not included, so the context must be */
    /* identified by the tei */
    if (!gtpie_gettv1(ie, GTPIE_NSAPI, 1, &linked_nsapi)) {
      
      /* Find the primary PDP context */
      if (pdp_getgtp1(&linked_pdp, get_tei(pack))) {
	gsn->incorrect++;
	gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		    "Incorrect optional information field");
	return gtp_create_pdp_resp(gsn, version, pdp, 
				   GTPCAUSE_OPT_IE_INCORRECT);
      }

      /* Check that the primary PDP context matches linked nsapi */
      if (linked_pdp->nsapi != linked_nsapi) {
	gsn->incorrect++;
	gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		    "Incorrect optional information field");
	return gtp_create_pdp_resp(gsn, version, pdp, 
				   GTPCAUSE_OPT_IE_INCORRECT);
      }
      
      /* Copy parameters from primary context */
      pdp->selmode = linked_pdp->selmode;
      pdp->imsi = linked_pdp->imsi;
      pdp->msisdn = linked_pdp->msisdn;
      pdp->eua = linked_pdp->eua;
      pdp->pco_req = linked_pdp->pco_req;
      pdp->apn_req = linked_pdp->apn_req;
      pdp->teic_gn = linked_pdp->teic_gn;
      pdp->secondary = 1;
    }
  } /* if (version == 1) */

  if (version == 0) {
    if (gtpie_gettv0(ie, GTPIE_QOS_PROFILE0, 0,
		     pdp->qos_req0, sizeof(pdp->qos_req0))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      return gtp_create_pdp_resp(gsn, version, pdp, GTPCAUSE_MAN_IE_MISSING);
    }
  }
  
  if ((version == 1) && (!linked_pdp)) {
    /* Not Secondary PDP Context Activation Procedure */
    /* IMSI (conditional) */
    if (gtpie_gettv0(ie, GTPIE_IMSI, 0, &pdp->imsi, sizeof(pdp->imsi))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      return gtp_create_pdp_resp(gsn, version, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }
  }
  
  /* Recovery (optional) */
  if (!gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
    /* TODO: Handle received recovery IE */
  }
  
  /* Selection mode (conditional) */
  if (!linked_pdp) { /* Not Secondary PDP Context Activation Procedure */
    if (gtpie_gettv0(ie, GTPIE_SELECTION_MODE, 0,
		     &pdp->selmode, sizeof(pdp->selmode))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      return gtp_create_pdp_resp(gsn, version, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }
  }

  if (version == 0) {
    if (gtpie_gettv2(ie, GTPIE_FL_DI, 0, &pdp->flru)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      return gtp_create_pdp_resp(gsn, version, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }
    
    if (gtpie_gettv2(ie, GTPIE_FL_C, 0, &pdp->flrc)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      return gtp_create_pdp_resp(gsn, version, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }
  }
  
  
  if (version == 1) {
    /* TEID (mandatory) */
    if (gtpie_gettv4(ie, GTPIE_TEI_DI, 0, &pdp->teid_gn)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      return gtp_create_pdp_resp(gsn, version, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }

    /* TEIC (conditional) */
    if (!linked_pdp) { /* Not Secondary PDP Context Activation Procedure */
      if (gtpie_gettv4(ie, GTPIE_TEI_C, 0, &pdp->teic_gn)) {
	gsn->missing++;
	gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		    "Missing mandatory information field");
	return gtp_create_pdp_resp(gsn, version, pdp, 
				   GTPCAUSE_MAN_IE_MISSING);
      }
    }

    /* NSAPI (mandatory) */
    if (gtpie_gettv1(ie, GTPIE_NSAPI, 0, &pdp->nsapi)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      return gtp_create_pdp_resp(gsn, version, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }
  }
  
  
  /* Charging Characteriatics (optional) */
  /* Trace reference (optional) */
  /* Trace type (optional) */
  /* Charging Characteriatics (optional) */
  
  if (!linked_pdp) { /* Not Secondary PDP Context Activation Procedure */
    /* End User Address (conditional) */
    if (gtpie_gettlv(ie, GTPIE_EUA, 0, &pdp->eua.l,
		     &pdp->eua.v, sizeof(pdp->eua.v))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      return gtp_create_pdp_resp(gsn, version, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }
    
    /* APN */
    if (gtpie_gettlv(ie, GTPIE_APN, 0, &pdp->apn_req.l,
		     &pdp->apn_req.v, sizeof(pdp->apn_req.v))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      return gtp_create_pdp_resp(gsn, version, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }
    
    /* Extract protocol configuration options (optional) */
    if (!gtpie_gettlv(ie, GTPIE_PCO, 0, &pdp->pco_req.l,
		      &pdp->pco_req.v, sizeof(pdp->pco_req.v))) {
    }
  }

  /* SGSN address for signalling (mandatory) */
  if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 0, &pdp->gsnrc.l,
		     &pdp->gsnrc.v, sizeof(pdp->gsnrc.v))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_create_pdp_resp(gsn, version, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  /* SGSN address for user traffic (mandatory) */
  if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 1, &pdp->gsnru.l,
		     &pdp->gsnru.v, sizeof(pdp->gsnru.v))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_create_pdp_resp(gsn, version, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  }
  
  if (!linked_pdp) { /* Not Secondary PDP Context Activation Procedure */
    /* MSISDN (conditional) */
    if (gtpie_gettlv(ie, GTPIE_MSISDN, 0, &pdp->msisdn.l,
		     &pdp->msisdn.v, sizeof(pdp->msisdn.v))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      return gtp_create_pdp_resp(gsn, version, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }
  }

  if (version == 1) {
    /* QoS (mandatory) */
    if (gtpie_gettlv(ie, GTPIE_QOS_PROFILE, 0, &pdp->qos_req.l,
		     &pdp->qos_req.v, sizeof(pdp->qos_req.v))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      return gtp_create_pdp_resp(gsn, version, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }

    /* TFT (conditional) */
    if (gtpie_gettlv(ie, GTPIE_TFT, 0, &pdp->tft.l,
		     &pdp->tft.v, sizeof(pdp->tft.v))) {
    }

    /* Trigger ID */
    /* OMC identity */
  }

  /* Initialize our own IP addresses */
  in_addr2gsna(&pdp->gsnlc, &gsn->gsnc);
  in_addr2gsna(&pdp->gsnlu, &gsn->gsnu);
  
  if (GTP_DEBUG) printf("gtp_create_pdp_ind: Before pdp_tidget\n");
  
  if (!pdp_getimsi(&pdp_old, pdp->imsi, pdp->nsapi)) {
    /* Found old pdp with same tid. Now the voodoo begins! */
    /* 09.60 / 29.060 allows create on existing context to "steal" */
    /* the context which was allready established */
    /* We check that the APN, selection mode and MSISDN is the same */
    if (GTP_DEBUG) printf("gtp_create_pdp_ind: Old context found\n"); 
    if ((pdp->apn_req.l == pdp_old->apn_req.l) 
	&& (!memcmp(pdp->apn_req.v, pdp_old->apn_req.v, pdp->apn_req.l)) 
	&& (pdp->selmode == pdp_old->selmode)
	&& (pdp->msisdn.l == pdp_old->msisdn.l) 
	&& (!memcmp(pdp->msisdn.v, pdp_old->msisdn.v, pdp->msisdn.l))) {
      /* OK! We are dealing with the same APN. We will copy new
       * parameters to the old pdp and send off confirmation 
       * We ignore the following information elements:
       * QoS: MS will get originally negotiated QoS.
       * End user address (EUA). MS will get old EUA anyway.
       * Protocol configuration option (PCO): Only application can verify */

      if (GTP_DEBUG) printf("gtp_create_pdp_ind: Old context found\n");
      
      /* Copy remote flow label */
      pdp_old->flru = pdp->flru;
      pdp_old->flrc = pdp->flrc;

      /* Copy remote tei */
      pdp_old->teid_gn = pdp->teid_gn;
      pdp_old->teic_gn = pdp->teic_gn;

      /* Copy peer GSN address */
      pdp_old->gsnrc.l = pdp->gsnrc.l;
      memcpy(&pdp_old->gsnrc.v, &pdp->gsnrc.v, pdp->gsnrc.l);
      pdp_old->gsnru.l = pdp->gsnru.l;
      memcpy(&pdp_old->gsnru.v, &pdp->gsnru.v, pdp->gsnru.l);

      /* Copy request parameters */
      pdp_old->seq     = pdp->seq;
      pdp_old->sa_peer = pdp->sa_peer;
      pdp_old->fd      = pdp->fd = fd;
      pdp_old->version =  pdp->version = version;

      /* Switch to using the old pdp context */
      pdp = pdp_old;
      
      /* Confirm to peer that things were "successful" */
      return gtp_create_pdp_resp(gsn, version, pdp, GTPCAUSE_ACC_REQ);
    }
    else { /* This is not the same PDP context. Delete the old one. */

      if (GTP_DEBUG) printf("gtp_create_pdp_ind: Deleting old context\n");
      
      if (gsn->cb_delete_context) gsn->cb_delete_context(pdp_old);
      pdp_freepdp(pdp_old);
      
      if (GTP_DEBUG) printf("gtp_create_pdp_ind: Deleted...\n");      
    }
  }

  pdp_newpdp(&pdp, pdp->imsi, pdp->nsapi, pdp);

  /* Callback function to validata login */
  if (gsn->cb_create_context_ind !=0) 
    return gsn->cb_create_context_ind(pdp);
  else {
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"No create_context_ind callback defined");
    return gtp_create_pdp_resp(gsn, version, pdp, GTPCAUSE_NOT_SUPPORTED);
  }
}


/* Handle Create PDP Context Response */
int gtp_create_pdp_conf(struct gsn_t *gsn, int version,
			 struct sockaddr_in *peer, 
			 void *pack, unsigned len) {
  struct pdp_t *pdp; 
  union gtpie_member *ie[GTPIE_SIZE];
  uint8_t cause, recovery;
  void *cbp = NULL;
  uint8_t type = 0;
  int hlen = get_hlen(pack);

  /* Remove packet from queue */
  if (gtp_conf(gsn, version, peer, pack, len, &type, &cbp)) return EOF;
  
  /* Find the context in question */
  if (pdp_getgtp1(&pdp, get_tei(pack))) {
    gsn->err_unknownpdp++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unknown PDP context");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, NULL, cbp);
    return EOF;
  }

  /* Register that we have received a valid teic from GGSN */
  pdp->teic_confirmed = 1;

  /* Decode information elements */
  if (gtpie_decaps(ie, version, pack+hlen, len-hlen)) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
    /*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	  pdp_freepdp(pdp); */
    return EOF;
  }

  /* Extract cause value (mandatory) */
  if (gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause)) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
    /*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	  pdp_freepdp(pdp); */
    return EOF;
  }

  /* Extract recovery (optional) */
  if (!gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
    /* TODO: Handle received recovery IE */
  }

  /* Extract protocol configuration options (optional) */
  if (!gtpie_gettlv(ie, GTPIE_PCO, 0, &pdp->pco_req.l,
		    &pdp->pco_req.v, sizeof(pdp->pco_req.v))) {
  }

  /* Check all conditional information elements */
  if (GTPCAUSE_ACC_REQ == cause) {

    if (version == 0) {
      if (gtpie_gettv0(ie, GTPIE_QOS_PROFILE0, 0,
		       &pdp->qos_neg0, sizeof(pdp->qos_neg0))) {
	gsn->missing++;
	gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		    "Missing conditional information field");
	if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
	/*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	      pdp_freepdp(pdp); */
	return EOF;
      }
    }
    
    if (gtpie_gettv1(ie, GTPIE_REORDER, 0, &pdp->reorder)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
	/*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	      pdp_freepdp(pdp); */
      return EOF;
    }

    if (version == 0) {
      if (gtpie_gettv2(ie, GTPIE_FL_DI, 0, &pdp->flru)) {
	gsn->missing++;
	gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		    "Missing conditional information field");
	if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
	/*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	      pdp_freepdp(pdp); */
	return EOF;
      }
    
      if (gtpie_gettv2(ie, GTPIE_FL_C, 0, &pdp->flrc)) {
	gsn->missing++;
	gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		    "Missing conditional information field");
	if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
	/*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	      pdp_freepdp(pdp); */
	return EOF;
      }
    }

    if (version == 1) {
      if (gtpie_gettv4(ie, GTPIE_TEI_DI, 0, &pdp->teid_gn)) {
	gsn->missing++;
	gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		    "Missing conditional information field");
	if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
	/*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	      pdp_freepdp(pdp); */
	return EOF;
      }
    
      if (gtpie_gettv4(ie, GTPIE_TEI_C, 0, &pdp->teic_gn)) {
	gsn->missing++;
	gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		    "Missing conditional information field");
	if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
	/*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	      pdp_freepdp(pdp); */
	return EOF;
      }
    }
    
    if (gtpie_gettv4(ie, GTPIE_CHARGING_ID, 0, &pdp->cid)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
	/*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	      pdp_freepdp(pdp); */
    }
    
    if (gtpie_gettlv(ie, GTPIE_EUA, 0, &pdp->eua.l,
		     &pdp->eua.v, sizeof(pdp->eua.v))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
      /*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	    pdp_freepdp(pdp); */
      return EOF;
    }
    
    if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 0, &pdp->gsnrc.l,
		     &pdp->gsnrc.v, sizeof(pdp->gsnrc.v))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
      /*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	    pdp_freepdp(pdp); */
      return EOF;
    }
    
    if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 1, &pdp->gsnru.l,
		     &pdp->gsnru.v, sizeof(pdp->gsnru.v))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
      /*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	    pdp_freepdp(pdp); */
      return EOF;
    }

    if (version == 1) {
      if (gtpie_gettlv(ie, GTPIE_QOS_PROFILE, 0, &pdp->qos_neg.l,
		       &pdp->qos_neg.v, sizeof(pdp->qos_neg.v))) {
	gsn->missing++;
	gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		    "Missing conditional information field");
	if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
	/*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	      pdp_freepdp(pdp); */
	return EOF;
      }
    }
   
  }
  
  if (gsn->cb_conf) gsn->cb_conf(type, cause, pdp, cbp);

  return 0;
}


/* API: Send Update PDP Context Request */
int gtp_update_context(struct gsn_t *gsn, struct pdp_t *pdp, void *cbp,
		       struct in_addr* inetaddr) {
  union gtp_packet packet;
  unsigned int length = get_default_gtp(pdp->version, GTP_UPDATE_PDP_REQ, &packet);
  
  if (pdp->version == 0)
    gtpie_tv0(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE0, 
	      sizeof(pdp->qos_req0), pdp->qos_req0);
  
  /* Include IMSI if updating with unknown teic_gn */
  if ((pdp->version == 1) && (!pdp->teic_gn))
    gtpie_tv0(&packet, &length, GTP_MAX, GTPIE_IMSI, 
	      sizeof(pdp->imsi), (uint8_t*) &pdp->imsi);
  
  gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_RECOVERY, 
	    gsn->restart_counter);
  
  if (pdp->version == 0) {
    gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_DI, 
	      pdp->fllu);
    gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_C,
	      pdp->fllc);
  }
  
  if (pdp->version == 1) {
    gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_DI,
	      pdp->teid_own);

    if (!pdp->teic_confirmed)
      gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_C,
		pdp->teic_own);
  }
  
  gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_NSAPI, 
	    pdp->nsapi);
  
  /* TODO 
     gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_TRACE_REF,
     pdp->traceref);
     gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_TRACE_TYPE,
     pdp->tracetype); */
  
  /* TODO if ggsn update message
     gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_EUA, 
     pdp->eua.l, pdp->eua.v);
  */
  
  gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	    pdp->gsnlc.l, pdp->gsnlc.v);
  gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	    pdp->gsnlu.l, pdp->gsnlu.v);
  
  if (pdp->version == 1) 
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE,
	      pdp->qos_req.l, pdp->qos_req.v);
  
  
  if ((pdp->version == 1) && pdp->tft.l)
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_TFT,
	      pdp->tft.l, pdp->tft.v);
  
  if ((pdp->version == 1) && pdp->triggerid.l)
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_TRIGGER_ID,
	      pdp->triggerid.l, pdp->triggerid.v);
  
  if ((pdp->version == 1) && pdp->omcid.l)
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_OMC_ID,
	      pdp->omcid.l, pdp->omcid.v);
  
  gtp_req(gsn, pdp->version, NULL, &packet, length, inetaddr, cbp);

  return 0;
}


/* Send Update PDP Context Response */
int gtp_update_pdp_resp(struct gsn_t *gsn, int version, 
			struct sockaddr_in *peer, int fd, 
			void *pack, unsigned len,
			struct pdp_t *pdp, uint8_t cause) {
  
  union gtp_packet packet;
  unsigned int length = get_default_gtp(version, GTP_CREATE_PDP_RSP, &packet);
  
  gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_CAUSE, cause);
  
  if (cause == GTPCAUSE_ACC_REQ) {
    
    if (version == 0) 
      gtpie_tv0(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE0, 
		sizeof(pdp->qos_neg0), pdp->qos_neg0);

    gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_RECOVERY, 
	      gsn->restart_counter);

    if (version == 0) {
      gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_DI, 
		pdp->fllu);
      gtpie_tv2(&packet, &length, GTP_MAX, GTPIE_FL_C,
		pdp->fllc);
    }

    if (version == 1) {
      gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_DI, 
		pdp->teid_own);
      
      if (!pdp->teic_confirmed)
	gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_TEI_C,
		  pdp->teic_own);
    }
    
    /* TODO we use teid_own as charging ID address */
    gtpie_tv4(&packet, &length, GTP_MAX, GTPIE_CHARGING_ID,
	      pdp->teid_own); 
    
    /* If ggsn 
       gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_EUA, 
       pdp->eua.l, pdp->eua.v); */
    
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	      pdp->gsnlc.l, pdp->gsnlc.v);
    gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	      pdp->gsnlu.l, pdp->gsnlu.v);
    
    if (version == 1)
      gtpie_tlv(&packet, &length, GTP_MAX, GTPIE_QOS_PROFILE,
		pdp->qos_neg.l, pdp->qos_neg.v);
    
    /* TODO: Charging gateway address */
  }
  
  return gtp_resp(version, gsn, pdp, &packet, length, peer, 
		  fd, get_seq(pack), get_tid(pack));
}


/* Handle Update PDP Context Request */
int gtp_update_pdp_ind(struct gsn_t *gsn, int version,
		       struct sockaddr_in *peer, int fd, 
		       void *pack, unsigned len) {
  struct pdp_t *pdp;
  struct pdp_t pdp_backup;
  union gtpie_member* ie[GTPIE_SIZE];
  uint8_t recovery;

  uint16_t seq = get_seq(pack);
  int hlen = get_hlen(pack);

  uint64_t imsi;
  uint8_t nsapi;
  
  /* Is this a dublicate ? */
  if(!gtp_dublicate(gsn, version, peer, seq)) {
    return 0; /* We allready send of response once */
  }
  
  
  /* Decode information elements */
  if (gtpie_decaps(ie, version, pack+hlen, len-hlen)) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    if (0 == version)
      return EOF;
    else
      return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len,
				 NULL, GTPCAUSE_INVALID_MESSAGE);
  }

  /* Finding PDP: */
  /* For GTP0 we use the tunnel identifier to provide imsi and nsapi. */
  /* For GTP1 we must use imsi and nsapi if imsi is present. Otherwise */
  /* we have to use the tunnel endpoint identifier */
  if (version == 0) {
    imsi = ((union gtp_packet*)pack)->gtp0.h.tid & 0x0fffffffffffffffull;
    nsapi = (((union gtp_packet*)pack)->gtp0.h.tid & 0xf000000000000000ull) >> 60;
    
    /* Find the context in question */
    if (pdp_getimsi(&pdp, imsi, nsapi)) {
      gsn->err_unknownpdp++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Unknown PDP context");
      return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len, 
				 NULL, GTPCAUSE_NON_EXIST);
    }
  }
  else if (version == 1) {
    /* NSAPI (mandatory) */
    if (gtpie_gettv1(ie, GTPIE_NSAPI, 0, &nsapi)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len,
				 NULL, GTPCAUSE_MAN_IE_MISSING);
    }
    
    /* IMSI (conditional) */
    if (gtpie_gettv0(ie, GTPIE_IMSI, 0, &imsi, sizeof(imsi))) {
      /* Find the context in question */
      if (pdp_getgtp1(&pdp, get_tei(pack))) {
	gsn->err_unknownpdp++;
	gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		    "Unknown PDP context");
	return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len,
				   NULL, GTPCAUSE_NON_EXIST);
      }
    }
    else {
      /* Find the context in question */
      if (pdp_getimsi(&pdp, imsi, nsapi)) {
	gsn->err_unknownpdp++;
	gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		    "Unknown PDP context");
	return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len,
				   NULL, GTPCAUSE_NON_EXIST);
      }
    }
  }
  else {
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Unknown version");
    return EOF;
  }
  
  /* Make a backup copy in case anything is wrong */
  memcpy(&pdp_backup, pdp, sizeof(pdp_backup));

  if (version == 0) {
    if (gtpie_gettv0(ie, GTPIE_QOS_PROFILE0, 0,
		     pdp->qos_req0, sizeof(pdp->qos_req0))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
      return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len, 
				 pdp, GTPCAUSE_MAN_IE_MISSING);
    }
  }

  /* Recovery (optional) */
  if (!gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
    /* TODO: Handle received recovery IE */
  }

  if (version == 0) {
    if (gtpie_gettv2(ie, GTPIE_FL_DI, 0, &pdp->flru)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
      return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }
    
    if (gtpie_gettv2(ie, GTPIE_FL_C, 0, &pdp->flrc)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
      return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }
  }


  if (version == 1) {
    /* TEID (mandatory) */
    if (gtpie_gettv4(ie, GTPIE_TEI_DI, 0, &pdp->teid_gn)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
      return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }
    
    /* TEIC (conditional) */
    /* If TEIC is not included it means that we have allready received it */
    /* TODO: From 29.060 it is not clear if TEI_C MUST be included for */
    /* all updated contexts, or only for one of the linked contexts */
    gtpie_gettv4(ie, GTPIE_TEI_C, 0, &pdp->teic_gn);
    
    /* NSAPI (mandatory) */
    if (gtpie_gettv1(ie, GTPIE_NSAPI, 0, &pdp->nsapi)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
      return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }
  }
  
  /* Trace reference (optional) */
  /* Trace type (optional) */

  /* End User Address (conditional) TODO: GGSN Initiated
  if (gtpie_gettlv(ie, GTPIE_EUA, 0, &pdp->eua.l,
		     &pdp->eua.v, sizeof(pdp->eua.v))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
    return gtp_update_pdp_resp(gsn, version, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  } */


  /* SGSN address for signalling (mandatory) */
  /* It is weird that this is mandatory when TEIC is conditional */
  if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 0, &pdp->gsnrc.l,
		     &pdp->gsnrc.v, sizeof(pdp->gsnrc.v))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
    return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  /* SGSN address for user traffic (mandatory) */
  if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 1, &pdp->gsnru.l,
		     &pdp->gsnru.v, sizeof(pdp->gsnru.v))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
    return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  }
  
  if (version == 1) {
    /* QoS (mandatory) */
    if (gtpie_gettlv(ie, GTPIE_QOS_PROFILE, 0, &pdp->qos_req.l,
		     &pdp->qos_req.v, sizeof(pdp->qos_req.v))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      memcpy(pdp, &pdp_backup, sizeof(pdp_backup));
      return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }

    /* TFT (conditional) */
    if (gtpie_gettlv(ie, GTPIE_TFT, 0, &pdp->tft.l,
		     &pdp->tft.v, sizeof(pdp->tft.v))) {
    }
    
    /* OMC identity */
  }

  /* Confirm to peer that things were "successful" */
  return gtp_update_pdp_resp(gsn, version, peer, fd, pack, len, pdp, 
			     GTPCAUSE_ACC_REQ);
}


/* Handle Update PDP Context Response */
int gtp_update_pdp_conf(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, 
			void *pack, unsigned len) {
  struct pdp_t *pdp; 
  union gtpie_member *ie[GTPIE_SIZE];
  uint8_t cause, recovery;
  void *cbp = NULL;
  uint8_t type = 0;
  
  /* Remove packet from queue */
  if (gtp_conf(gsn, 0, peer, pack, len, &type, &cbp)) return EOF;

  /* Find the context in question */
  if (pdp_getgtp0(&pdp, ntoh16(((union gtp_packet*)pack)->gtp0.h.flow))) {
    gsn->err_unknownpdp++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unknown PDP context");
    if (gsn->cb_conf) gsn->cb_conf(type, cause, NULL, cbp);
    return EOF;
  }

  /* Register that we have received a valid teic from GGSN */
  pdp->teic_confirmed = 1;

  /* Decode information elements */
  if (gtpie_decaps(ie, 0, pack+GTP0_HEADER_SIZE, len-GTP0_HEADER_SIZE)) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
    /*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	  pdp_freepdp(pdp); */
    return EOF;
  }
      
  /* Extract cause value (mandatory) */
  if (gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause)) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
    /*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	  pdp_freepdp(pdp); */
    return EOF;
  }

  /* Extract recovery (optional) */
  if (!gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
    /* TODO: Handle received recovery IE */
  }

  /* Check all conditional information elements */
  if (GTPCAUSE_ACC_REQ != cause) {
    if (gsn->cb_conf) gsn->cb_conf(type, cause, pdp, cbp);
    /*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	  pdp_freepdp(pdp); */
    return 0;
  }
  else {
    /* Check for missing conditionary information elements */
    if (!(gtpie_exist(ie, GTPIE_QOS_PROFILE0, 0) &&
	  gtpie_exist(ie, GTPIE_REORDER, 0) &&
	  gtpie_exist(ie, GTPIE_FL_DI, 0) &&
	  gtpie_exist(ie, GTPIE_FL_C, 0) &&
	  gtpie_exist(ie, GTPIE_CHARGING_ID, 0) &&
	  gtpie_exist(ie, GTPIE_EUA, 0) &&
	  gtpie_exist(ie, GTPIE_GSN_ADDR, 0) &&
	  gtpie_exist(ie, GTPIE_GSN_ADDR, 1))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, cbp);
      /*    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
	    pdp_freepdp(pdp); */
      return EOF;
    }

    /* Update pdp with new values */
    gtpie_gettv0(ie, GTPIE_QOS_PROFILE0, 0,
		 pdp->qos_neg0, sizeof(pdp->qos_neg0));
    gtpie_gettv1(ie, GTPIE_REORDER, 0, &pdp->reorder);
    gtpie_gettv2(ie, GTPIE_FL_DI, 0, &pdp->flru);
    gtpie_gettv2(ie, GTPIE_FL_C, 0, &pdp->flrc);
    gtpie_gettv4(ie, GTPIE_CHARGING_ID, 0, &pdp->cid);
    gtpie_gettlv(ie, GTPIE_EUA, 0, &pdp->eua.l,
		 &pdp->eua.v, sizeof(pdp->eua.v));
    gtpie_gettlv(ie, GTPIE_GSN_ADDR, 0, &pdp->gsnrc.l,
		 &pdp->gsnrc.v, sizeof(pdp->gsnrc.v));
    gtpie_gettlv(ie, GTPIE_GSN_ADDR, 1, &pdp->gsnru.l,
		 &pdp->gsnru.v, sizeof(pdp->gsnru.v));
    
    if (gsn->cb_conf) gsn->cb_conf(type, cause, pdp, cbp);
    return 0; /* Succes */
  }
}


/* API: Send Delete PDP Context Request */
int gtp_delete_context_req(struct gsn_t *gsn, struct pdp_t *pdp, void *cbp,
			   int teardown) {
  union gtp_packet packet;
  unsigned int length = get_default_gtp(pdp->version, GTP_DELETE_PDP_REQ, &packet);
  struct in_addr addr;
  struct pdp_t *linked_pdp;
  struct pdp_t *secondary_pdp;
  int n;
  int count = 0;

  if (gsna2in_addr(&addr, &pdp->gsnrc)) {
    gsn->err_address++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "GSN address conversion failed");
    return EOF;
  }

  if (pdp_getgtp1(&linked_pdp, pdp->teic_own)) {
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Unknown linked PDP context");
    return EOF;
  }

  if (!teardown) {
    for (n=0; n< PDP_MAXNSAPI; n++)
      if (linked_pdp->secondary_tei[n]) count++;
    if (count <= 1) {
      gtp_err(LOG_ERR, __FILE__, __LINE__, 
	      "Must use teardown for last context");
      return EOF;
    }
  }
 
  if (pdp->version == 1) {
    if (teardown)
      gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_TEARDOWN,
		0xff);

    gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_NSAPI,
	      pdp->nsapi);
  }

  gtp_req(gsn, pdp->version, pdp, &packet, length, &addr, cbp);

  if (teardown) { /* Remove all contexts */
    for (n=0; n< PDP_MAXNSAPI; n++) {
      if (linked_pdp->secondary_tei[n]) {
	if (pdp_getgtp1(&secondary_pdp, linked_pdp->secondary_tei[n])) {
	  gtp_err(LOG_ERR, __FILE__, __LINE__, "Unknown secondary PDP context");
	  return EOF;
	}
	if (linked_pdp != secondary_pdp) {
	  if (gsn->cb_delete_context) gsn->cb_delete_context(secondary_pdp);
	  pdp_freepdp(secondary_pdp);
	}
      }
    }
    if (gsn->cb_delete_context) gsn->cb_delete_context(linked_pdp);
    pdp_freepdp(linked_pdp);
  }
  else {
    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
    if (pdp == linked_pdp) {
      linked_pdp->secondary_tei[pdp->nsapi & 0xf0] = 0;
      linked_pdp->nodata = 1;
    }
    else
      pdp_freepdp(pdp);
  }

  return 0;
}

/* Send Delete PDP Context Response */
int gtp_delete_pdp_resp(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, int fd,
			void *pack, unsigned len, 
			struct pdp_t *pdp, struct pdp_t *linked_pdp, 
			uint8_t cause, int teardown)
{
  union gtp_packet packet;
  struct pdp_t *secondary_pdp;
  unsigned int length = get_default_gtp(version, GTP_DELETE_PDP_RSP, &packet);
  int n;

  gtpie_tv1(&packet, &length, GTP_MAX, GTPIE_CAUSE, cause);

  gtp_resp(version, gsn, pdp, &packet, length, peer, fd,
	   get_seq(pack), get_tid(pack));

  if (cause == GTPCAUSE_ACC_REQ) {
    if ((teardown) || (version == 0)) { /* Remove all contexts */
      for (n=0; n< PDP_MAXNSAPI; n++) {
	if (linked_pdp->secondary_tei[n]) {
	  if (pdp_getgtp1(&secondary_pdp, linked_pdp->secondary_tei[n])) {
	    gtp_err(LOG_ERR, __FILE__, __LINE__, 
		    "Unknown secondary PDP context");
	    return EOF;
	  }
	  if (linked_pdp != secondary_pdp) {
	    if (gsn->cb_delete_context) gsn->cb_delete_context(secondary_pdp);
	    pdp_freepdp(secondary_pdp);
	  }
	}
      }
      if (gsn->cb_delete_context) gsn->cb_delete_context(linked_pdp);
      pdp_freepdp(linked_pdp);
    }
    else { /* Remove only current context */
      if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
      if (pdp == linked_pdp) {
	linked_pdp->secondary_tei[pdp->nsapi & 0xf0] = 0;
	linked_pdp->nodata = 1;
      }
      else
	pdp_freepdp(pdp);
    }
  } /* if (cause == GTPCAUSE_ACC_REQ) */
  
  return 0;
}

/* Handle Delete PDP Context Request */
int gtp_delete_pdp_ind(struct gsn_t *gsn, int version,
		       struct sockaddr_in *peer, int fd,
		       void *pack, unsigned len) {
  struct pdp_t *pdp = NULL;
  struct pdp_t *linked_pdp = NULL;
  union gtpie_member* ie[GTPIE_SIZE];
  
  uint16_t seq = get_seq(pack);
  int hlen = get_hlen(pack);

  uint8_t nsapi;
  uint8_t teardown = 0;
  int n;
  int count = 0;

  /* Is this a dublicate ? */
  if(!gtp_dublicate(gsn, version, peer, seq)) {
    return 0; /* We allready send off response once */
  }

  /* Find the linked context in question */
  if (pdp_getgtp1(&linked_pdp, get_tei(pack))) {
    gsn->err_unknownpdp++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unknown PDP context");
    return gtp_delete_pdp_resp(gsn, version, peer, fd, pack, len, NULL, NULL,
			       GTPCAUSE_NON_EXIST, teardown);
  }

  /* If version 0 this is also the secondary context */
  if (version == 0) 
    pdp = linked_pdp;
  
  /* Decode information elements */
  if (gtpie_decaps(ie, version, pack+hlen, len-hlen)) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    if (0 == version)
      return EOF;
    else
      return gtp_delete_pdp_resp(gsn, version, peer, fd, pack, len, NULL, NULL,
				 GTPCAUSE_INVALID_MESSAGE, teardown);
  }
  
  if (version == 1) {
    /* NSAPI (mandatory) */
    if (gtpie_gettv1(ie, GTPIE_NSAPI, 0, &nsapi)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing mandatory information field");
      return gtp_delete_pdp_resp(gsn, version, peer, fd, pack, len, NULL, NULL,
				 GTPCAUSE_MAN_IE_MISSING, teardown);
    }
    
    /* Find the context in question */
    if (pdp_getgtp1(&pdp, linked_pdp->secondary_tei[nsapi & 0x0f])) {
      gsn->err_unknownpdp++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Unknown PDP context");
      return gtp_delete_pdp_resp(gsn, version, peer, fd, pack, len, NULL, NULL,
				 GTPCAUSE_NON_EXIST, teardown);
    }
    
    /* Teardown (conditional) */
    gtpie_gettv1(ie, GTPIE_TEARDOWN, 0, &teardown);

    if (!teardown) {
      for (n=0; n< PDP_MAXNSAPI; n++)
	if (linked_pdp->secondary_tei[n]) count++;
      if (count <= 1) {
	return 0; /* 29.060 7.3.5 Ignore message */
      }
    }
  }

  return gtp_delete_pdp_resp(gsn, version, peer, fd, pack, len, 
			     pdp, linked_pdp, GTPCAUSE_ACC_REQ, teardown);
}


/* Handle Delete PDP Context Response */
int gtp_delete_pdp_conf(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, 
			void *pack, unsigned len) {
  union gtpie_member *ie[GTPIE_SIZE];
  uint8_t cause;
  void *cbp = NULL;
  uint8_t type = 0;
  int hlen = get_hlen(pack);
  
  /* Remove packet from queue */
  if (gtp_conf(gsn, version, peer, pack, len, &type, &cbp)) return EOF;
  
  /* Decode information elements */
  if (gtpie_decaps(ie, version, pack+hlen, len-hlen)) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, NULL, cbp);
    return EOF;
  }

  /* Extract cause value (mandatory) */
  if (gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause)) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, NULL, cbp);
    return EOF;
  }

  /* Check the cause value (again) */
  if ((GTPCAUSE_ACC_REQ != cause) && (GTPCAUSE_NON_EXIST != cause)) {
    gsn->err_cause++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unexpected cause value received: %d", cause);
    if (gsn->cb_conf) gsn->cb_conf(type, cause, NULL, cbp);
    return EOF;
  }
  
  /* Callback function to notify application */
  if (gsn->cb_conf) gsn->cb_conf(type, cause, NULL, cbp);
  
  return 0;
}

/* Send Error Indication (response to a GPDU message */
int gtp_error_ind_resp(struct gsn_t *gsn, int version,
		       struct sockaddr_in *peer, int fd,
		       void *pack, unsigned len)
{
  union gtp_packet packet;
  unsigned int length = get_default_gtp(version, GTP_ERROR, &packet);
  
  return gtp_resp(version, gsn, NULL, &packet, length, peer, fd,
		  get_seq(pack), get_tid(pack));
}

/* Handle Error Indication */
int gtp_error_ind_conf(struct gsn_t *gsn, int version,
		       struct sockaddr_in *peer, 
		       void *pack, unsigned len) {
  struct pdp_t *pdp; 
  
  /* Find the context in question */
  if (pdp_tidget(&pdp, ((union gtp_packet*)pack)->gtp0.h.tid)) {
    gsn->err_unknownpdp++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unknown PDP context");
    return EOF;
  }

  gsn->err_unknownpdp++; /* TODO: Change counter */
  gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
	      "Received Error Indication");

  if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
  pdp_freepdp(pdp);
  return 0;
}

int gtp_gpdu_ind(struct gsn_t *gsn, int version,
		  struct sockaddr_in *peer, int fd,
		  void *pack, unsigned len) {

  int hlen = GTP1_HEADER_SIZE_SHORT;

  /* Need to include code to verify packet src and dest addresses */
  struct pdp_t *pdp; 

  if (version == 0) {
    if (pdp_getgtp0(&pdp, ntoh16(((union gtp_packet*)pack)->gtp0.h.flow))) {
      gsn->err_unknownpdp++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Unknown PDP context");
      return gtp_error_ind_resp(gsn, version, peer, fd, pack, len);
    }
    hlen = GTP0_HEADER_SIZE;
  }
  else if (version == 1) {
    if (pdp_getgtp1(&pdp, ntoh32(((union gtp_packet*)pack)->gtp1l.h.tei))) {
      gsn->err_unknownpdp++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Unknown PDP context");
      return gtp_error_ind_resp(gsn, version, peer, fd, pack, len);
    }

    /* Is this a long or a short header ? */
    if (((union gtp_packet*)pack)->gtp1l.h.flags & 0x07)
      hlen = GTP1_HEADER_SIZE_LONG;
    else
      hlen = GTP1_HEADER_SIZE_SHORT;
  }
  else {
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unknown version");
  }
  
  /* If the GPDU was not from the peer GSN tell him to delete context */
  if (memcmp(&peer->sin_addr, pdp->gsnru.v, pdp->gsnru.l)) { /* TODO Range? */
    gsn->err_unknownpdp++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unknown PDP context");
    return gtp_error_ind_resp(gsn, version, peer, fd, pack, len);
  }

  /* Callback function */
  if (gsn->cb_data_ind !=0)
    return gsn->cb_data_ind(pdp, pack+hlen, len-hlen);

  return 0;
}



/* Receives GTP packet and sends off for further processing 
 * Function will check the validity of the header. If the header
 * is not valid the packet is either dropped or a version not 
 * supported is returned to the peer. 
 * TODO: Need to decide on return values! */
int gtp_decaps0(struct gsn_t *gsn)
{
  unsigned char buffer[PACKET_MAX];
  struct sockaddr_in peer;
  size_t peerlen;
  int status;
  struct gtp0_header *pheader;
  int version = 0; /* GTP version should be determined from header!*/
  int fd = gsn->fd0;

  /* TODO: Need strategy of userspace buffering and blocking */
  /* Currently read is non-blocking and send is blocking. */
  /* This means that the program have to wait for busy send calls...*/

  while (1) { /* Loop until no more to read */
    if (fcntl(gsn->fd0, F_SETFL, O_NONBLOCK)) {
      gtp_err(LOG_ERR, __FILE__, __LINE__, "fnctl()");
      return -1;
    }
    peerlen = sizeof(peer);
    if ((status = 
	 recvfrom(gsn->fd0, buffer, sizeof(buffer), 0,
		  (struct sockaddr *) &peer, &peerlen)) < 0 ) {
      if (errno == EAGAIN) return 0;
      gsn->err_readfrom++;
      gtp_err(LOG_ERR, __FILE__, __LINE__, "recvfrom(fd0=%d, buffer=%lx, len=%d) failed: status = %d error = %s", gsn->fd0, (unsigned long) buffer, sizeof(buffer), status, status ? strerror(errno) : "No error");
      return -1;
    }
  
    /* Need at least 1 byte in order to check version */
    if (status < (1)) {
      gsn->empty++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Discarding packet - too small");
      continue;
    }
    
    pheader = (struct gtp0_header *) (buffer);
    
    /* Version should be gtp0 (or earlier) */
    /* 09.60 is somewhat unclear on this issue. On gsn->fd0 we expect only */
    /* GTP 0 messages. If other version message is received we reply that we */
    /* only support version 0, implying that this is the only version */
    /* supported on this port */
    if (((pheader->flags & 0xe0) > 0x00)) {
      gsn->unsup++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unsupported GTP version");
      gtp_unsup_req(gsn, 0, &peer, gsn->fd0, buffer, status); /* 29.60: 11.1.1 */
      continue;
    }
    
    /* Check length of gtp0 packet */
    if (status < GTP0_HEADER_SIZE) {
      gsn->tooshort++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "GTP0 packet too short");
      continue;  /* Silently discard 29.60: 11.1.2 */
    }

    /* Check packet length field versus length of packet */
    if (status != (ntoh16(pheader->length) + GTP0_HEADER_SIZE)) {
      gsn->tooshort++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "GTP packet length field does not match actual length");
      continue;  /* Silently discard */
    }
    
    if ((gsn->mode == GTP_MODE_GGSN) && 
	((pheader->type == GTP_CREATE_PDP_RSP) ||
	 (pheader->type == GTP_UPDATE_PDP_RSP) ||
	 (pheader->type == GTP_DELETE_PDP_RSP))) {
      gsn->unexpect++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unexpected GTP Signalling Message");
      continue;  /* Silently discard 29.60: 11.1.4 */
    }

    if ((gsn->mode == GTP_MODE_SGSN) && 
	((pheader->type == GTP_CREATE_PDP_REQ) ||
	 (pheader->type == GTP_UPDATE_PDP_REQ) ||
	 (pheader->type == GTP_DELETE_PDP_REQ))) {
      gsn->unexpect++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unexpected GTP Signalling Message");
      continue;  /* Silently discard 29.60: 11.1.4 */
    }

    switch (pheader->type) {
    case GTP_ECHO_REQ:
      gtp_echo_ind(gsn, version, &peer, fd, buffer, status);
      break;
    case GTP_ECHO_RSP:
      gtp_echo_conf(gsn, version, &peer, buffer, status);
      break;
    case GTP_NOT_SUPPORTED:
      gtp_unsup_ind(gsn, &peer, buffer, status);
      break;
    case GTP_CREATE_PDP_REQ:
      gtp_create_pdp_ind(gsn, version, &peer, fd, buffer, status);
      break;
    case GTP_CREATE_PDP_RSP:
      gtp_create_pdp_conf(gsn, version, &peer, buffer, status);
      break;
    case GTP_UPDATE_PDP_REQ:
      gtp_update_pdp_ind(gsn, version, &peer, fd, buffer, status);
      break;
    case GTP_UPDATE_PDP_RSP:
      gtp_update_pdp_conf(gsn, version, &peer, buffer, status);
      break;
    case GTP_DELETE_PDP_REQ:
      gtp_delete_pdp_ind(gsn, version, &peer, fd, buffer, status);
      break;
    case GTP_DELETE_PDP_RSP:
      gtp_delete_pdp_conf(gsn, version, &peer, buffer, status);
      break;
    case GTP_ERROR:
      gtp_error_ind_conf(gsn, version, &peer, buffer, status);
      break;
    case GTP_GPDU:
      gtp_gpdu_ind(gsn, version, &peer, fd, buffer, status);
      break;
    default:
      gsn->unknown++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unknown GTP message type received");
      break;
    }
  }
}


int gtp_decaps1c(struct gsn_t *gsn)
{
  unsigned char buffer[PACKET_MAX];
  struct sockaddr_in peer;
  size_t peerlen;
  int status;
  struct gtp1_header_short *pheader;
  int version = 1; /* TODO GTP version should be determined from header!*/
  int fd = gsn->fd1c;

  /* TODO: Need strategy of userspace buffering and blocking */
  /* Currently read is non-blocking and send is blocking. */
  /* This means that the program have to wait for busy send calls...*/

  while (1) { /* Loop until no more to read */
    if (fcntl(fd, F_SETFL, O_NONBLOCK)) {
      gtp_err(LOG_ERR, __FILE__, __LINE__, "fnctl()");
      return -1;
    }
    peerlen = sizeof(peer);
    if ((status = 
	 recvfrom(fd, buffer, sizeof(buffer), 0,
		  (struct sockaddr *) &peer, &peerlen)) < 0 ) {
      if (errno == EAGAIN) return 0;
      gsn->err_readfrom++;
      gtp_err(LOG_ERR, __FILE__, __LINE__, "recvfrom(fd=%d, buffer=%lx, len=%d) failed: status = %d error = %s", fd, (unsigned long) buffer, sizeof(buffer), status, status ? strerror(errno) : "No error");
      return -1;
    }
  
    /* Need at least 1 byte in order to check version */
    if (status < (1)) {
      gsn->empty++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Discarding packet - too small");
      continue;
    }
    
    pheader = (struct gtp1_header_short *) (buffer);
    
    /* Version must be no larger than GTP 1 */
    if (((pheader->flags & 0xe0) > 0x20)) {
      gsn->unsup++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unsupported GTP version");
      gtp_unsup_req(gsn, version, &peer, fd, buffer, status);
      /*29.60: 11.1.1*/
      continue;
    }

    /* Version must be at least GTP 1 */
    /* 29.060 is somewhat unclear on this issue. On gsn->fd1c we expect only */
    /* GTP 1 messages. If GTP 0 message is received we silently discard */
    /* the message */
    if (((pheader->flags & 0xe0) < 0x20)) {
      gsn->unsup++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unsupported GTP version");
      continue;
    }

    /* Check packet flag field */
    if (((pheader->flags & 0xf7) != 0x32)) {
      gsn->unsup++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unsupported packet flag");
      continue;
    }

    /* Check length of packet */
    if (status < GTP1_HEADER_SIZE_LONG) {
      gsn->tooshort++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "GTP packet too short");
      continue;  /* Silently discard 29.60: 11.1.2 */
    }

    /* Check packet length field versus length of packet */
    if (status != (ntoh16(pheader->length) + GTP1_HEADER_SIZE_SHORT)) {
      gsn->tooshort++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "GTP packet length field does not match actual length");
      continue;  /* Silently discard */
    }

    /* Check for extension headers */
    /* TODO: We really should cycle through the headers and determine */
    /* if any have the comprehension required flag set */
    if (((pheader->flags & 0x04) != 0x00)) {
      gsn->unsup++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unsupported extension header");
      gtp_extheader_req(gsn, version, &peer, fd, buffer, status);

      continue;
    }

    if ((gsn->mode == GTP_MODE_GGSN) && 
	((pheader->type == GTP_CREATE_PDP_RSP) ||
	 (pheader->type == GTP_UPDATE_PDP_RSP) ||
	 (pheader->type == GTP_DELETE_PDP_RSP))) {
      gsn->unexpect++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unexpected GTP Signalling Message");
      continue;  /* Silently discard 29.60: 11.1.4 */
    }

    if ((gsn->mode == GTP_MODE_SGSN) && 
	((pheader->type == GTP_CREATE_PDP_REQ) ||
	 (pheader->type == GTP_UPDATE_PDP_REQ) ||
	 (pheader->type == GTP_DELETE_PDP_REQ))) {
      gsn->unexpect++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unexpected GTP Signalling Message");
      continue;  /* Silently discard 29.60: 11.1.4 */
    }

    switch (pheader->type) {
    case GTP_ECHO_REQ:
      gtp_echo_ind(gsn, version, &peer, fd, buffer, status);
      break;
    case GTP_ECHO_RSP:
      gtp_echo_conf(gsn, version, &peer, buffer, status);
      break;
    case GTP_NOT_SUPPORTED:
      gtp_unsup_ind(gsn, &peer, buffer, status);
      break;
    case GTP_SUPP_EXT_HEADER:
      gtp_extheader_ind(gsn, &peer, buffer, status);
      break;
    case GTP_CREATE_PDP_REQ:
      gtp_create_pdp_ind(gsn, version, &peer, fd, buffer, status);
      break;
    case GTP_CREATE_PDP_RSP:
      gtp_create_pdp_conf(gsn, version, &peer, buffer, status);
      break;
    case GTP_UPDATE_PDP_REQ:
      gtp_update_pdp_ind(gsn, version, &peer, fd, buffer, status);
      break;
    case GTP_UPDATE_PDP_RSP:
      gtp_update_pdp_conf(gsn, version, &peer, buffer, status);
      break;
    case GTP_DELETE_PDP_REQ:
      gtp_delete_pdp_ind(gsn, version, &peer, fd, buffer, status);
      break;
    case GTP_DELETE_PDP_RSP:
      gtp_delete_pdp_conf(gsn, version, &peer, buffer, status);
      break;
    case GTP_ERROR:
      gtp_error_ind_conf(gsn, version, &peer, buffer, status);
      break;
    default:
      gsn->unknown++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unknown GTP message type received");
      break;
    }
  }
}

int gtp_decaps1u(struct gsn_t *gsn)
{
  unsigned char buffer[PACKET_MAX];
  struct sockaddr_in peer;
  size_t peerlen;
  int status;
  struct gtp1_header_short *pheader;
  int version = 1; /* GTP version should be determined from header!*/
  int fd = gsn->fd1u;

  /* TODO: Need strategy of userspace buffering and blocking */
  /* Currently read is non-blocking and send is blocking. */
  /* This means that the program have to wait for busy send calls...*/

  while (1) { /* Loop until no more to read */
    if (fcntl(gsn->fd1u, F_SETFL, O_NONBLOCK)) {
      gtp_err(LOG_ERR, __FILE__, __LINE__, "fnctl()");
      return -1;
    }
    peerlen = sizeof(peer);
    if ((status = 
	 recvfrom(gsn->fd1u, buffer, sizeof(buffer), 0,
		  (struct sockaddr *) &peer, &peerlen)) < 0 ) {
      if (errno == EAGAIN) return 0;
      gsn->err_readfrom++;
      gtp_err(LOG_ERR, __FILE__, __LINE__, "recvfrom(fd1u=%d, buffer=%lx, len=%d) failed: status = %d error = %s", gsn->fd1u, (unsigned long) buffer, sizeof(buffer), status, status ? strerror(errno) : "No error");
      return -1;
    }
  
    /* Need at least 1 byte in order to check version */
    if (status < (1)) {
      gsn->empty++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Discarding packet - too small");
      continue;
    }
    
    pheader = (struct gtp1_header_short *) (buffer);
    
    /* Version must be no larger than GTP 1 */
    if (((pheader->flags & 0xe0) > 0x20)) {
      gsn->unsup++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unsupported GTP version");
      gtp_unsup_req(gsn, 1, &peer, gsn->fd1c, buffer, status);/*29.60: 11.1.1*/
      continue;
    }

    /* Version must be at least GTP 1 */
    /* 29.060 is somewhat unclear on this issue. On gsn->fd1c we expect only */
    /* GTP 1 messages. If GTP 0 message is received we silently discard */
    /* the message */
    if (((pheader->flags & 0xe0) < 0x20)) {
      gsn->unsup++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unsupported GTP version");
      continue;
    }

    /* Check packet flag field (allow both with and without sequence number)*/
    if (((pheader->flags & 0xf5) != 0x30)) {
      gsn->unsup++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unsupported packet flag");
      continue;
    }

    /* Check length of packet */
    if (status < GTP1_HEADER_SIZE_SHORT) {
      gsn->tooshort++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "GTP packet too short");
      continue;  /* Silently discard 29.60: 11.1.2 */
    }

    /* Check packet length field versus length of packet */
    if (status != (ntoh16(pheader->length) + GTP1_HEADER_SIZE_SHORT)) {
      gsn->tooshort++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "GTP packet length field does not match actual length");
      continue;  /* Silently discard */
    }

    /* Check for extension headers */
    /* TODO: We really should cycle through the headers and determine */
    /* if any have the comprehension required flag set */
    if (((pheader->flags & 0x04) != 0x00)) {
      gsn->unsup++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unsupported extension header");
      gtp_extheader_req(gsn, version, &peer, fd, buffer, status);

      continue;
    }
    
    switch (pheader->type) {
    case GTP_ECHO_REQ:
      gtp_echo_ind(gsn, version, &peer, fd, buffer, status);
      break;
    case GTP_ECHO_RSP:
      gtp_echo_conf(gsn, version, &peer, buffer, status);
      break;
    case GTP_SUPP_EXT_HEADER:
      gtp_extheader_ind(gsn, &peer, buffer, status);
      break;
    case GTP_ERROR:
      gtp_error_ind_conf(gsn, version, &peer, buffer, status);
      break;
      /* Supported header extensions */
    case GTP_GPDU:
      gtp_gpdu_ind(gsn, version, &peer, fd, buffer, status);
      break;
    default:
      gsn->unknown++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unknown GTP message type received");
      break;
    }
  }
}

int gtp_data_req(struct gsn_t *gsn, struct pdp_t* pdp, 
	     void *pack, unsigned len)
{
  union gtp_packet packet;
  struct sockaddr_in addr;
  int fd;
  int length;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
#if defined(__FreeBSD__) || defined(__APPLE__)
  addr.sin_len = sizeof(addr);
#endif

  memcpy(&addr.sin_addr, pdp->gsnru.v,pdp->gsnru.l); /* TODO range check */

  if (pdp->version == 0) {
    
    length = GTP0_HEADER_SIZE+len;
    addr.sin_port = htons(GTP0_PORT);
    fd = gsn->fd0;
    
    get_default_gtp(0, GTP_GPDU, &packet);
    packet.gtp0.h.length = hton16(len);
    packet.gtp0.h.seq = hton16(pdp->gtpsntx++);
    packet.gtp0.h.flow = hton16(pdp->flru);
    packet.gtp0.h.tid = (pdp->imsi & 0x0fffffffffffffffull) + ((uint64_t)pdp->nsapi << 60);

    if (len > sizeof (union gtp_packet) - sizeof(struct gtp0_header)) {
      gsn->err_memcpy++;
      gtp_err(LOG_ERR, __FILE__, __LINE__, 
	      "Memcpy failed: %d > %d", len,
	      sizeof (union gtp_packet) - sizeof(struct gtp0_header));
      return EOF;
    }
    memcpy(packet.gtp0.p, pack, len); /* TODO Should be avoided! */
  }
  else if (pdp->version == 1) {
    
    length = GTP1_HEADER_SIZE_LONG+len;
    addr.sin_port = htons(GTP1U_PORT);
    fd = gsn->fd1u;

    get_default_gtp(1, GTP_GPDU, &packet);
    packet.gtp1l.h.length = hton16(len-GTP1_HEADER_SIZE_SHORT+
				   GTP1_HEADER_SIZE_LONG);
    packet.gtp1l.h.seq = hton16(pdp->gtpsntx++);
    packet.gtp1l.h.tei = hton32(pdp->teid_gn);

    if (len > sizeof (union gtp_packet) - sizeof(struct gtp1_header_long)) {
      gsn->err_memcpy++;
      gtp_err(LOG_ERR, __FILE__, __LINE__, 
	      "Memcpy failed: %d > %d", len,
	      sizeof (union gtp_packet) - sizeof(struct gtp0_header));
      return EOF;
    }
    memcpy(packet.gtp1l.p, pack, len); /* TODO Should be avoided! */
  }
  else {
    gtp_err(LOG_ERR, __FILE__, __LINE__, 
	    "Unknown version");
    return EOF;
  }

  if (fcntl(fd, F_SETFL, 0)) {
    gtp_err(LOG_ERR, __FILE__, __LINE__, "fnctl()");
    return -1;
  }

  if (sendto(fd, &packet, length, 0,
	     (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    gsn->err_sendto++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Sendto(fd=%d, msg=%lx, len=%d) failed: Error = %s", fd, (unsigned long) &packet, GTP0_HEADER_SIZE+len, strerror(errno));
    return EOF;
  }
  return 0;
}


/* ***********************************************************
 * Conversion functions
 *************************************************************/

int char2ul_t(char* src, struct ul_t dst) {
  dst.l = strlen(src)+1;
  dst.v = malloc(dst.l);
  dst.v[0] = dst.l - 1;
  memcpy(&dst.v[1], src, dst.v[0]);
  return 0;
}

/* ***********************************************************
 * IP address conversion functions
 * There exist several types of address representations:
 * - eua: End User Address. (29.060, 7.7.27, message type 128) 
 *   Used for signalling address to mobile station. Supports IPv4
 *   IPv6 x.25 etc. etc.
 * - gsna: GSN Address. (29.060, 7.7.32, message type 133): IP address
 *   of GSN. If length is 4 it is IPv4. If length is 16 it is IPv6.
 * - in_addr: IPv4 address struct.
 * - sockaddr_in: Socket API representation of IP address and
 *   port number.
 *************************************************************/

int ipv42eua(struct ul66_t *eua, struct in_addr *src) {
  eua->v[0] = 0xf1; /* IETF */
  eua->v[1] = 0x21; /* IPv4 */
  if (src) {
    eua->l = 6;
    memcpy(&eua->v[2], src, 4);
  }
  else 
    {
      eua->l = 2;
    }
  return 0;
}

int eua2ipv4(struct in_addr *dst, struct ul66_t *eua) {
  if ((eua->l != 6) || 
      (eua->v[0] != 0xf1) || 
      (eua->v[1] = 0x21)) 
    return -1; /* Not IPv4 address*/
  memcpy(dst, &eua->v[2], 4);
  return 0;
}

int gsna2in_addr(struct in_addr *dst, struct ul16_t *gsna) {
  memset(dst, 0, sizeof(struct in_addr));
  if (gsna->l != 4) return EOF; /* Return if not IPv4 */
  memcpy(dst, gsna->v, gsna->l);
  return 0;
}

int in_addr2gsna(struct ul16_t *gsna, struct in_addr *src) {
  memset(gsna, 0, sizeof(struct ul16_t));
  gsna->l = 4;
  memcpy(gsna->v, src, gsna->l);
  return 0;
}

