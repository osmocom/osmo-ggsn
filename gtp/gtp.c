/* 
 *  OpenGGSN - Gateway GPRS Support Node
 *  Copyright (C) 2002 Mondru AB.
 * 
 *  The contents of this file may be used under the terms of the GNU
 *  General Public License Version 2, provided that the above copyright
 *  notice and this permission notice is included in all copies or
 *  substantial portions of the software.
 * 
 *  The initial developer of the original code is
 *  Jens Jakobsen <jj@openggsn.org>
 * 
 *  Contributor(s):
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

#include <stdint.h> /* ISO C99 types */

#include "../config.h"
#include "pdp.h"
#include "gtp.h"
#include "gtpie.h"
#include "queue.h"


struct gtp0_header gtp0_default;
struct gtp1_header_long gtp1_default;

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

int gtp_create_context(struct gsn_t *gsn, struct pdp_t *pdp, void *aid,
		       struct in_addr* inetaddr) {
  int version = 0;

  return gtp_create_pdp_req(gsn, version, aid, inetaddr, pdp);
}

int gtp_update_context(struct gsn_t *gsn, struct pdp_t *pdp, void *aid,
		       struct in_addr* inetaddr) {
  int version = 0;
  
  return gtp_update_pdp_req(gsn, version, aid, inetaddr, pdp);
}

int gtp_delete_context(struct gsn_t *gsn, struct pdp_t *pdp, void *aid) {
  int version = 0;
  return gtp_delete_pdp_req(gsn, version, aid, pdp);
}

/* gtp_gpdu */

extern int gtp_fd(struct gsn_t *gsn) {
  return gsn->fd;
}

/* gtp_decaps */
/* gtp_retrans */
/* gtp_retranstimeout */

int gtp_set_cb_delete_context(struct gsn_t *gsn,
			      int (*cb_delete_context) (struct pdp_t* pdp)) 
{
  gsn->cb_delete_context = cb_delete_context;
  return 0;
}

int gtp_set_cb_create_context(struct gsn_t *gsn,
			      int (*cb_create_context) (struct pdp_t* pdp)) 
{
  gsn->cb_create_context = cb_create_context;
  return 0;
}

/*

  int gtp_set_cb_create_pdp_conf(struct gsn_t *gsn, 
  int (*cb) (struct pdp_t*, int)) 
  {
   gsn->cb_create_pdp_conf = cb;
  return 0;
  }

 int gtp_set_cb_update_pdp_conf(struct gsn_t *gsn, 
			       int (*cb) (struct pdp_t*, int, int)) 
 {
   gsn->cb_update_pdp_conf = cb;
   return 0;
} 

in t gtp_set_cb_delete_pdp_conf(struct gsn_t *gsn, 
int (*cb) (struct pdp_t*, int)) 
 { 
gsn->cb_delete_pdp_conf = cb;
return 0;
}

*/

int gtp_set_cb_conf(struct gsn_t *gsn,
		    int (*cb) (int type, int cause, 
			       struct pdp_t* pdp, void *aid)) {
  gsn->cb_conf = cb;
  return 0;
}

extern int gtp_set_cb_gpdu(struct gsn_t *gsn,
			   int (*cb_gpdu) (struct pdp_t* pdp,
					   void* pack,
					   unsigned len)) 
{
  gsn->cb_gpdu = cb_gpdu;
  return 0;
}



void get_default_gtp(int version, void *packet) {
  switch (version) {
  case 0:
    memcpy(packet, &gtp0_default, sizeof(gtp0_default));
  break;
  case 1:
    memcpy(packet, &gtp1_default, sizeof(gtp1_default));
    break;
  }
}

int print_packet(void *packet, unsigned len)
{
  int i;
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
  int n;
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
  int n;
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
 *   sideeffects in the application which is asked twice to allocate
 *   validate the login.
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
 *   Send off a responce to a request. Use the same sequence
 *   number in the response as in the request.
 * gtp_retrans:
 *   Retransmit any outstanding packets which have exceeded
 *   a predefined timeout.
 *************************************************************/

int gtp_req(struct gsn_t *gsn, int version, union gtp_packet *packet, 
	    int len, struct in_addr *inetaddr, void *aid) {
  struct sockaddr_in addr;
  struct qmsg_t *qmsg;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = *inetaddr;
  addr.sin_port = htons(GTP0_PORT);

  packet->gtp0.h.seq = hton16(gsn->seq_next);
  
  if (sendto(gsn->fd, packet, len, 0,
	     (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    gsn->err_sendto++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Sendto(fd=%d, msg=%lx, len=%d) failed: Error = %s", gsn->fd, (unsigned long) &packet, len, strerror(errno));
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
    qmsg->aid = aid;
    qmsg->type = ntoh8(packet->gtp0.h.type);
  }
  gsn->seq_next++; /* Count up this time */
  return 0;
}

/* gtp_conf
 * Remove signalling packet from retransmission queue.
 * return 0 on success, EOF if packet was not found */

int gtp_conf(struct gsn_t *gsn, int version, struct sockaddr_in *peer,
	     union gtp_packet *packet, int len, uint8_t *type, void **aid) {
  int seq = ntoh16(packet->gtp0.h.seq);

  if (queue_freemsg_seq(gsn->queue_req, peer, seq, type, aid)) {
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
      if (gsn->cb_conf) gsn->cb_conf(qmsg->type, EOF, NULL, qmsg->aid);
      queue_freemsg(gsn->queue_req, qmsg);
    }
    else {
      if (sendto(gsn->fd, &qmsg->p, qmsg->l, 0,
		 (struct sockaddr *) &qmsg->peer, sizeof(struct sockaddr_in)) < 0) {
	gsn->err_sendto++;
	gtp_err(LOG_ERR, __FILE__, __LINE__, "Sendto(fd=%d, msg=%lx, len=%d) failed: Error = %s", gsn->fd, (unsigned long) &qmsg->p, qmsg->l, strerror(errno));
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

int gtp_resp(int version, struct gsn_t *gsn, union gtp_packet *packet,
	     int len, struct sockaddr_in *peer) {
  struct qmsg_t *qmsg;
  uint16_t seq;

  seq = ntoh16(packet->gtp0.h.seq);
  
  /* print message */
  /*
  printf("gtp_resp: to %s:UDP%u\n",
	 inet_ntoa(peer->sin_addr),
	 ntohs(peer->sin_port));
  print_packet(packet, len); 
  */
  
  if (sendto(gsn->fd, packet, len, 0,
	     (struct sockaddr *) peer, sizeof(struct sockaddr_in)) < 0) {
    gsn->err_sendto++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Sendto(fd=%d, msg=%lx, len=%d) failed: Error = %s", gsn->fd, (unsigned long) &packet, len, strerror(errno));
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
    qmsg->aid = NULL;
    qmsg->type = 0;
  }
  return 0;
}

int gtp_dublicate(struct gsn_t *gsn, int version,  
		  struct sockaddr_in *peer, uint16_t seq) {
  struct qmsg_t *qmsg;

  if(queue_seqget(gsn->queue_resp, &qmsg, peer, seq)) {
    return EOF; /* Notfound */
  }
  else {
    /* print message */
    
    /*printf("gtp_dublicate: to %s:UDP%u\n",
	   inet_ntoa(peer->sin_addr),
	   ntohs(peer->sin_port));
    print_packet(&qmsg->p, qmsg->l);
    */
    if (sendto(gsn->fd, &qmsg->p, qmsg->l, 0,
	       (struct sockaddr *) peer, sizeof(struct sockaddr_in)) < 0) {
      gsn->err_sendto++;
      gtp_err(LOG_ERR, __FILE__, __LINE__, "Sendto(fd=%d, msg=%lx, len=%d) failed: Error = %s", gsn->fd, (unsigned long) &qmsg->p, qmsg->l, strerror(errno));
    }
    return 0;
  }
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
	  gtp_err(LOG_ERR, __FILE__, __LINE__, "fopen(path=%s, mode=%s) failed: Error = %s", filename, "r", strerror(errno));
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



int gtp_new(struct gsn_t **gsn, char *statedir, struct in_addr *listen) 
{
  struct sockaddr_in addr;
  int gtp_fd;
  
  syslog(LOG_ERR, "GTP: gtp_newgsn() started");

  *gsn = calloc(sizeof(struct gsn_t), 1); /* TODO */

  (*gsn)->statedir = statedir;
  log_restart(*gsn);
  
  /* Initialise request retransmit queue */
  queue_new(&(*gsn)->queue_req);
  queue_new(&(*gsn)->queue_resp);
  
  /* Initialise pdp table */
  pdp_init();

  /* Initialise call back functions */
  (*gsn)->cb_create_context = 0;
  (*gsn)->cb_delete_context = 0;
  (*gsn)->cb_conf = 0;
  (*gsn)->cb_gpdu = 0;

  if ((gtp_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
    (*gsn)->err_socket++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "socket(domain=%d, type=%d, protocol=%d) failed: Error = %s", AF_INET, SOCK_DGRAM, 0, strerror(errno));
    return -1;
  }
  (*gsn)->fd = gtp_fd;
  
  /* syslog(LOG_ERR, "GTP: gtp_init() after socket");*/

  (*gsn)->gsnc = *listen;
  (*gsn)->gsnu = *listen;
    
  memset(&addr, 0, sizeof(addr));
  
  addr.sin_family = AF_INET;
  /*  addr.sin_addr = *inetaddr; */
  addr.sin_addr = *listen;  /* Same IP for user traffic and signalling*/
  addr.sin_port = htons(GTP0_PORT);
  
  if (bind(gtp_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    (*gsn)->err_socket++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "bind(fd=%d, addr=%lx, len=%d) failed: Error = %s", gtp_fd, (unsigned long) &addr, sizeof(addr), strerror(errno));
    return -1;
  }

  /* Initialise "standard" GTP0 header */
  memset(&gtp0_default, 0, sizeof(gtp0_default));
  gtp0_default.flags=0x1e;
  gtp0_default.spare1=0xff;
  gtp0_default.spare2=0xff;
  gtp0_default.spare3=0xff;
  gtp0_default.number=0xff;
  
  /* Initialise "standard" GTP1 header */
  memset(&gtp1_default, 0, sizeof(gtp1_default));
  gtp0_default.flags=0x1e;
  
  return 0;
}

int gtp_free(struct gsn_t *gsn) {

  /* Clean up retransmit queues */
  queue_free(gsn->queue_req);
  queue_free(gsn->queue_resp);

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
int gtp_echo_req(struct gsn_t *gsn, struct in_addr *inetaddr)
{
  union gtp_packet packet;

  get_default_gtp(0, &packet);
  packet.gtp0.h.type = hton8(GTP_ECHO_REQ);
  packet.gtp0.h.length = hton16(0);

  return gtp_req(gsn, 0, &packet, GTP0_HEADER_SIZE, inetaddr, NULL);
}

/* Send of an echo reply */
int gtp_echo_resp(struct gsn_t *gsn, struct sockaddr_in *peer,
		  void *pack, unsigned len)
{
  union gtp_packet packet;
  int length = 0;
  
  get_default_gtp(0, &packet);

  gtpie_tv1(packet.gtp0.p, &length, GTP_MAX, GTPIE_RECOVERY, 
	    gsn->restart_counter);
  
  packet.gtp0.h.type = hton8(GTP_ECHO_RSP);
  packet.gtp0.h.length = hton16(length);
  packet.gtp0.h.seq = ((union gtp_packet*)pack)->gtp0.h.seq;

  return gtp_resp(0, gsn, &packet, GTP0_HEADER_SIZE+length, peer);
}


/* Handle a received echo request */
int gtp_echo_ind(struct gsn_t *gsn, struct sockaddr_in *peer,
		 void *pack, unsigned len) {

  uint16_t seq = ntoh16(((union gtp_packet*)pack)->gtp0.h.seq);

  if(!gtp_dublicate(gsn, 0, peer, seq)) {
    return 0; /* We allready send of response once */
  }


  /* Now send off a reply to the peer */
  return gtp_echo_resp(gsn, peer, pack, len);
}

/* Handle a received echo reply */
int gtp_echo_conf(struct gsn_t *gsn, struct sockaddr_in *peer,
		  void *pack, unsigned len) {
  union gtpie_member *ie[GTPIE_SIZE];
  unsigned char recovery;
  void *aid = NULL;
  uint8_t type = 0;

  /* Remove packet from queue */
  if (gtp_conf(gsn, 0, peer, pack, len, &type, &aid)) return EOF;

  if (gtpie_decaps(ie, pack+sizeof(struct gtp0_header), len-sizeof(struct gtp0_header))) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    return EOF;
  }
  
  if (gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory field");
    return EOF;
  }

  if (gsn->cb_conf) gsn->cb_conf(type, 0, NULL, aid); /* TODO: Should return recovery in callback */

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

int gtp_unsup_resp(struct gsn_t *gsn, struct sockaddr_in *peer,
		   void *pack, unsigned len)
{
  union gtp_packet packet;
  int length = 0;

  get_default_gtp(0, &packet);
  packet.gtp0.h.type = hton8(GTP_NOT_SUPPORTED);
  packet.gtp0.h.length = hton16(0);
  
  return gtp_resp(0, gsn, &packet, GTP0_HEADER_SIZE+length, peer);
}

/* Handle a Version Not Supported message */
int gtp_unsup_conf(struct gsn_t *gsn, struct sockaddr_in *peer, void *pack, unsigned len) {

  /* TODO: Need to check the validity of header and information elements */
  /* TODO: Implement callback to application */
  /* As long as we only support GTP0 we should never receive this message */
  /* Should be implemented as part of GTP1 support */
  
  /* print received message */
  /*
  printf("gtp_unsup_ind: from %s:UDP%u\n",
	 inet_ntoa(peer->sin_addr),
	 ntohs(peer->sin_port));
  print_packet(pack, len);
  */
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

/* Send Create PDP Context Request */
extern int gtp_create_pdp_req(struct gsn_t *gsn, int version, void *aid,
			      struct in_addr* inetaddr, struct pdp_t *pdp) {
  union gtp_packet packet;
  int length = 0;

  get_default_gtp(0, &packet);
  
  if (0==0) { /* Always GTP0 */

    gtpie_tv0(packet.gtp0.p, &length, GTP_MAX, GTPIE_QOS_PROFILE0, 
	      sizeof(pdp->qos_req0), pdp->qos_req0);
    gtpie_tv1(packet.gtp0.p, &length, GTP_MAX, GTPIE_RECOVERY, 
	      gsn->restart_counter);
    gtpie_tv1(packet.gtp0.p, &length, GTP_MAX, GTPIE_SELECTION_MODE,
	      pdp->selmode);
    gtpie_tv2(packet.gtp0.p, &length, GTP_MAX, GTPIE_FL_DI, 
	      pdp->fllu);
    gtpie_tv2(packet.gtp0.p, &length, GTP_MAX, GTPIE_FL_C,
	      pdp->fllc);
    gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_EUA, 
	      pdp->eua.l, pdp->eua.v);
    gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_APN, 
	      pdp->apn_use.l, pdp->apn_use.v);

    if (pdp->pco_req.l) { /* Optional PCO */
      gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_PCO, 
		pdp->pco_req.l, pdp->pco_req.v);
    }

    gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	      pdp->gsnlc.l, pdp->gsnlc.v);
    gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	      pdp->gsnlu.l, pdp->gsnlu.v);
    gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_MSISDN,
	      pdp->msisdn.l, pdp->msisdn.v);
    


  } else { /* GTP1 */
    gtpie_tv0(packet.gtp1s.p, &length, GTP_MAX, GTPIE_IMSI, 
	      sizeof(pdp->imsi), (uint8_t*) &pdp->imsi);
    gtpie_tv1(packet.gtp1s.p, &length, GTP_MAX, GTPIE_RECOVERY, 
	      gsn->restart_counter);
    gtpie_tv1(packet.gtp1s.p, &length, GTP_MAX, GTPIE_SELECTION_MODE,
	      pdp->selmode);
    gtpie_tv4(packet.gtp1s.p, &length, GTP_MAX, GTPIE_TEI_DI, 
	      pdp->teid_own);
    gtpie_tv4(packet.gtp1s.p, &length, GTP_MAX, GTPIE_TEI_C,
	      pdp->teic_own);
    gtpie_tv1(packet.gtp1s.p, &length, GTP_MAX, GTPIE_NSAPI, 
	      pdp->nsapi);
    /*gtpie_tv1(packet.gtp1s.p, &length, GTP_MAX, GTPIE_NSAPI, 
      pdp->nsapil); For use by several QoS profiles for the same address */
    gtpie_tv2(packet.gtp1s.p, &length, GTP_MAX, GTPIE_CHARGING_C,
	      pdp->cch_pdp);
    gtpie_tv2(packet.gtp1s.p, &length, GTP_MAX, GTPIE_TRACE_REF,
	      pdp->traceref);
    gtpie_tv2(packet.gtp1s.p, &length, GTP_MAX, GTPIE_TRACE_TYPE,
	      pdp->tracetype);
    gtpie_tlv(packet.gtp1s.p, &length, GTP_MAX, GTPIE_EUA, 
	      pdp->eua.l, pdp->eua.v);
    gtpie_tlv(packet.gtp1s.p, &length, GTP_MAX, GTPIE_APN, 
	      pdp->apn_use.l, pdp->apn_use.v);
    gtpie_tlv(packet.gtp1s.p, &length, GTP_MAX, GTPIE_PCO, 
	      pdp->pco_req.l, pdp->pco_req.v);
    gtpie_tlv(packet.gtp1s.p, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	      pdp->gsnlc.l, pdp->gsnlc.v);
    gtpie_tlv(packet.gtp1s.p, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	      pdp->gsnlu.l, pdp->gsnlu.v);
    gtpie_tlv(packet.gtp1s.p, &length, GTP_MAX, GTPIE_MSISDN,
	      pdp->msisdn.l, pdp->msisdn.v);
    gtpie_tlv(packet.gtp1s.p, &length, GTP_MAX, GTPIE_QOS_PROFILE,
	      pdp->qos_req.l, pdp->qos_req.v);
    gtpie_tlv(packet.gtp1s.p, &length, GTP_MAX, GTPIE_TFT,
	      pdp->tft.l, pdp->tft.v);
    gtpie_tlv(packet.gtp1s.p, &length, GTP_MAX, GTPIE_TRIGGER_ID,
	      pdp->triggerid.l, pdp->triggerid.v);
    gtpie_tlv(packet.gtp1s.p, &length, GTP_MAX, GTPIE_OMC_ID,
	      pdp->omcid.l, pdp->omcid.v);
  }
  packet.gtp0.h.type = hton8(GTP_CREATE_PDP_REQ);
  packet.gtp0.h.length = hton16(length);
  packet.gtp0.h.flow = 0;
  packet.gtp0.h.tid = pdp->tid;

  gtp_req(gsn, 0, &packet, GTP0_HEADER_SIZE+length, inetaddr, aid);

  return 0;
}

/* Send Create PDP Context Response */
int gtp_create_pdp_resp(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, 
			void *pack, unsigned len, 
			struct pdp_t *pdp, uint8_t cause)
{
  union gtp_packet packet;
  int length = 0;

  get_default_gtp(0, &packet);

  gtpie_tv1(packet.gtp0.p, &length, GTP_MAX, GTPIE_CAUSE, cause);

  if (cause == GTPCAUSE_ACC_REQ) {
    gtpie_tv0(packet.gtp0.p, &length, GTP_MAX, GTPIE_QOS_PROFILE0, 
	      sizeof(pdp->qos_neg0), pdp->qos_neg0);
    gtpie_tv1(packet.gtp0.p, &length, GTP_MAX, GTPIE_REORDER,
	      pdp->reorder);
    gtpie_tv1(packet.gtp0.p, &length, GTP_MAX, GTPIE_RECOVERY, 
	      gsn->restart_counter);
    gtpie_tv2(packet.gtp0.p, &length, GTP_MAX, GTPIE_FL_DI, 
	      pdp->fllu);
    gtpie_tv2(packet.gtp0.p, &length, GTP_MAX, GTPIE_FL_C,
	      pdp->fllc);
    gtpie_tv4(packet.gtp0.p, &length, GTP_MAX, GTPIE_CHARGING_ID,
	      0x12345678);
    gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_EUA, 
	      pdp->eua.l, pdp->eua.v);

    if (pdp->pco_neg.l) { /* Optional PCO */
      gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_PCO,
		pdp->pco_neg.l, pdp->pco_neg.v);
    }

    gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	      pdp->gsnlc.l, pdp->gsnlc.v);
    gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	      pdp->gsnlu.l, pdp->gsnlu.v);
  }

  packet.gtp0.h.type = hton8(GTP_CREATE_PDP_RSP);
  packet.gtp0.h.length = hton16(length);
  packet.gtp0.h.flow = hton16(pdp->flrc);
  packet.gtp0.h.seq = ((union gtp_packet*)pack)->gtp0.h.seq;
  packet.gtp0.h.tid = ((union gtp_packet*)pack)->gtp0.h.tid;

  return gtp_resp(0, gsn, &packet, GTP0_HEADER_SIZE+length, peer);
}

/* Handle Create PDP Context Request */
int gtp_create_pdp_ind(struct gsn_t *gsn, int version,
		       struct sockaddr_in *peer, void *pack, unsigned len) {
  struct pdp_t *pdp, *pdp_old; 
  struct pdp_t pdp_buf;
  union gtpie_member* ie[GTPIE_SIZE];
  uint8_t recovery;
  uint64_t imsi;
  uint8_t nsapi;
  int auth = 0; /* Allow access if no callback is defined */

  uint16_t seq = ntoh16(((union gtp_packet*)pack)->gtp0.h.seq);

  if(!gtp_dublicate(gsn, 0, peer, seq)) {
    return 0; /* We allready send of response once */
  }

  /* Decode information elements */
  if (gtpie_decaps(ie, pack+GTP0_HEADER_SIZE, len-GTP0_HEADER_SIZE)) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    if (0 == version)
      return EOF;
    else
      return gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
				 GTPCAUSE_INVALID_MESSAGE);
  }

  pdp = &pdp_buf;
  memset(pdp, 0, sizeof(struct pdp_t));

  /* Extract IMSI and NSAPI from header */
  imsi = ((union gtp_packet*)pack)->gtp0.h.tid & 0x0fffffffffffffff;
  nsapi = (((union gtp_packet*)pack)->gtp0.h.tid & 0xf000000000000000) >> 60;

  /* pdp_newpdp(&pdp, imsi, nsapi); TODO: Need to remove again */

  if (gtpie_gettv0(ie, GTPIE_QOS_PROFILE0, 0,
		   pdp->qos_req0, sizeof(pdp->qos_req0))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  /* Extract recovery (optional) */
  if (!gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
    /* TODO: Handle received recovery IE */
  }

  if (gtpie_gettv0(ie, GTPIE_SELECTION_MODE, 0,
		   &pdp->selmode, sizeof(pdp->selmode))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  if (gtpie_gettv2(ie, GTPIE_FL_DI, 0, &pdp->flru)) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  if (gtpie_gettv2(ie, GTPIE_FL_C, 0, &pdp->flrc)) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  if (gtpie_gettlv(ie, GTPIE_EUA, 0, &pdp->eua.l,
		     &pdp->eua.v, sizeof(pdp->eua.v))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  if (gtpie_gettlv(ie, GTPIE_APN, 0, &pdp->apn_req.l,
		     &pdp->apn_req.v, sizeof(pdp->apn_req.v))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  /* Extract protocol configuration options (optional) */
  if (!gtpie_gettlv(ie, GTPIE_PCO, 0, &pdp->pco_req.l,
		    &pdp->pco_req.v, sizeof(pdp->pco_req.v))) {
    /* TODO: Handle PCO IE */
  }

  if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 0, &pdp->gsnrc.l,
		     &pdp->gsnrc.v, sizeof(pdp->gsnrc.v))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 1, &pdp->gsnru.l,
		     &pdp->gsnru.v, sizeof(pdp->gsnru.v))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  }
  
  if (gtpie_gettlv(ie, GTPIE_MSISDN, 0, &pdp->msisdn.l,
		   &pdp->msisdn.v, sizeof(pdp->msisdn.v))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  in_addr2gsna(&pdp->gsnlc, &gsn->gsnc);
  in_addr2gsna(&pdp->gsnlu, &gsn->gsnu);

  if (GTP_DEBUG) printf("gtp_create_pdp_ind: Before pdp_tidget\n");

  if (!pdp_tidget(&pdp_old, ((union gtp_packet*)pack)->gtp0.h.tid)) {
    /* Found old pdp with same tid. Now the voodoo begins! */
    /* We check that the APN, selection mode and MSISDN is the same */
    if (GTP_DEBUG) printf("gtp_create_pdp_ind: Old context found\n"); 
    if (   (pdp->apn_req.l == pdp_old->apn_req.l) 
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

      /* Copy peer GSN address */
      pdp_old->gsnrc.l = pdp->gsnrc.l;
      memcpy(&pdp_old->gsnrc.v, &pdp->gsnrc.v, pdp->gsnrc.l);
      pdp_old->gsnru.l = pdp->gsnru.l;
      memcpy(&pdp_old->gsnru.v, &pdp->gsnru.v, pdp->gsnru.l);
      
      /* pdp_freepdp(pdp); not nessasary anymore since never allocated */
      pdp = pdp_old;
      
      /* Confirm to peer that things were "successful" */
      return gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
				 GTPCAUSE_ACC_REQ);
    }
    else { /* This is not the same PDP context. Delete the old one. */

      if (GTP_DEBUG) printf("gtp_create_pdp_ind: Deleting old context\n");
      
      if (gsn->cb_delete_context) gsn->cb_delete_context(pdp_old);
      pdp_freepdp(pdp_old);

      if (GTP_DEBUG) printf("gtp_create_pdp_ind: Deleted...\n");      
    }
  }

  pdp_newpdp(&pdp, imsi, nsapi, pdp);

  /* Callback function to validata login */
  if (gsn->cb_create_context !=0) 
    auth = gsn->cb_create_context(pdp);

  /* Now send off a reply to the peer */
  if (!auth) {
    return gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
			       GTPCAUSE_ACC_REQ);
  }
  else {
    gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
			GTPCAUSE_USER_AUTH_FAIL);
    pdp_freepdp(pdp);
    return 0;
  }
}


/* Handle Create PDP Context Response */
int gtp_create_pdp_conf(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, 
			void *pack, unsigned len) {
  struct pdp_t *pdp; 
  union gtpie_member *ie[GTPIE_SIZE];
  uint8_t cause, recovery;
  void *aid = NULL;
  uint8_t type = 0;

  /* Remove packet from queue */
  if (gtp_conf(gsn, 0, peer, pack, len, &type, &aid)) return EOF;
  
  /* Find the context in question */
  if (pdp_getgtp0(&pdp, ntoh16(((union gtp_packet*)pack)->gtp0.h.flow))) {
    gsn->err_unknownpdp++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unknown PDP context");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, NULL, aid);
    return EOF;
  }

  /* Decode information elements */
  if (gtpie_decaps(ie, pack+GTP0_HEADER_SIZE, len-GTP0_HEADER_SIZE)) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, aid);
    return EOF;
  }

  /* Extract cause value (mandatory) */
  if (gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause)) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, aid);
    return EOF;
  }

  /* Extract recovery (optional) */
  if (!gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
    /* TODO: Handle received recovery IE */
  }

  /* Extract protocol configuration options (optional) */
  if (!gtpie_gettlv(ie, GTPIE_PCO, 0, &pdp->pco_req.l,
		    &pdp->pco_req.v, sizeof(pdp->pco_req.v))) {
    /* TODO: Handle PCO IE */
  }

  /* Check all conditional information elements */
  if (GTPCAUSE_ACC_REQ == cause) {

    if (gtpie_gettv0(ie, GTPIE_QOS_PROFILE0, 0,   /* TODO: HACK only gtp0 */
		     &pdp->qos_neg0, sizeof(pdp->qos_neg0))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, aid);
      return EOF;
    }
    /* pdp->qos_neg.l = 3;  * TODO: HACK only gtp0 */
    
    if (gtpie_gettv1(ie, GTPIE_REORDER, 0, &pdp->reorder)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, aid);
      return EOF;
    }

    if (gtpie_gettv2(ie, GTPIE_FL_DI, 0, &pdp->flru)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, aid);
      return EOF;
    }
    
    if (gtpie_gettv2(ie, GTPIE_FL_C, 0, &pdp->flrc)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, aid);
      return EOF;
    }
    
    if (gtpie_gettv4(ie, GTPIE_CHARGING_ID, 0, &pdp->cid)) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, aid);
      return gtp_create_pdp_resp(gsn, version, peer, pack, len, pdp, 
				 GTPCAUSE_MAN_IE_MISSING);
    }
    
    if (gtpie_gettlv(ie, GTPIE_EUA, 0, &pdp->eua.l,
		     &pdp->eua.v, sizeof(pdp->eua.v))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, aid);
      return EOF;
    }
    
    if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 0, &pdp->gsnrc.l,
		     &pdp->gsnrc.v, sizeof(pdp->gsnrc.v))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, aid);
      return EOF;
    }
    
    if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 1, &pdp->gsnru.l,
		     &pdp->gsnru.v, sizeof(pdp->gsnru.v))) {
      gsn->missing++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		  "Missing conditional information field");
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, aid);
      return EOF;
    }
  }

  if (gsn->cb_conf) gsn->cb_conf(type, cause, pdp, aid);

  return 0;
}

/* Send Update PDP Context Request */
extern int gtp_update_pdp_req(struct gsn_t *gsn, int version, void *aid,
			      struct in_addr* inetaddr, struct pdp_t *pdp) {
  union gtp_packet packet;
  int length = 0;

  get_default_gtp(0, &packet);
  
  gtpie_tv0(packet.gtp0.p, &length, GTP_MAX, GTPIE_QOS_PROFILE0, 
	    sizeof(pdp->qos_req0), pdp->qos_req0);
  gtpie_tv1(packet.gtp0.p, &length, GTP_MAX, GTPIE_RECOVERY, 
	    gsn->restart_counter);
  gtpie_tv2(packet.gtp0.p, &length, GTP_MAX, GTPIE_FL_DI, 
	    pdp->fllu);
  gtpie_tv2(packet.gtp0.p, &length, GTP_MAX, GTPIE_FL_C,
	    pdp->fllc);
  gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	    pdp->gsnlc.l, pdp->gsnlc.v);
  gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	    pdp->gsnlu.l, pdp->gsnlu.v);
  
  packet.gtp0.h.type = hton8(GTP_UPDATE_PDP_REQ);
  packet.gtp0.h.length = hton16(length);
  packet.gtp0.h.flow = 0;
  packet.gtp0.h.tid = (pdp->imsi & 0x0fffffffffffffff) + ((uint64_t)pdp->nsapi << 60);

  return gtp_req(gsn, 0, &packet, GTP0_HEADER_SIZE+length, inetaddr, aid);
}

/* Send Update PDP Context Response */
int gtp_update_pdp_resp(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, 
			void *pack, unsigned len, 
			struct pdp_t *pdp, uint8_t cause)
{
  union gtp_packet packet;
  int length = 0;

  get_default_gtp(0, &packet);

  gtpie_tv1(packet.gtp0.p, &length, GTP_MAX, GTPIE_CAUSE, cause);

  if (cause == GTPCAUSE_ACC_REQ) {
    gtpie_tv0(packet.gtp0.p, &length, GTP_MAX, GTPIE_QOS_PROFILE0, 
	      sizeof(pdp->qos_sub0), pdp->qos_sub0);
    gtpie_tv1(packet.gtp0.p, &length, GTP_MAX, GTPIE_RECOVERY, 
	      gsn->restart_counter);
    gtpie_tv2(packet.gtp0.p, &length, GTP_MAX, GTPIE_FL_DI, 
	      pdp->fllu);
    gtpie_tv2(packet.gtp0.p, &length, GTP_MAX, GTPIE_FL_C,
	      pdp->fllc);
    gtpie_tv4(packet.gtp0.p, &length, GTP_MAX, GTPIE_CHARGING_ID,
	      0x12345678);
    gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	      pdp->gsnlc.l, pdp->gsnlc.v);
    gtpie_tlv(packet.gtp0.p, &length, GTP_MAX, GTPIE_GSN_ADDR, 
	      pdp->gsnlu.l, pdp->gsnlu.v);
  }

  packet.gtp0.h.type = hton8(GTP_UPDATE_PDP_RSP);
  packet.gtp0.h.length = hton16(length);
  packet.gtp0.h.flow = hton16(pdp->flrc);
  packet.gtp0.h.seq = ((union gtp_packet*)pack)->gtp0.h.seq;
  packet.gtp0.h.tid = (pdp->imsi & 0x0fffffffffffffff) + ((uint64_t)pdp->nsapi << 60);

  return gtp_resp(0, gsn, &packet, GTP0_HEADER_SIZE+length, peer);
}

/* Handle Update PDP Context Request */
int gtp_update_pdp_ind(struct gsn_t *gsn, int version,
		       struct sockaddr_in *peer, void *pack, unsigned len) {
  struct pdp_t *pdp, *pdp2; 
  struct pdp_t pdp_buf;
  union gtpie_member* ie[GTPIE_SIZE];
  uint8_t recovery;

  uint16_t seq = ntoh16(((union gtp_packet*)pack)->gtp0.h.seq);

  /* Is this a dublicate ? */
  if(!gtp_dublicate(gsn, 0, peer, seq)) {
    return 0; /* We allready send of response once */
  }

  /* Find the pdp context in question */
  if (pdp_getgtp0(&pdp, ntoh16(((union gtp_packet*)pack)->gtp0.h.flow))) {
    gsn->err_unknownpdp++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unknown PDP context");
    return gtp_update_pdp_resp(gsn, version, peer, pack, len, NULL,
			       GTPCAUSE_NON_EXIST);
  }
  
  /* Decode information elements */
  if (gtpie_decaps(ie, pack+GTP0_HEADER_SIZE, len-GTP0_HEADER_SIZE)) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    if (0 == version)
      return EOF;
    else
      return gtp_update_pdp_resp(gsn, version, peer, pack, len, pdp, 
				 GTPCAUSE_INVALID_MESSAGE);
  }

  pdp2 = &pdp_buf;
  memcpy(pdp2, pdp, sizeof (struct pdp_t)); /* Generate local copy */

  if (gtpie_gettv0(ie, GTPIE_QOS_PROFILE0, 0,   /* TODO: HACK only gtp0 */
		     &pdp2->qos_req0, sizeof(pdp2->qos_req0))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_update_pdp_resp(gsn, version, peer, pack, len, pdp2,
			       GTPCAUSE_MAN_IE_MISSING);
  }
  /* pdp2->qos_req.l = 3;  * TODO: HACK only gtp0 */

  /* Extract recovery (optional) */
  if (!gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
    /* TODO: Handle received recovery IE */
  }

  if (gtpie_gettv2(ie, GTPIE_FL_DI, 0, &pdp2->flru)) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_update_pdp_resp(gsn, version, peer, pack, len, pdp2, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  if (gtpie_gettv2(ie, GTPIE_FL_C, 0, &pdp2->flrc)) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_update_pdp_resp(gsn, version, peer, pack, len, pdp2, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 0, &pdp2->gsnrc.l,
		     &pdp2->gsnrc.v, sizeof(pdp2->gsnrc.v))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_update_pdp_resp(gsn, version, peer, pack, len, pdp2, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  if (gtpie_gettlv(ie, GTPIE_GSN_ADDR, 1, &pdp2->gsnru.l,
		     &pdp2->gsnru.v, sizeof(pdp2->gsnru.v))) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return gtp_update_pdp_resp(gsn, version, peer, pack, len, pdp2, 
			       GTPCAUSE_MAN_IE_MISSING);
  }

  /* OK! It seames as if we received a valid message */

  memcpy(pdp, pdp2, sizeof (struct pdp_t)); /* Update original pdp */

  /* Confirm to peer that things were "successful" */
  return gtp_update_pdp_resp(gsn, version, peer, pack, len, pdp, 
			     GTPCAUSE_ACC_REQ);
}


/* Handle Update PDP Context Response */
int gtp_update_pdp_conf(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, 
			void *pack, unsigned len) {
  struct pdp_t *pdp; 
  union gtpie_member *ie[GTPIE_SIZE];
  uint8_t cause, recovery;
  void *aid = NULL;
  uint8_t type = 0;
  
  /* Remove packet from queue */
  if (gtp_conf(gsn, 0, peer, pack, len, &type, &aid)) return EOF;

  /* Find the context in question */
  if (pdp_getgtp0(&pdp, ntoh16(((union gtp_packet*)pack)->gtp0.h.flow))) {
    gsn->err_unknownpdp++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unknown PDP context");
    if (gsn->cb_conf) gsn->cb_conf(type, cause, NULL, aid);
    return EOF;
  }

  /* Decode information elements */
  if (gtpie_decaps(ie, pack+GTP0_HEADER_SIZE, len-GTP0_HEADER_SIZE)) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, aid);
    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
    pdp_freepdp(pdp);
    return EOF;
  }
      
  /* Extract cause value (mandatory) */
  if (gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause)) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, aid);
    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
    pdp_freepdp(pdp);
    return EOF;
  }

  /* Extract recovery (optional) */
  if (!gtpie_gettv1(ie, GTPIE_RECOVERY, 0, &recovery)) {
    /* TODO: Handle received recovery IE */
  }

  /* Check all conditional information elements */
  if (GTPCAUSE_ACC_REQ != cause) {
    if (gsn->cb_conf) gsn->cb_conf(type, cause, pdp, aid);
    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
    pdp_freepdp(pdp);
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
      if (gsn->cb_conf) gsn->cb_conf(type, EOF, pdp, aid);
      if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
      pdp_freepdp(pdp);
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
    
    if (gsn->cb_conf) gsn->cb_conf(type, cause, pdp, aid);
    return 0; /* Succes */
  }
}

/* Send Delete PDP Context Request */
extern int gtp_delete_pdp_req(struct gsn_t *gsn, int version, void *aid,
			      struct pdp_t *pdp) {
  union gtp_packet packet;
  int length = 0;
  struct in_addr addr;

  if (gsna2in_addr(&addr, &pdp->gsnrc)) {
    gsn->err_address++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "GSN address conversion failed");
    return EOF;
  }

  get_default_gtp(0, &packet);

  packet.gtp0.h.type = hton8(GTP_DELETE_PDP_REQ);
  packet.gtp0.h.length = hton16(length);
  packet.gtp0.h.flow = hton16(pdp->flrc);
  packet.gtp0.h.tid = (pdp->imsi & 0x0fffffffffffffff) + ((uint64_t)pdp->nsapi << 60);

  return gtp_req(gsn, 0, &packet, GTP0_HEADER_SIZE+length, &addr, aid);
}

/* Send Delete PDP Context Response */
int gtp_delete_pdp_resp(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, 
			void *pack, unsigned len, 
			struct pdp_t *pdp, uint8_t cause)
{
  union gtp_packet packet;
  int length = 0;
  uint16_t flow = 0;
  
  if (pdp) flow = hton16(pdp->flrc);
  
  get_default_gtp(0, &packet);

  gtpie_tv1(packet.gtp0.p, &length, GTP_MAX, GTPIE_CAUSE, cause);

  packet.gtp0.h.type = hton8(GTP_DELETE_PDP_RSP);
  packet.gtp0.h.length = hton16(length);
  packet.gtp0.h.flow = flow;
  packet.gtp0.h.seq = ((union gtp_packet*)pack)->gtp0.h.seq;
  packet.gtp0.h.tid = ((union gtp_packet*)pack)->gtp0.h.tid;

  if (pdp) {
    /* Callback function to allow application to clean up */
    if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
    pdp_freepdp(pdp); /* Clean up PDP context */
  }
  
  return gtp_resp(0, gsn, &packet, GTP0_HEADER_SIZE+length, peer);
}

/* Handle Delete PDP Context Request */
int gtp_delete_pdp_ind(struct gsn_t *gsn, int version,
		       struct sockaddr_in *peer, void *pack, unsigned len) {
  struct pdp_t *pdp; 
  union gtpie_member* ie[GTPIE_SIZE];
  uint16_t seq = ntoh16(((union gtp_packet*)pack)->gtp0.h.seq);

  /* Is this a dublicate ? */
  if(!gtp_dublicate(gsn, 0, peer, seq)) {
    return 0;
  }

  /* Find the pdp context in question */
  if (pdp_getgtp0(&pdp, ntoh16(((union gtp_packet*)pack)->gtp0.h.flow))) {
    gsn->err_unknownpdp++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unknown PDP context");
    if (0 == version)
      return gtp_delete_pdp_resp(gsn, version, peer, pack, len, NULL,
				 GTPCAUSE_ACC_REQ);
    else
      return gtp_delete_pdp_resp(gsn, version, peer, pack, len, NULL,
				 GTPCAUSE_NON_EXIST);
  }
  
  /* Decode information elements */
  if (gtpie_decaps(ie, pack+GTP0_HEADER_SIZE, len-GTP0_HEADER_SIZE)) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    if (0 == version)
      return EOF;
    else
      return gtp_delete_pdp_resp(gsn, version, peer, pack, len, pdp, 
				 GTPCAUSE_INVALID_MESSAGE);
  }

  return gtp_delete_pdp_resp(gsn, version, peer, pack, len, pdp,
			     GTPCAUSE_ACC_REQ);
}


/* Handle Delete PDP Context Response */
int gtp_delete_pdp_conf(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, 
			void *pack, unsigned len) {
  struct pdp_t *pdp; 
  union gtpie_member *ie[GTPIE_SIZE];
  uint8_t cause;
  void *aid = NULL;
  uint8_t type = 0;

  /* Remove packet from queue */
  if (gtp_conf(gsn, 0, peer, pack, len, &type, &aid)) return EOF;
  
  /* Find the context in question */
  if (pdp_getgtp0(&pdp, ntoh16(((union gtp_packet*)pack)->gtp0.h.flow))) {
    gsn->err_unknownpdp++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unknown PDP context");
    return EOF;
  }

  /* Decode information elements */
  if (gtpie_decaps(ie, pack+GTP0_HEADER_SIZE, len-GTP0_HEADER_SIZE)) {
    gsn->invalid++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Invalid message format");
    return EOF;
  }

  /* Extract cause value */
  if (gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause)) {
    gsn->missing++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Missing mandatory information field");
    return EOF;
  }

  /* Check the cause value */
  if ((GTPCAUSE_ACC_REQ != cause) &&  (GTPCAUSE_NON_EXIST != cause)) {
    gsn->err_cause++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unexpected cause value received: %d", cause);
    return EOF;
  }

  /* Callback function to allow application to clean up */
  if (gsn->cb_conf) gsn->cb_conf(type, cause, pdp, aid);

  if (gsn->cb_delete_context) gsn->cb_delete_context(pdp);
  pdp_freepdp(pdp);  
  
  return 0;
}

/* Send Error Indication (response to a GPDU message */
int gtp_error_ind_resp(struct gsn_t *gsn, int version,
		       struct sockaddr_in *peer, 
		       void *pack, unsigned len)
{
  union gtp_packet packet;
  int length = 0;
  
  get_default_gtp(0, &packet);
  
  packet.gtp0.h.type = hton8(GTP_ERROR);
  packet.gtp0.h.length = hton16(length);
  packet.gtp0.h.flow = 0;
  packet.gtp0.h.seq = ((union gtp_packet*)pack)->gtp0.h.seq;
  packet.gtp0.h.tid = ((union gtp_packet*)pack)->gtp0.h.tid;
  
  return gtp_resp(0, gsn, &packet, GTP0_HEADER_SIZE+length, peer);
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
		 struct sockaddr_in *peer,
		 void *pack,
		 unsigned len) {

  /* Need to include code to verify packet src and dest addresses */
  struct pdp_t *pdp; 
  
  if (pdp_getgtp0(&pdp, ntoh16(((union gtp_packet*)pack)->gtp0.h.flow))) {
    gsn->err_unknownpdp++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, peer, pack, len,
		"Unknown PDP context");
    return gtp_error_ind_resp(gsn, version, peer, pack, len);
 
  }
  
  /* Callback function */
  if (gsn->cb_gpdu !=0)
    return gsn->cb_gpdu(pdp, pack+20, len-20); /* TODO ???? */

  return 0;
}


/* Receives GTP packet and sends off for further processing 
 * Function will check the validity of the header. If the header
 * is not valid the packet is either dropped or a version not 
 * supported is returned to the peer. 
 * TODO: Need to decide on return values! */
int gtp_decaps(struct gsn_t *gsn)
{
  unsigned char buffer[PACKET_MAX + 64 /*TODO: ip header */ ];
  int status, ip_len = 0;
  struct sockaddr_in peer;
  int peerlen;
  struct gtp0_header *pheader;
  int version = 0; /* GTP version should be determined from header!*/

  peerlen = sizeof(peer);
  if ((status = 
       recvfrom(gsn->fd, buffer, sizeof(buffer), 0,
		(struct sockaddr *) &peer, &peerlen)) < 0 ) {
    gsn->err_readfrom++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "recvfrom(fd=%d, buffer=%lx, len=%d) failed: status = %d error = %s", gsn->fd, (unsigned long) buffer, sizeof(buffer), status, status ? strerror(errno) : "No error");
    return -1;
  }
  
  /* Strip off IP header, if present: TODO Is this nessesary? */
  if ((buffer[0] & 0xF0) == 0x40) {
    ip_len = (buffer[0] & 0xF) * 4;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		"IP header found in return from read");
    return -1;
  }
  
  /* Need at least 1 byte in order to check version */
  if (status < (1)) {
    gsn->empty++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		"Discarding packet - too small");
    return -1;
  }
  
  /* TODO: Remove these ERROR MESSAGES 
  gtp_err(LOG_ERR, __FILE__, __LINE__, "Discarding packet - too small");
  gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
	      "Discarding packet - too small"); */

  pheader = (struct gtp0_header *) (buffer + ip_len);

  /* Version should be gtp0 (or earlier in theory) */
  if (((pheader->flags & 0xe0) > 0x00)) {
    gsn->unsup++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		"Unsupported GTP version");
    return gtp_unsup_resp(gsn, &peer, buffer, status); /* 29.60: 11.1.1 */
  }
  
  /* Check length of gtp0 packet */
  if (((pheader->flags & 0xe0) == 0x00) && (status < GTP0_HEADER_SIZE)) {
    gsn->tooshort++;
    gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		"GTP0 packet too short");
    return -1; /* Silently discard 29.60: 11.1.2 */
  }

  switch (pheader->type) {
  case GTP_ECHO_REQ:
    return gtp_echo_ind(gsn, &peer, buffer+ip_len, status - ip_len);
  case GTP_ECHO_RSP:
    return gtp_echo_conf(gsn, &peer, buffer+ip_len, status - ip_len);
  case GTP_NOT_SUPPORTED:
    return gtp_unsup_conf(gsn, &peer, buffer+ip_len, status - ip_len);
  case GTP_CREATE_PDP_REQ:
    return gtp_create_pdp_ind(gsn, version, &peer, buffer+ip_len, 
			      status - ip_len);
  case GTP_CREATE_PDP_RSP:
    return gtp_create_pdp_conf(gsn, version, &peer, buffer+ip_len, 
			       status - ip_len);
  case GTP_UPDATE_PDP_REQ:
    return gtp_update_pdp_ind(gsn, version, &peer, buffer+ip_len, 
			      status - ip_len);
  case GTP_UPDATE_PDP_RSP:
    return gtp_update_pdp_conf(gsn, version, &peer, buffer+ip_len, 
			       status - ip_len);
  case GTP_DELETE_PDP_REQ:
    return gtp_delete_pdp_ind(gsn, version, &peer, buffer+ip_len, 
			      status - ip_len);
  case GTP_DELETE_PDP_RSP:
    return gtp_delete_pdp_conf(gsn, version, &peer, buffer+ip_len, 
			       status - ip_len);
  case GTP_ERROR:
    return gtp_error_ind_conf(gsn, version, &peer, buffer+ip_len, 
			      status - ip_len);
  case GTP_GPDU:
    return gtp_gpdu_ind(gsn, version, &peer, buffer+ip_len, status - ip_len);
  default:
    {
      gsn->unknown++;
      gtp_errpack(LOG_ERR, __FILE__, __LINE__, &peer, buffer, status,
		  "Unknown GTP message type received");
      return -1;
    }
  }
}

int gtp_gpdu(struct gsn_t *gsn, struct pdp_t* pdp, 
	     void *pack, unsigned len)
{
  union gtp_packet packet;
  struct sockaddr_in addr;

  /*printf("gtp_encaps start\n");
    print_packet(pack, len);*/

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;

  memcpy(&addr.sin_addr, pdp->gsnru.v,pdp->gsnru.l); /* TODO range check */
  addr.sin_port = htons(GTP0_PORT);

  get_default_gtp(0, &packet);
  packet.gtp0.h.type = hton8(GTP_GPDU);
  packet.gtp0.h.length = hton16(len);
  packet.gtp0.h.seq = hton16(pdp->gtpsntx++);
  packet.gtp0.h.flow = hton16(pdp->flru);
  packet.gtp0.h.tid = (pdp->imsi & 0x0fffffffffffffff) + ((uint64_t)pdp->nsapi << 60);

  if (len > sizeof (union gtp_packet) - sizeof(struct gtp0_header)) {
    gsn->err_memcpy++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, 
	    "Memcpy failed");
    return EOF;
    }

  memcpy(packet.gtp0.p, pack, len); /* TODO Should be avoided! */
  
  if (sendto(gsn->fd, &packet, GTP0_HEADER_SIZE+len, 0,
	     (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    gsn->err_sendto++;
    gtp_err(LOG_ERR, __FILE__, __LINE__, "Sendto(fd=%d, msg=%lx, len=%d) failed: Error = %s", gsn->fd, (unsigned long) &packet, GTP0_HEADER_SIZE+len, strerror(errno));
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

