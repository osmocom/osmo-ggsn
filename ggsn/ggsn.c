/* 
 * OpenGGSN - Gateway GPRS Support Node
 * Copyright (C) 2002, 2003 Mondru AB.
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

/* ggsn.c
 *
 */

#ifdef __linux__
#define _GNU_SOURCE 1		/* strdup() prototype, broken arpa/inet.h */
#endif


#include <syslog.h>
#include <ctype.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/socket.h>  
#include <sys/ioctl.h>
#include <net/if.h>
#include <features.h>

#include <errno.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h> 

#include <time.h>

#include "tun.h"
#include "ippool.h"
#include "syserr.h"
#include "../gtp/pdp.h"
#include "../gtp/gtp.h"
#include "cmdline.h"


int maxfd = 0;	                /* For select()            */
struct tun_t *tun;              /* TUN instance            */

struct in_addr listen_;
struct in_addr net, mask;       /* Network interface       */
struct in_addr dns1, dns2;      /* PCO DNS address         */
char *ipup, *ipdown;            /* Filename of scripts     */
int debug;                      /* Print debug output      */
struct ul255_t pco;
struct ul255_t qos;
struct ul255_t apn;

struct tun_t *tun;              /* TUN instance            */
struct ippool_t *ippool;        /* Pool of IP addresses    */
struct gsn_t *gsn;              /* GSN instance            */



/* Used to write process ID to file. Assume someone else will delete */
void log_pid(char *pidfile) {
  FILE *file;
  mode_t oldmask;
  
  oldmask = umask(022);
  file = fopen(pidfile, "w");
  umask(oldmask);
  if(!file)
    return;
  fprintf(file, "%d\n", getpid());
  fclose(file);
}


int encaps_printf(void *p, void *packet, unsigned len)
{
  int i;
  if (debug) {
    printf("The packet looks like this:\n");
    for( i=0; i<len; i++) {
      printf("%02x ", (unsigned char)*(char *)(packet+i));
      if (!((i+1)%16)) printf("\n");
    };
    printf("\n"); 
  }
  return 0;
}

int delete_context(struct pdp_t *pdp) {
  if (debug) printf("Deleting PDP context\n");
  ippool_freeip((struct ippoolm_t *) pdp->peer);
  return 0;
}


int create_context(struct pdp_t *pdp) {
  struct in_addr addr;
  struct ippoolm_t *member;

  if (debug) printf("Received create PDP context request\n");

  pdp->eua.l=0; /* TODO: Indicates dynamic IP */

  /* ulcpy(&pdp->qos_neg, &pdp->qos_req, sizeof(pdp->qos_req.v)); */
  memcpy(pdp->qos_neg0, pdp->qos_req0, sizeof(pdp->qos_neg));
  memcpy(&pdp->pco_neg, &pco, sizeof(pdp->pco_neg));

  if (pdp_euaton(&pdp->eua, &addr)) {
    addr.s_addr = 0; /* Request dynamic */
  }

  if (ippool_newip(ippool, &member, &addr)) {
    return EOF; /* Allready in use, or no more available */
  }

  pdp_ntoeua(&member->addr, &pdp->eua);
  pdp->peer = &member;
  pdp->ipif = tun; /* TODO */
  member->peer = pdp;

  return 0; /* Success */
}


/* Callback for receiving messages from tun */
int cb_tun_ind(struct tun_t *tun, void *pack, unsigned len) {
  struct ippoolm_t *ipm;
  struct in_addr dst;
  struct tun_packet_t *iph = (struct tun_packet_t*) pack;
  
  dst.s_addr = iph->dst;
  
  if (ippool_getip(ippool, &ipm, &dst)) {
    if (debug) printf("Received packet with no destination!!!\n");
    return 0;
  }
  
  if (ipm->peer) /* Check if a peer protocol is defined */
    gtp_gpdu(gsn, (struct pdp_t*) ipm->peer, pack, len);
  return 0;
}

int encaps_tun(struct pdp_t *pdp, void *pack, unsigned len) {
  /*  printf("encaps_tun. Packet received: forwarding to tun\n");*/
  return tun_encaps((struct tun_t*) pdp->ipif, pack, len);
}


int main(int argc, char **argv)
{
  /* gengeopt declarations */
  struct gengetopt_args_info args_info;

  struct hostent *host;

	
  fd_set fds;			/* For select() */
  struct timeval idleTime;	/* How long to select() */


  int timelimit; /* Number of seconds to be connected */
  int starttime; /* Time program was started */

  /* open a connection to the syslog daemon */
  /*openlog(PACKAGE, LOG_PID, LOG_DAEMON);*/
  openlog(PACKAGE, (LOG_PID | LOG_PERROR), LOG_DAEMON);

  if (cmdline_parser (argc, argv, &args_info) != 0)
    exit(1);
  if (args_info.debug_flag) {
    printf("listen: %s\n", args_info.listen_arg);
    printf("conf: %s\n", args_info.conf_arg);
    printf("fg: %d\n", args_info.fg_flag);
    printf("debug: %d\n", args_info.debug_flag);
    printf("qos: %#08x\n", args_info.qos_arg);
    printf("apn: %s\n", args_info.apn_arg);
    printf("net: %s\n", args_info.net_arg);
    printf("dynip: %s\n", args_info.dynip_arg);
    printf("statip: %s\n", args_info.statip_arg);
    printf("ipup: %s\n", args_info.ipup_arg);
    printf("ipdown: %s\n", args_info.ipdown_arg);
    printf("pidfile: %s\n", args_info.pidfile_arg);
    printf("statedir: %s\n", args_info.statedir_arg);
    printf("timelimit: %d\n", args_info.timelimit_arg);
  }

  /* Try out our new parser */
  
  if (cmdline_parser_configfile (args_info.conf_arg, &args_info, 0) != 0)
    exit(1);
  if (args_info.debug_flag) {
    printf("cmdline_parser_configfile\n");
    printf("listen: %s\n", args_info.listen_arg);
    printf("conf: %s\n", args_info.conf_arg);
    printf("fg: %d\n", args_info.fg_flag);
    printf("debug: %d\n", args_info.debug_flag);
    printf("qos: %#08x\n", args_info.qos_arg);
    printf("apn: %s\n", args_info.apn_arg);
    printf("net: %s\n", args_info.net_arg);
    printf("dynip: %s\n", args_info.dynip_arg);
    printf("statip: %s\n", args_info.statip_arg);
    printf("ipup: %s\n", args_info.ipup_arg);
    printf("ipdown: %s\n", args_info.ipdown_arg);
    printf("pidfile: %s\n", args_info.pidfile_arg);
    printf("statedir: %s\n", args_info.statedir_arg);
    printf("timelimit: %d\n", args_info.timelimit_arg);
  }

  /* Handle each option */

  /* foreground                                                   */
  /* If flag not given run as a daemon                            */
  if (!args_info.fg_flag)
    {
      closelog(); 
      /* Close the standard file descriptors. */
      /* Is this really needed ? */
      freopen("/dev/null", "w", stdout);
      freopen("/dev/null", "w", stderr);
      freopen("/dev/null", "r", stdin);
      daemon(0, 0);
      /* Open log again. This time with new pid */
      openlog(PACKAGE, LOG_PID, LOG_DAEMON);
    }

  /* debug                                                        */
  debug = args_info.debug_flag;

  /* pidfile */
  /* This has to be done after we have our final pid */
  if (args_info.pidfile_arg) {
    log_pid(args_info.pidfile_arg);
  }

  /* listen                                                       */
  /* If no listen option is specified listen to any local port    */
  /* Do hostname lookup to translate hostname to IP address       */
  if (args_info.listen_arg) {
    if (!(host = gethostbyname(args_info.listen_arg))) {
      fprintf(stderr, "%s: Invalid listening address: %s!\n", 
	      PACKAGE, args_info.listen_arg);
      syslog(LOG_ERR, "Invalid listening address: %s!", 
	     args_info.listen_arg);
      return 1;
    }
    else {
      memcpy(&listen_.s_addr, host->h_addr, host->h_length);
    }
  }
  else {
    listen_.s_addr = htonl(INADDR_ANY);
  }
  
  /* net                                                          */
  /* Store net as in_addr net and mask                            */
  if (args_info.net_arg) {
    if(ippool_aton(&net, &mask, args_info.net_arg, 0)) {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
	      "Invalid network address: %s!", args_info.net_arg);
      return -1;
    }
  }

  /* dynip                                                        */
  if (!args_info.dynip_arg) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
	    "No dynamic address pool given!");
    return -1;
  }
  else {
    if (ippool_new(&ippool, args_info.dynip_arg, 
		   IPPOOL_NONETWORK | IPPOOL_NOBROADCAST)) {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
	      "Failed to allocate IP pool!");
    }
  }

  /* DNS1 and DNS2 */
  dns1.s_addr = 0;
  if (args_info.pcodns1_arg)
    inet_aton(args_info.pcodns1_arg, &dns1);

  dns2.s_addr = 0;
  if (args_info.pcodns2_arg)
    inet_aton(args_info.pcodns2_arg, &dns2);

  pco.l = 20;
  pco.v[0] = 0x80; /* x0000yyy x=1, yyy=000: PPP */
  pco.v[1] = 0x80; /* IPCP */
  pco.v[2] = 0x21; 
  pco.v[3] = 0x10; /* Length of contents */
  pco.v[4] = 0x02; /* ACK */
  pco.v[5] = 0x00; /* ID: Need to match request */
  pco.v[6] = 0x00; /* Length */
  pco.v[7] = 0x10;
  pco.v[8] = 0x81; /* DNS 1 */
  pco.v[9] = 0x06;
  memcpy(&pco.v[10], &dns1, sizeof(dns1));
  pco.v[14] = 0x83;
  pco.v[15] = 0x06; /* DNS 2 */
  memcpy(&pco.v[16], &dns2, sizeof(dns2));

  /* ipup */
  ipup = args_info.ipup_arg;

  /* ipdown */
  ipdown = args_info.ipdown_arg;

  /* Timelimit                                                       */
  timelimit = args_info.timelimit_arg;
  starttime = time(NULL);
  
  /* qos                                                             */
  qos.l = 3;
  qos.v[2] = (args_info.qos_arg) & 0xff;
  qos.v[1] = ((args_info.qos_arg) >> 8) & 0xff;
  qos.v[0] = ((args_info.qos_arg) >> 16) & 0xff;

  /* apn                                                             */
  if (strlen(args_info.apn_arg) > (sizeof(apn.v)-1)) {
    printf("Invalid APN\n");
    return -1;
  }
  apn.l = strlen(args_info.apn_arg) + 1;
  apn.v[0] = (char) strlen(args_info.apn_arg);
  strncpy(&apn.v[1], args_info.apn_arg, sizeof(apn.v)-1);
  
  

  if (debug) printf("gtpclient: Initialising GTP tunnel\n");
  
  if (gtp_new(&gsn, args_info.statedir_arg,  &listen_)) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
	    "Failed to create gtp");
    exit(1);
  }
  if (gsn->fd > maxfd) maxfd = gsn->fd;
    

  gtp_set_cb_gpdu(gsn, encaps_tun);
  gtp_set_cb_delete_context(gsn, delete_context);
  gtp_set_cb_create_context(gsn, create_context);


  /* Create a tunnel interface */
  if (tun_new((struct tun_t**) &tun)) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
	    "Failed to create tun");
    exit(1);
  }

  tun_setaddr(tun, &net,  &net, &mask);
  tun_set_cb_ind(tun, cb_tun_ind);
  if (tun->fd > maxfd) maxfd = tun->fd;

  if (ipup) {
    char buf[1024];
    char snet[100];
    char smask[100];

    strncpy(snet, inet_ntoa(net), sizeof(snet));
    snet[sizeof(snet)-1] = 0;
    strncpy(smask, inet_ntoa(mask), sizeof(smask));
    smask[sizeof(smask)-1] = 0;
    
    /* system("ipup /dev/tun0 192.168.0.10"); */
    snprintf(buf, sizeof(buf), "%s %s %s %s",
	     ipup, tun->devname, snet, smask);
    buf[sizeof(buf)-1] = 0;
    if (debug) printf("%s\n", buf);
    system(buf);
  }

  /******************************************************************/
  /* Main select loop                                               */
  /******************************************************************/

  while (((starttime + timelimit) > time(NULL)) || (0 == timelimit)) {
	
    FD_ZERO(&fds);
    if (tun) FD_SET(tun->fd, &fds);
    FD_SET(gsn->fd, &fds);
    
    gtp_retranstimeout(gsn, &idleTime);
    switch (select(maxfd + 1, &fds, NULL, NULL, &idleTime)) {
    case -1:	/* Error with select() *
		   if (errno != EINTR)
		   syslog(LOG_ERR, "CTRL: Error with select(), quitting");
		   *goto leave_clear_call;*/
      syslog(LOG_ERR, "GGSN: select = -1");
      break;  
    case 0:
      /* printf("Select returned 0\n"); */
      gtp_retrans(gsn); /* Only retransmit if nothing else */
      break; 
    default:
      break;
    }

    if (tun->fd != -1 && FD_ISSET(tun->fd, &fds) && 
	tun_decaps(tun) < 0) {
      syslog(LOG_ERR, "TUN read failed (fd)=(%d)", tun->fd);
    }

    if (FD_ISSET(gsn->fd, &fds))
      gtp_decaps(gsn);
    
  }

  gtp_free(gsn);
  tun_free(tun);
  
  return 1;
  
}

