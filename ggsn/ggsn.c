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
#include "../gtp/pdp.h"
#include "../gtp/gtp.h"
#include "cmdline.h"


int maxfd = 0;	                /* For select() */
int tun_fd = -1;		/* Network file descriptor */
struct tun_t *tun;              /* TUN instance            */
struct in_addr net, mask;       /* Network interface       */
char *ipup, *ipdown;            /* Filename of scripts */
int debug;                      /* Print debug output */


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

int getip(struct pdp_t *pdp, void* ipif, struct ul66_t *eua,
	  struct in_addr *net, struct in_addr *mask) {
  struct in_addr addr;
  uint32_t ip_start, ip_end, ip_cur;
  struct pdp_t *pdp_;
  struct ul66_t eua_;

  if (debug) {
  printf("Begin getip %d %d %2x%2x%2x%2x\n", (unsigned)ipif, eua->l, 
	 eua->v[2],eua->v[3],eua->v[4],eua->v[5]);
  }

  ip_start = ntoh32(net->s_addr & mask->s_addr);
  ip_end   = ntoh32(hton32(ip_start) | ~mask->s_addr);

  /* By convention the first address is the network address, and the last */
  /* address is the broadcast address. This way two IP addresses are "lost" */
  ip_start++; 
  
  if (eua->l == 0) { /* No address supplied. Find one that is available! */
    /* This routine does linear search. In order to support millions of 
     * addresses we should instead keep a linked list of available adresses */
    for (ip_cur = ip_start; ip_cur < ip_end; ip_cur++) {
      addr.s_addr = hton32(ip_cur);
      pdp_ntoeua(&addr, &eua_);
      if (pdp_ipget(&pdp_, ipif, &eua_) == -1) {
	pdp_ntoeua(&addr, &pdp->eua);
	pdp->ipif = ipif;
	return 0;
      };
    }
    return EOF; /* No addresses available */
  }
  else { /* Address supplied */
    if (pdp_ipget(&pdp_, ipif, eua) == -1) {
      pdp->ipif = ipif;
      pdp->eua.l = eua->l;
      memcpy(pdp->eua.v, eua->v, eua->l);
      return 0;
    }
    else return EOF; /* Specified address not available */
  }
}


int delete_context(struct pdp_t *pdp) {
  if (debug) printf("Deleting PDP context\n");
  pdp_ipdel(pdp);
  return 0;
}



int create_context(struct pdp_t *pdp) {

  if (debug) printf("Received create PDP context request\n");

  pdp->eua.l=0; /* TODO: Indicates dynamic IP */

  /* ulcpy(&pdp->qos_neg, &pdp->qos_req, sizeof(pdp->qos_req.v)); */
  memcpy(pdp->qos_neg0, pdp->qos_req0, sizeof(pdp->qos_neg));

  getip(pdp, tun, &pdp->eua, &net, &mask);
  pdp_ipset(pdp, pdp->ipif, &pdp->eua);

  return 0; /* Success */
}



int create_tun() {
  char buf[1024];
  char snet[100], smask[100];

  if ((tun_fd = tun_newtun((struct tun_t**) &tun)) > maxfd)
    maxfd = tun_fd;

  if (tun_fd == -1) {
    printf("Failed to open tun\n");
    exit(1);
  }

  strncpy(snet, inet_ntoa(net), sizeof(snet)); 
  snet[sizeof(snet)-1] = 0;
  strncpy(smask, inet_ntoa(mask), sizeof(smask));
  smask[sizeof(smask)-1] = 0;

  snprintf(buf, sizeof(buf), "/sbin/ifconfig %s %s mtu 1450 netmask %s",
	  tun->devname, snet, smask);
  buf[sizeof(buf)-1] = 0;
  if (debug) printf("%s\n", buf);
  system(buf);

  if (ipup) {
    /* system("ipup /dev/tun0 192.168.0.10"); */
    snprintf(buf, sizeof(buf), "%s %s %s %s",
	     ipup, tun->devname, snet, smask);
    buf[sizeof(buf)-1] = 0;
    if (debug) printf("%s\n", buf);
    system(buf);
  }

  return 0;
}


int encaps_gtp(void *gsn, struct tun_t *tun, void *pack, unsigned len) {
  struct pdp_t *pdp;
  struct in_addr addr;
  struct ul66_t eua;
  /*printf("encaps_gtp. Packet received: forwarding to gtp.\n");*/
  /* First we need to extract the IP destination address */
  memcpy(&addr.s_addr, pack+16, 4); /* This ought to be dest addr */
  pdp_ntoeua(&addr, &eua);
  if (pdp_ipget(&pdp, tun, &eua) == 0) {
    return gtp_gpdu((struct gsn_t*) gsn, pdp, pack, len);
  }
  else {
    if (debug) printf("Received packet with no destination!!!\n");
    return 0;
  }
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

  struct in_addr listen;
	
  int gtpfd = -1;		/* Network file descriptor */
  struct gsn_t *gsn;            /* GSN instance            */

  fd_set fds;			/* For select() */
  struct timeval idleTime;	/* How long to select() */

  struct ul_t qos, apn;
  unsigned char qosh[3], apnh[256];

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
    printf("mask: %s\n", args_info.mask_arg);
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
    printf("mask: %s\n", args_info.mask_arg);
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
      memcpy(&listen.s_addr, host->h_addr, host->h_length);
    }
  }
  else {
    listen.s_addr = htonl(INADDR_ANY);
  }
  
  /* net                                                          */
  /* Store net as in_addr                                         */
  if (args_info.net_arg) {
    if (!inet_aton(args_info.net_arg, &net)) {
      fprintf(stderr, "%s: Invalid network address: %s!\n", 
	      PACKAGE, args_info.net_arg);
      syslog(LOG_ERR, "Invalid network address: %s!", 
	     args_info.net_arg);
      return 1;
    }
  }

  /* mask                                                         */
  /* Store mask as in_addr                                        */
  if (args_info.mask_arg) {
    if (!inet_aton(args_info.mask_arg, &mask)) {
      fprintf(stderr, "%s: Invalid network mask: %s!\n", 
	      PACKAGE, args_info.mask_arg);
      syslog(LOG_ERR, "Invalid network mask: %s!", 
	     args_info.mask_arg);
      return 1;
    }
  }

  /* ipup */
  ipup = args_info.ipup_arg;

  /* ipdown */
  ipdown = args_info.ipdown_arg;

  /* Timelimit                                                       */
  timelimit = args_info.timelimit_arg;
  starttime = time(NULL);
  
  /* qos                                                             */
  qos.l = 3;
  qos.v = qosh;
  qos.v[2] = (args_info.qos_arg) & 0xff;
  qos.v[1] = ((args_info.qos_arg) >> 8) & 0xff;
  qos.v[0] = ((args_info.qos_arg) >> 16) & 0xff;
  
  /* apn                                                             */
  if (strlen(args_info.apn_arg)>(sizeof(apnh)-1)) {
    printf("invalid APN\n");
    exit(1);
  }
  apn.l = strlen(args_info.apn_arg) + 1;
  apn.v = apnh;
  apn.v[0] = (char) strlen(args_info.apn_arg);
  strncpy(&apn.v[1], args_info.apn_arg, (sizeof(apnh)-1));

  if (debug) printf("gtpclient: Initialising GTP tunnel\n");
  
  if ((gtpfd = gtp_new(&gsn, args_info.statedir_arg, &listen)) > maxfd)
    maxfd = gtpfd;

  if ((gtpfd = gtp_fd(gsn)) > maxfd)
    maxfd = gtpfd;
    

  gtp_set_cb_gpdu(gsn, encaps_tun);
  gtp_set_cb_delete_context(gsn, delete_context);
  
  gtp_set_cb_create_context(gsn, create_context);
  create_tun();

  /******************************************************************/
  /* Main select loop                                               */
  /******************************************************************/

  while (((starttime + timelimit) > time(NULL)) || (0 == timelimit)) {
	
    FD_ZERO(&fds);
    if (tun_fd != -1) FD_SET(tun_fd, &fds);
    if (gtpfd != -1) FD_SET(gtpfd, &fds);
    
    gtp_retranstimeout(gsn, &idleTime);
    switch (select(maxfd + 1, &fds, NULL, NULL, &idleTime)) {
    case -1:	/* Error with select() *
		   if (errno != EINTR)
		   syslog(LOG_ERR, "CTRL: Error with select(), quitting");
		   *goto leave_clear_call;*/
      syslog(LOG_ERR, "GGSN: select = -1");
      break;  
    case 0:
      gtp_retrans(gsn); /* Only retransmit if nothing else */
      break; 
    default:
      break;
    }

    if (tun_fd != -1 && FD_ISSET(tun_fd, &fds) && 
	tun_decaps(tun, encaps_gtp, gsn) < 0) {
      syslog(LOG_ERR, "TUN read failed (fd)=(%d)", tun_fd);
    }

    if (gtpfd != -1 && FD_ISSET(gtpfd, &fds) && 
	gtp_decaps(gsn) < 0) {
      syslog(LOG_ERR, "GTP read failed (gtpfd)=(%d)", gtpfd);
    }
    
    
  }

  gtp_free(gsn);
  
  return 1;
  
}

