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
 * sgsnemu.c
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
#include <resolv.h>
#include <time.h>

#include "tun.h"
#include "../gtp/pdp.h"
#include "../gtp/gtp.h"
#include "cmdline.h"

/* State variable      */
/* 0: Idle             */
/* 1: Wait_connect     */
/* 2: Connected        */
/* 3: Wait_disconnect  */
int state = 0;                  

int maxfd = 0;	                /* For select() */
int tun_fd = -1;		/* Network file descriptor */
struct tun_t *tun;              /* TUN instance            */
struct tun_t *tun1, *tun2;      /* TUN instance for client */
int tun_fd1 = -1;		/* Network file descriptor */
int tun_fd2 = -1;		/* Network file descriptor */
struct in_addr net, mask;       /* Network interface       */
int stattun;                    /* Allocate static tun     */

int debug;                      /* Print debug messages */

int encaps_printf(void *p, void *packet, unsigned len)
{
  int i;
  printf("The packet looks like this:\n");
  for( i=0; i<len; i++) {
    printf("%02x ", (unsigned char)*(char *)(packet+i));
    if (!((i+1)%16)) printf("\n");
  };
  printf("\n"); 
}

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


int create_tun() {
  char buf[1024];
  char snet[100], smask[100];

  if ((tun_fd = tun_newtun((struct tun_t**) &tun)) > maxfd)
    maxfd = tun_fd;

  if (tun_fd == -1) {
    printf("Failed to open tun\n");
    exit(1);
  }

  strncpy(snet, inet_ntoa(net), 100);
  strncpy(smask, inet_ntoa(mask), 100);

  sprintf(buf, "ifconfig %s %s mtu 1450 netmask %s",
	  tun->devname, snet, smask);
  if (debug) printf("%s\n", buf);
  system(buf);

  system("echo 1 > /proc/sys/net/ipv4/ip_forward");
  
  return 0;
}

int getip(struct pdp_t *pdp, void* ipif, struct ul66_t *eua,
	  struct in_addr *net, struct in_addr *mask) {
  struct in_addr addr;
  uint32_t ip_start, ip_end, ip_cur;
  struct pdp_t *pdp_;
  struct ul66_t eua_;

  printf("Begin getip %d %d %2x%2x%2x%2x\n", (unsigned)ipif, eua->l, 
	 eua->v[2],eua->v[3],eua->v[4],eua->v[5]);

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

  if (!stattun) {
    tun_freetun((struct tun_t*) pdp->ipif);
    
    /* Clean up locally */
    if (pdp->ipif == tun1) {
      printf("Deleting tun interface\n");
      tun_fd1=-1;
    }
    if (pdp->ipif == tun2) {
      printf("Deleting tun interface\n");
      tun_fd2=-1;
    }
  }

  pdp_ipdel(pdp);
  return 0;
}

int create_pdp_conf(struct pdp_t *pdp, int cause) {
  char buf[1024];

  printf("Received create PDP context response. Cause value: %d\n", cause);
  if ((cause == 128) && (pdp->eua.l == 6)) {


    if (stattun) {
      pdp->ipif = tun1;
    }
    else {
      printf("Setting up interface and routing\n");
      if ((tun_fd = tun_newtun((struct tun_t**) &pdp->ipif)) > maxfd)
	maxfd = tun_fd;

      /* HACK: Only support select of up to two tun interfaces */
      if (NULL == tun1) {
	tun1 = pdp->ipif;
	tun_fd1 = tun1->fd;
      }
      else {
	tun2 = pdp->ipif;
	tun_fd2 = tun2->fd;
      }
      
      /*system("ifconfig tun0 192.168.0.10");*/
      sprintf(buf, "ifconfig %s %hu.%hu.%hu.%hu", 
	      ((struct tun_t*) pdp->ipif)->devname,
	      pdp->eua.v[2], pdp->eua.v[3], pdp->eua.v[4], pdp->eua.v[5]);
      printf(buf);  printf("\n");
      system(buf);
      
      
      /*system("route add -net 192.168.0.0 netmask 255.255.255.0 gw 192.168.0.10");*/
      sprintf(buf, "route add -net %hu.%hu.%hu.0 netmask 255.255.255.0 gw %hu.%hu.%hu.%hu", 
	      pdp->eua.v[2], pdp->eua.v[3], pdp->eua.v[4],
	      pdp->eua.v[2], pdp->eua.v[3], pdp->eua.v[4], pdp->eua.v[5]);
      printf(buf);  printf("\n");
      system(buf);
      
      system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    }
    
    pdp_ipset(pdp, pdp->ipif, &pdp->eua);

    state = 2;                      /* Connected */
  }
  else {
    state = 0;
  }

  printf("\n");

  return 0;
}


int create_pdp_ind(struct pdp_t *pdp) {

  printf("Received create PDP context request\n");

  pdp->eua.l=0; /* TODO: Indicates dynamic IP */

  /* ulcpy(&pdp->qos_neg, &pdp->qos_req, sizeof(pdp->qos_req.v)); */
  memcpy(pdp->qos_neg0, pdp->qos_req0, sizeof(pdp->qos_neg));

  getip(pdp, &tun, &pdp->eua, &net, &mask);
  pdp_ipset(pdp, pdp->ipif, &pdp->eua);

  return 0; /* Success */
}


int delete_pdp_conf(struct pdp_t *pdp, int cause) {
  printf("Received delete PDP context response. Cause value: %d\n", cause);
  return 0;
}

int echo_conf(struct pdp_t *pdp, int cause) {
  printf("Received echo response. Cause value: %d\n", cause);
  return 0;
}

int conf(int type, int cause, struct pdp_t* pdp, void *aid) {
  /* if (cause < 0) return 0; Some error occurred. We don't care */
  switch (type) {
  case GTP_ECHO_REQ:
    return echo_conf(pdp, cause);
  case GTP_CREATE_PDP_REQ:
    if (cause !=128) return 0; /* Request not accepted. We don't care */
    return create_pdp_conf(pdp, cause);
  case GTP_DELETE_PDP_REQ:
    if (cause !=128) return 0; /* Request not accepted. We don't care */
    return delete_pdp_conf(pdp, cause);
  default:
    return 0;
  }
}

int encaps_gtp_client(void *gsn, struct tun_t *tun, void *pack, unsigned len) {
  /* Special client version which checks for source address instead */
  struct pdp_t *pdp;
  struct in_addr addr;
  struct ul66_t eua;
  /*printf("encaps_gtp. Packet received: forwarding to gtp.\n");*/
  /* First we need to extract the IP destination address */
  memcpy(&addr.s_addr, pack+12, 4); /* This ought to be dest addr */
  pdp_ntoeua(&addr, &eua);
  if (pdp_ipget(&pdp, tun, &eua) == 0) {
    return gtp_gpdu((struct gsn_t*) gsn, pdp, pack, len);
  }
  else {
    printf("Received packet with no destination!!!\n");
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

  /* function-local options */

  struct hostent *host;

  struct in_addr listen, remote;
  struct in_addr dns;

  int gtpfd = -1;		/* Network file descriptor */
  struct gsn_t *gsn;            /* GSN instance            */

  fd_set fds;			/* For select() */
  struct timeval idleTime;	/* How long to select() */

  struct pdp_t *pdp[2];
	
  int n; /* For counter */

  int contexts; /* Number of contexts to create */
  int timelimit; /* Number of seconds to be connected */
  int starttime; /* Time program was started */

  struct ul_t imsi, qos, apn, msisdn;
  unsigned char qosh[3], imsih[8], apnh[256], msisdnh[256];
  struct ul255_t pco;
  uint64_t imsi3;

  /* open a connection to the syslog daemon */
  /*openlog(PACKAGE, LOG_PID, LOG_DAEMON);*/
  openlog(PACKAGE, (LOG_PID | LOG_PERROR), LOG_DAEMON);

  if (cmdline_parser (argc, argv, &args_info) != 0)
    exit(1);
  if (args_info.debug_flag) {
    printf("remote: %s\n", args_info.remote_arg);
    printf("listen: %s\n", args_info.listen_arg);
    printf("conf: %s\n", args_info.conf_arg);
    printf("fg: %d\n", args_info.fg_flag);
    printf("debug: %d\n", args_info.debug_flag);
    printf("imsi: %s\n", args_info.imsi_arg);
    printf("qos: %#08x\n", args_info.qos_arg);
    printf("apn: %s\n", args_info.apn_arg);
    printf("msisdn: %s\n", args_info.msisdn_arg);
    printf("uid: %s\n", args_info.uid_arg);
    printf("pwd: %s\n", args_info.pwd_arg);
    printf("static: %d\n", args_info.static_flag);
    printf("net: %s\n", args_info.net_arg);
    printf("mask: %s\n", args_info.mask_arg);
    printf("pidfile: %s\n", args_info.pidfile_arg);
    printf("statedir: %s\n", args_info.statedir_arg);
    printf("dns: %s\n", args_info.dns_arg);
    printf("contexts: %d\n", args_info.contexts_arg);
    printf("timelimit: %d\n", args_info.timelimit_arg);
  }

  /* Try out our new parser */
  
  if (args_info.conf_arg) {
    if (cmdline_parser_configfile (args_info.conf_arg, &args_info, 0) != 0)
      exit(1);
    if (args_info.debug_flag) {
      printf("cmdline_parser_configfile\n");
      printf("remote: %s\n", args_info.remote_arg);
      printf("listen: %s\n", args_info.listen_arg);
      printf("conf: %s\n", args_info.conf_arg);
      printf("fg: %d\n", args_info.fg_flag);
      printf("debug: %d\n", args_info.debug_flag);
      printf("imsi: %s\n", args_info.imsi_arg);
      printf("qos: %#08x\n", args_info.qos_arg);
      printf("apn: %s\n", args_info.apn_arg);
      printf("msisdn: %s\n", args_info.msisdn_arg);
      printf("uid: %s\n", args_info.uid_arg);
      printf("pwd: %s\n", args_info.pwd_arg);
      printf("static: %d\n", args_info.static_flag);
      printf("net: %s\n", args_info.net_arg);
      printf("mask: %s\n", args_info.mask_arg);
      printf("pidfile: %s\n", args_info.pidfile_arg);
      printf("statedir: %s\n", args_info.statedir_arg);
      printf("dns: %s\n", args_info.dns_arg);
      printf("contexts: %d\n", args_info.contexts_arg);
      printf("timelimit: %d\n", args_info.timelimit_arg);
    }
  }

  /* Handle each option */

  /* foreground                                                   */
  /* If flag not given run as a daemon                            */
  if (!args_info.fg_flag)
    {
      closelog(); 
      /* Close the standard file descriptors. Why? */
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

  /* dns                                                          */
  /* If no dns option is given use system         default         */
  /* Do hostname lookup to translate hostname to IP address       */
  printf("\n");
  if (args_info.dns_arg) {
    if (!(host = gethostbyname(args_info.dns_arg))) {
      fprintf(stderr, "%s: Invalid dns address: %s!\n", 
	      PACKAGE, args_info.dns_arg);
      syslog(LOG_ERR, "Invalid dns address: %s!", 
	     args_info.dns_arg);
      exit(1);
    }
    else {
      memcpy(&dns.s_addr, host->h_addr, host->h_length);
      _res.nscount = 1;
      _res.nsaddr_list[0].sin_addr = dns;
      printf("Using DNS server:      %s (%s)\n", args_info.dns_arg, inet_ntoa(dns));
    }
  }
  else {
    dns.s_addr= 0;
    printf("Using default DNS server\n");
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
      exit(1);
    }
    else {
      memcpy(&listen.s_addr, host->h_addr, host->h_length);
      printf("Local IP address is:   %s (%s)\n", args_info.listen_arg, inet_ntoa(listen));
    }
  }
  else {
    fprintf(stderr, "%s: Listening address must be specified: %s!\n", 
	    PACKAGE, args_info.listen_arg);
    syslog(LOG_ERR, "Listening address must be specified: %s!", 
	   args_info.listen_arg);
    exit(1);
  }
  
  
  /* remote                                                       */
  /* If no remote option is specified terminate                   */
  /* Do hostname lookup to translate hostname to IP address       */
  if (args_info.remote_arg) {
    if (!(host = gethostbyname(args_info.remote_arg))) {
      fprintf(stderr, "%s: Invalid remote address: %s!\n", 
	      PACKAGE, args_info.remote_arg);
      syslog(LOG_ERR, "Invalid remote address: %s!", 
	     args_info.remote_arg);
      exit(1);
    }
    else {
      memcpy(&remote.s_addr, host->h_addr, host->h_length);
      printf("Remote IP address is:  %s (%s)\n", args_info.remote_arg, inet_ntoa(remote));
    }
  }
  else {
    fprintf(stderr, "%s: No remote address given!\n", 
	    PACKAGE);
    syslog(LOG_ERR, "No remote address given!");
    exit(1);
  }


  /* net                                                          */
  /* Store net as in_addr                                         */
  if (args_info.net_arg) {
    if (!inet_aton(args_info.net_arg, &net)) {
      fprintf(stderr, "%s: Invalid network address: %s!\n", 
	      PACKAGE, args_info.net_arg);
      syslog(LOG_ERR, "Invalid network address: %s!", 
	     args_info.net_arg);
      exit(1);
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
      exit(1);
    }
  }

  /* imsi                                                            */
  if (strlen(args_info.imsi_arg)!=15) {
    printf("Invalid IMSI\n");
    exit(1);
  }
  imsi.l = 8;
  imsi.v = imsih;
  imsi.v[0] = args_info.imsi_arg[0]-48 + (args_info.imsi_arg[1]-48)*16;
  imsi.v[1] = args_info.imsi_arg[2]-48 + (args_info.imsi_arg[3]-48)*16;
  imsi.v[2] = args_info.imsi_arg[4]-48 + (args_info.imsi_arg[5]-48)*16;
  imsi.v[3] = args_info.imsi_arg[6]-48 + (args_info.imsi_arg[7]-48)*16;
  imsi.v[4] = args_info.imsi_arg[8]-48 + (args_info.imsi_arg[9]-48)*16;
  imsi.v[5] = args_info.imsi_arg[10]-48 + (args_info.imsi_arg[11]-48)*16;
  imsi.v[6] = args_info.imsi_arg[12]-48 + (args_info.imsi_arg[13]-48)*16;
  imsi.v[7] = args_info.imsi_arg[14]-48 + 0*16;

  if (imsi.l > sizeof(imsi3)) {
    printf("Invalid IMSI\n");
    exit(1);
  }
  else {
    memcpy(&imsi3, imsi.v, imsi.l);
    printf("IMSI is:               %s (%#08llx)\n", args_info.imsi_arg, imsi3);
  }

  /* qos                                                             */
  qos.l = 3;
  qos.v = qosh;
  qos.v[2] = (args_info.qos_arg) & 0xff;
  qos.v[1] = ((args_info.qos_arg) >> 8) & 0xff;
  qos.v[0] = ((args_info.qos_arg) >> 16) & 0xff;
  
  /* contexts                                                        */
  contexts = args_info.contexts_arg;

  /* Timelimit                                                       */
  timelimit = args_info.timelimit_arg;
  starttime = time(NULL);
  
  /* apn                                                             */
  if (strlen(args_info.apn_arg)>255) {
    printf("Invalid APN\n");
    exit(1);
  }
  apn.l = strlen(args_info.apn_arg) + 1;
  apn.v = apnh;
  apn.v[0] = (char) strlen(args_info.apn_arg);
  strncpy(&apn.v[1], args_info.apn_arg, 255);
  printf("Using APN:             %s\n", args_info.apn_arg);
  
  /* msisdn                                                          */
  if (strlen(args_info.msisdn_arg)>255) {
    printf("Invalid MSISDN\n");
    exit(1);
  }
  msisdn.l = 1;
  msisdn.v = msisdnh;
  msisdn.v[0] = 0x91; /* International format */
  for(n=0; n<strlen(args_info.msisdn_arg); n++) {
    if ((n%2) == 0) {
      msisdn.v[((int)n/2)+1] = args_info.msisdn_arg[n] - 48 + 0xf0;
      msisdn.l += 1;
    }
    else {
      msisdn.v[((int)n/2)+1] = (msisdn.v[((int)n/2)+1] & 0x0f) + (args_info.msisdn_arg[n] - 48) * 16;
    }
  }
  printf("Using MSISDN:          %s\n", args_info.msisdn_arg);

  /* UID and PWD */
  /* Might need to also insert stuff like DNS etc. */
  if ((strlen(args_info.uid_arg) + strlen(args_info.pwd_arg) + 10)>255) {
    printf("invalid UID and PWD\n");
    exit(1);
  }
  pco.l = strlen(args_info.uid_arg) + strlen(args_info.pwd_arg) + 10;
  pco.v[0] = 0x80; /* PPP */
  pco.v[1] = 0xc0;
  pco.v[2] = 0x23; /* PAP */
  pco.v[3] = 0x12;
  pco.v[4] = 0x01; /* Authenticate request */
  pco.v[5] = 0x01;
  pco.v[6] = 0x00; /* MSB of length */
  pco.v[7] = strlen(args_info.uid_arg) + strlen(args_info.pwd_arg) + 6;
  pco.v[8] = strlen(args_info.uid_arg);
  memcpy(&pco.v[9], args_info.uid_arg, strlen(args_info.uid_arg));
  pco.v[9+strlen(args_info.uid_arg)] = strlen(args_info.pwd_arg);
  memcpy(&pco.v[10+strlen(args_info.uid_arg)], args_info.pwd_arg, strlen(args_info.pwd_arg));
  
  /* static */
  stattun = args_info.static_flag;

  printf("\nInitialising GTP library\n");
  if ((gtpfd = gtp_new(&gsn, args_info.statedir_arg,  &listen)) > maxfd)
    maxfd = gtpfd;

  if ((gtpfd = gtp_fd(gsn)) > maxfd)
    maxfd = gtpfd;
    
  gtp_set_cb_gpdu(gsn, encaps_tun);
  gtp_set_cb_delete_context(gsn, delete_context);
  
  gtp_set_cb_conf(gsn, conf);
  printf("Done initialising GTP library\n\n");
  
  if (stattun) {
    create_tun();
    tun1 = tun;
    tun_fd1 = tun1->fd;
  }

  /* See if anybody is there */
  printf("Sending off echo request\n");
  if (gtpfd != -1) gtp_echo_req(gsn, &remote); /* See if remote is alive ? */

  for(n=0; n<contexts; n++) {
    printf("Setting up PDP context #%d\n", n);

    pdp_newpdp(&pdp[n], imsi3, n, NULL); /* Allocated here. Cleaned up in gtp.c: TODO Should be statically allocated! */
    
    /*    
	  if (qos.l > sizeof(pdp[n]->qos_req.v)) {
	  exit(1);
	  }
	  else {
	  pdp[n]->qos_req.l = qos.l;
	  memcpy(pdp[n]->qos_req.v, qos.v, qos.l);
	  }
    */
    memcpy(pdp[n]->qos_req0, qos.v, qos.l); /* TODO range check */
    
    pdp[n]->selmode = 0x01; /* MS provided APN, subscription not verified */
    
    if (apn.l > sizeof(pdp[n]->apn_use.v)) {
      exit(1);
    }
    else {
      pdp[n]->apn_use.l = apn.l;
      memcpy(pdp[n]->apn_use.v, apn.v, apn.l);
    }
    
    pdp[n]->gsnlc.l = 4;
    memcpy(pdp[n]->gsnlc.v, &listen, 4);
    pdp[n]->gsnlu.l = 4;
    memcpy(pdp[n]->gsnlu.v, &listen, 4);
    
    if (msisdn.l > sizeof(pdp[n]->msisdn.v)) {
      exit(1);
    }
    else {
      pdp[n]->msisdn.l = msisdn.l;
      memcpy(pdp[n]->msisdn.v, msisdn.v, msisdn.l);
    }
    
    ipv42eua(&pdp[n]->eua, NULL); /* Request dynamic IP address */
    
    if (pco.l > sizeof(pdp[n]->pco_req.v)) {
      exit(1);
    }
    else {
      pdp[n]->pco_req.l = pco.l;
      memcpy(pdp[n]->pco_req.v, pco.v, pco.l);
    }
    
    /* Create context */
    /* We send this of once. Retransmissions are handled by gtplib */
    if (gtpfd != -1) gtp_create_context(gsn, pdp[n], NULL, &remote);
  }    

  state = 1;  /* Enter wait_connection state */

  printf("Waiting for response from ggsn........\n\n");

  
  /******************************************************************/
  /* Main select loop                                               */
  /******************************************************************/

  while (((starttime + timelimit + 10) > time(NULL)) || (0 == timelimit)) {

    /* Take down client connections at some stage */
    if (((starttime + timelimit) <= time(NULL)) && (0 != timelimit) && (2 == state)) {
      state = 3;
      for(n=0; n<contexts; n++) {
	/* Delete context */
	printf("Disconnecting PDP context #%d\n", n);
	if (gtpfd != -1) gtp_delete_context(gsn, pdp[n], NULL);
      }
    }

    FD_ZERO(&fds);
    if (tun_fd1 != -1) FD_SET(tun_fd1, &fds);
    if (tun_fd2 != -1) FD_SET(tun_fd2, &fds);
    if (gtpfd != -1) FD_SET(gtpfd, &fds);
    
    gtp_retranstimeout(gsn, &idleTime);

    switch (select(maxfd + 1, &fds, NULL, NULL, &idleTime)) {
    case -1:
      syslog(LOG_ERR, "sgsnemu: select = -1");
      break;  
    case 0:
      gtp_retrans(gsn); /* Only retransmit if nothing else */
      break; 
    default:
      break;
    }

    if (tun_fd1 != -1 && 
	FD_ISSET(tun_fd1, &fds) && 
	tun_decaps(tun1, encaps_gtp_client, gsn) < 0) {
      syslog(LOG_ERR, "TUN read failed (fd)=(%d)", tun_fd1);
    }

    if (tun_fd2 != -1 && 
	FD_ISSET(tun_fd2, &fds) && 
	tun_decaps(tun2, encaps_gtp_client, gsn) < 0) {
      syslog(LOG_ERR, "TUN read failed (fd)=(%d)", tun_fd2);
    }

    if (gtpfd != -1 && FD_ISSET(gtpfd, &fds) && 
	gtp_decaps(gsn) < 0) {
      syslog(LOG_ERR, "GTP read failed (gre)=(%d)", gtpfd);
    }
    
    
    }

  gtp_free(gsn); /* Clean up the gsn instance */
  
  return 1;
  
}

