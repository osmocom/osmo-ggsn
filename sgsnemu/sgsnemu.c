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
#include <sys/time.h>
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

#define SGSNEMU_BUFSIZE 1024

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

/* Variables matching program configuration parameters */
int debug;                      /* Print debug messages */
struct in_addr net, mask;       /* Network interface       */
int createif;                   /* Create local network interface */
char *ipup, *ipdown;            /* Filename of scripts */
int defaultroute;               /* Set up default route    */
struct in_addr pinghost;        /* Remote ping host    */
int pingrate, pingsize, pingcount, pingquiet;
struct in_addr listen_, remote;
struct in_addr dns;
int contexts;                   /* Number of contexts to create */
int timelimit;                  /* Number of seconds to be connected */


/* Definitions to use for PING. Most of the ping code was derived from */
/* the original ping program by Mike Muuss                             */

/* IP header and ICMP echo header */
#define CREATEPING_MAX  2048
#define CREATEPING_IP     20
#define CREATEPING_ICMP    8

struct ip_ping {
  u_int8_t ipver;               /* Type and header length*/
  u_int8_t tos;                 /* Type of Service */
  u_int16_t length;             /* Total length */
  u_int16_t fragid;             /* Identifier */
  u_int16_t offset;             /* Flags and fragment offset */
  u_int8_t ttl;                 /* Time to live */
  u_int8_t protocol;            /* Protocol */
  u_int16_t ipcheck;            /* Header checksum */
  u_int32_t src;                /* Source address */
  u_int32_t dst;                /* Destination */
  u_int8_t type;                /* Type and header length*/
  u_int8_t code;                /* Code */
  u_int16_t checksum;           /* Header checksum */
  u_int16_t ident;              /* Identifier */
  u_int16_t seq;                /* Sequence number */
  u_int8_t data[CREATEPING_MAX]; /* Data */
} __attribute__((packed));

/* Statistical values for ping */
int nreceived = 0;
int ntreceived = 0;
int ntransmitted = 0;
int tmin = 999999999;
int tmax = 0;
int tsum = 0;


int encaps_printf(struct pdp_t *pdp, void *pack, unsigned len) {
  int i;
  printf("The packet looks like this:\n");
  for( i=0; i<len; i++) {
    printf("%02x ", (unsigned char)*(char *)(pack+i));
    if (!((i+1)%16)) printf("\n");
  };
  printf("\n");
  return 0;
}

char * print_ipprot(int t) {
  switch (t) {
  case  1: return "ICMP";
  case  6: return "TCP";
  case 17: return "UDP";
  default: return "Unknown";
  };
}


char * print_icmptype(int t) {
  static char *ttab[] = {
    "Echo Reply",
    "ICMP 1",
    "ICMP 2",
    "Dest Unreachable",
    "Source Quench",
    "Redirect",
    "ICMP 6",
    "ICMP 7",
    "Echo",
    "ICMP 9",
    "ICMP 10",
    "Time Exceeded",
    "Parameter Problem",
    "Timestamp",
    "Timestamp Reply",
    "Info Request",
    "Info Reply"
  };
  if( t < 0 || t > 16 )
    return("OUT-OF-RANGE");  
  return(ttab[t]);
}

/* Print out statistics when at the end of ping sequence */
int ping_finish()
{
  printf("\n");
  printf("\n----%s PING Statistics----\n", inet_ntoa(pinghost));
  printf("%d packets transmitted, ", ntransmitted );
  printf("%d packets received, ", nreceived );
  if (ntransmitted) {
    if( nreceived > ntransmitted)
      printf("-- somebody's printing up packets!");
    else
      printf("%d%% packet loss", 
	     (int) (((ntransmitted-nreceived)*100) /
		    ntransmitted));
  }
  printf("\n");
  if (debug) printf("%d packets received in total\n", ntreceived );
  if (nreceived  && tsum)
    printf("round-trip (ms)  min/avg/max = %.3f/%.3f/%.3f\n\n",
	   tmin/1000.0,
	   tsum/1000.0/nreceived,
	   tmax/1000.0 );
  ntransmitted = 0;
  return 0;
}

/* Handle a received ping packet. Print out line and update statistics. */
int encaps_ping(struct pdp_t *pdp, void *pack, unsigned len) {
  struct timezone tz;
  struct timeval tv;
  struct timeval *tp;
  struct ip_ping *pingpack = pack;
  struct in_addr src;
  int triptime;

  src.s_addr = pingpack->src;

  gettimeofday(&tv, &tz);
  if (debug) printf("%d.%6d ", (int) tv.tv_sec, (int) tv.tv_usec);

  if (len < CREATEPING_IP + CREATEPING_ICMP) {
    printf("packet too short (%d bytes) from %s\n", len,
	   inet_ntoa(src));
    return 0;
  }

  ntreceived++;
  if (pingpack->protocol != 1) {
    if (!pingquiet) printf("%d bytes from %s: ip_protocol=%d (%s)\n",
	   len, inet_ntoa(src), pingpack->protocol, 
	   print_ipprot(pingpack->protocol));
    return 0;
  }

  if (pingpack->type != 0) {
    if (!pingquiet) printf("%d bytes from %s: icmp_type=%d (%s) icmp_code=%d\n",
	   len, inet_ntoa(src), pingpack->type, 
	   print_icmptype(pingpack->type), pingpack->code);
    return 0;
  }

  nreceived++;
  if (!pingquiet) printf("%d bytes from %s: icmp_seq=%d", len,
	 inet_ntoa(src), ntohs(pingpack->seq));

  if (len >= sizeof(struct timeval) + CREATEPING_IP + CREATEPING_ICMP) {
    gettimeofday(&tv, &tz);
    tp = (struct timeval *) pingpack->data;
    if( (tv.tv_usec -= tp->tv_usec) < 0 )   {
      tv.tv_sec--;
      tv.tv_usec += 1000000;
    }
    tv.tv_sec -= tp->tv_sec;

    triptime = tv.tv_sec*1000000+(tv.tv_usec);
    tsum += triptime;
    if( triptime < tmin )
      tmin = triptime;
    if( triptime > tmax )
      tmax = triptime;

    if (!pingquiet) printf(" time=%.3f ms\n", triptime/1000.0);

  } 
  else
    if (!pingquiet) printf("\n");
  return 0;
}

/* Create a new ping packet and send it off to peer. */
int create_ping(void *gsn, struct pdp_t *pdp,
		struct in_addr *dst, int seq, int datasize) {

  struct ip_ping pack;
  u_int16_t *p = (u_int16_t *) &pack;
  u_int8_t  *p8 = (u_int8_t *) &pack;
  struct in_addr src;
  int n;
  long int sum = 0;
  int count = 0;

  struct timezone tz;
  struct timeval *tp = (struct timeval *) &p8[CREATEPING_IP + CREATEPING_ICMP];

  if (datasize > CREATEPING_MAX) {
    fprintf(stderr, "%s: Ping size to large: %d!\n", 
	    PACKAGE, datasize);
    syslog(LOG_ERR, "Ping size to large: %d!", 
	   datasize);
    exit(1);
  }

  memcpy(&src, &(pdp->eua.v[2]), 4); /* Copy a 4 byte address */

  pack.ipver  = 0x45;
  pack.tos    = 0x00;
  pack.length = htons(CREATEPING_IP + CREATEPING_ICMP + datasize);
  pack.fragid = 0x0000;
  pack.offset = 0x0040;
  pack.ttl    = 0x40;
  pack.protocol = 0x01;
  pack.ipcheck = 0x0000;
  pack.src = src.s_addr;
  pack.dst = dst->s_addr;
  pack.type = 0x08;
  pack.code = 0x00;
  pack.checksum = 0x0000;
  pack.ident = 0x0000;
  pack.seq = htons(seq);

  /* Generate ICMP payload */
  p8 = (u_int8_t *) &pack + CREATEPING_IP + CREATEPING_ICMP;
  for (n=0; n<(datasize); n++) p8[n] = n;

  if (datasize >= sizeof(struct timeval)) 
    gettimeofday(tp, &tz);

  /* Calculate IP header checksum */
  p = (u_int16_t *) &pack;
  count = CREATEPING_IP;
  sum = 0;
  while (count>1) {
    sum += *p++;
    count -= 2;
  }
  while (sum>>16) 
    sum = (sum & 0xffff) + (sum >> 16);
  pack.ipcheck = ~sum;


  /* Calculate ICMP checksum */
  count = CREATEPING_ICMP + datasize; /* Length of ICMP message */
  sum = 0;
  p = (u_int16_t *) &pack;
  p += CREATEPING_IP / 2;
  while (count>1) {
    sum += *p++;
    count -= 2;
  }
  if (count>0)
    sum += * (unsigned char *) p;
  while (sum>>16) 
    sum = (sum & 0xffff) + (sum >> 16);
  pack.checksum = ~sum;

  ntransmitted++;

  return gtp_gpdu(gsn, pdp, &pack, 28 + datasize);
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

int delete_context(struct pdp_t *pdp) {
  char buf[SGSNEMU_BUFSIZE];
  if ((createif) && (pdp->ipif!=0)) {
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
  
  if (ipdown) {
    /* system("ipdown /dev/tun0 192.168.0.10"); */
    snprintf(buf, sizeof(buf), "%s %s %hu.%hu.%hu.%hu",
	     ipdown,
	     ((struct tun_t*) pdp->ipif)->devname,
	     pdp->eua.v[2], pdp->eua.v[3], pdp->eua.v[4], pdp->eua.v[5]);
    if (debug) printf("%s\n", buf);
    system(buf);
  }

  pdp_ipdel(pdp);
  return 0;
}

int create_pdp_conf(struct pdp_t *pdp, int cause) {
  char buf[SGSNEMU_BUFSIZE];
  char snet[SGSNEMU_BUFSIZE];
  char smask[SGSNEMU_BUFSIZE];

  printf("Received create PDP context response. Cause value: %d\n", cause);
  if ((cause == 128) && (pdp->eua.l == 6)) {
    
    if (!createif) {
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
      
      /*system("/sbin/ifconfig tun0 192.168.0.10");*/
      snprintf(buf, sizeof(buf), "/sbin/ifconfig %s %hu.%hu.%hu.%hu", 
	      ((struct tun_t*) pdp->ipif)->devname,
	      pdp->eua.v[2], pdp->eua.v[3], pdp->eua.v[4], pdp->eua.v[5]);
      /* if (debug) */ printf("%s\n", buf);
      system(buf);

      /* system("route add -host 192.168.0.10 dev tun0"); */
      /* It seams as if we do not need to set up a route to a p-t-p interface
	 snprintf(buf, sizeof(buf), 
	       "/sbin/route add -host %hu.%hu.%hu.%hu dev %s",
	      pdp->eua.v[2], pdp->eua.v[3], pdp->eua.v[4], pdp->eua.v[5],
	      ((struct tun_t*) pdp->ipif)->devname);
	 if (debug) printf("%s\n", buf);
      system(buf);*/

      if (defaultroute) {
	strncpy(snet, inet_ntoa(net), sizeof(snet));
	strncpy(smask, inet_ntoa(mask), sizeof(smask));
	/* system("route add -net 0.0.0.0 netmask 0.0.0.0 gw 192.168.0.1"); */
	snprintf(buf, sizeof(buf), 
		 "/sbin/route add -net %s netmask %s gw %hu.%hu.%hu.%hu", 
		snet, smask,
		pdp->eua.v[2], pdp->eua.v[3], pdp->eua.v[4], pdp->eua.v[5]);
	/* if (debug) */ printf("%s\n", buf);
	system(buf);
      }

      if (ipup) {
	/* system("ipup /dev/tun0 192.168.0.10"); */
	snprintf(buf, sizeof(buf), "%s %s %hu.%hu.%hu.%hu",
		ipup,
		((struct tun_t*) pdp->ipif)->devname,
		pdp->eua.v[2], pdp->eua.v[3], pdp->eua.v[4], pdp->eua.v[5]);
	if (debug) printf("%s\n", buf);
	system(buf);
      }
      
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

int delete_pdp_conf(struct pdp_t *pdp, int cause) {
  printf("Received delete PDP context response. Cause value: %d\n", cause);
  state = 0; /* Idle */
  return 0;
}

int echo_conf(struct pdp_t *pdp, int cause) {
  if (cause <0)
    printf("Echo request timed out\n");
  else
    printf("Received echo response.\n");
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
    printf("Received packet without a valid source address!!!\n");
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
  int gtpfd = -1;		/* Network file descriptor */
  struct gsn_t *gsn;            /* GSN instance            */
  fd_set fds;			/* For select() */
  struct timeval idleTime;	/* How long to select() */
  struct pdp_t *pdp[50];
  int n; /* For counter */
  int starttime;                /* Time program was started */
  int pingseq = 0;              /* Ping sequence counter */

  /* function-local options */
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
    printf("pidfile: %s\n", args_info.pidfile_arg);
    printf("statedir: %s\n", args_info.statedir_arg);
    printf("dns: %s\n", args_info.dns_arg);
    printf("contexts: %d\n", args_info.contexts_arg);
    printf("timelimit: %d\n", args_info.timelimit_arg);
    printf("createif: %d\n", args_info.createif_flag);
    printf("ipup: %s\n", args_info.ipup_arg);
    printf("ipdown: %s\n", args_info.ipdown_arg);
    printf("defaultroute: %d\n", args_info.defaultroute_flag);
    printf("net: %s\n", args_info.net_arg);
    printf("mask: %s\n", args_info.mask_arg);
    printf("pinghost: %s\n", args_info.pinghost_arg);
    printf("pingrate: %d\n", args_info.pingrate_arg);
    printf("pingsize: %d\n", args_info.pingsize_arg);
    printf("pingcount: %d\n", args_info.pingcount_arg);
    printf("pingquiet: %d\n", args_info.pingquiet_flag);
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
      printf("pidfile: %s\n", args_info.pidfile_arg);
      printf("statedir: %s\n", args_info.statedir_arg);
      printf("dns: %s\n", args_info.dns_arg);
      printf("contexts: %d\n", args_info.contexts_arg);
      printf("timelimit: %d\n", args_info.timelimit_arg);
      printf("createif: %d\n", args_info.createif_flag);
      printf("ipup: %s\n", args_info.ipup_arg);
      printf("ipdown: %s\n", args_info.ipdown_arg);
      printf("defaultroute: %d\n", args_info.defaultroute_flag);
      printf("net: %s\n", args_info.net_arg);
      printf("mask: %s\n", args_info.mask_arg);
      printf("pinghost: %s\n", args_info.pinghost_arg);
      printf("pingrate: %d\n", args_info.pingrate_arg);
      printf("pingsize: %d\n", args_info.pingsize_arg);
      printf("pingcount: %d\n", args_info.pingcount_arg);
      printf("pingquiet: %d\n", args_info.pingquiet_flag);
    }
  }

  /* Handle each option */

  /* foreground                                                   */
  /* If fg flag not given run as a daemon                            */
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
  /* If no dns option is given use system default                 */
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
      memcpy(&listen_.s_addr, host->h_addr, host->h_length);
      printf("Local IP address is:   %s (%s)\n", args_info.listen_arg, inet_ntoa(listen_));
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
  if (args_info.contexts_arg>16) {
    printf("Contexts has to be less than 16\n");
    exit(1);
  }
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
  
  /* createif */
  createif = args_info.createif_flag;

  /* ipup */
  ipup = args_info.ipup_arg;

  /* ipdown */
  ipdown = args_info.ipdown_arg;

  /* defaultroute */
  defaultroute = args_info.defaultroute_flag;

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

  /* pinghost                                                         */
  /* Store ping host as in_addr                                   */
  if (args_info.pinghost_arg) {
    if (!inet_aton(args_info.pinghost_arg, &pinghost)) {
      fprintf(stderr, "%s: Invalid ping host: %s!\n", 
	      PACKAGE, args_info.pinghost_arg);
      syslog(LOG_ERR, "Invalid ping host: %s!", 
	     args_info.pinghost_arg);
      exit(1);
    }
  }

  /* Other ping parameters                                        */
  pingrate = args_info.pingrate_arg;
  pingsize = args_info.pingsize_arg;
  pingcount = args_info.pingcount_arg;
  pingquiet = args_info.pingquiet_flag;

  printf("\nInitialising GTP library\n");
  if ((gtpfd = gtp_new(&gsn, args_info.statedir_arg,  &listen_)) > maxfd)
    maxfd = gtpfd;

  if ((gtpfd = gtp_fd(gsn)) > maxfd)
    maxfd = gtpfd;
    
  if (createif) 
    gtp_set_cb_gpdu(gsn, encaps_tun);
  else
    gtp_set_cb_gpdu(gsn, encaps_ping);
	
  gtp_set_cb_delete_context(gsn, delete_context);
  
  gtp_set_cb_conf(gsn, conf);
  printf("Done initialising GTP library\n\n");

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
    memcpy(pdp[n]->gsnlc.v, &listen_, 4);
    pdp[n]->gsnlu.l = 4;
    memcpy(pdp[n]->gsnlu.v, &listen_, 4);
    
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

  while ((((starttime + timelimit + 10) > time(NULL)) 
	 || (0 == timelimit)) && (state!=0)) {

    /* Take down client connections at some stage */
    if (((starttime + timelimit) <= time(NULL)) && (0 != timelimit) && (2 == state)) {
      state = 3;
      for(n=0; n<contexts; n++) {
	/* Delete context */
	printf("Disconnecting PDP context #%d\n", n);
	if (gtpfd != -1) gtp_delete_context(gsn, pdp[n], NULL);
	if ((pinghost.s_addr !=0) && ntransmitted) ping_finish();
      }
}


    /* Ping */
    while ((2 == state) && (pinghost.s_addr !=0) && 
	((pingseq < pingcount) || (pingcount == 0)) &&
	(starttime + pingseq/pingrate) <= time(NULL)) {
      create_ping(gsn, pdp[pingseq % contexts],
		  &pinghost, pingseq, pingsize);
      pingseq++;
    }

    if (ntransmitted && pingcount && nreceived >= pingcount)
      ping_finish();


    FD_ZERO(&fds);
    if (tun_fd1 != -1) FD_SET(tun_fd1, &fds);
    if (tun_fd2 != -1) FD_SET(tun_fd2, &fds);
    if (gtpfd != -1) FD_SET(gtpfd, &fds);
    
    gtp_retranstimeout(gsn, &idleTime);

    if ((pinghost.s_addr !=0) && 
	((idleTime.tv_sec !=0) || (idleTime.tv_usec !=0))) {
      idleTime.tv_sec = 0;
      idleTime.tv_usec = 1000000 / pingrate;
    }

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
      syslog(LOG_ERR, "GTP read failed (gtpfd)=(%d)", gtpfd);
    }
    
    
  }

  gtp_free(gsn); /* Clean up the gsn instance */
  
  return 0;
  
}

