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
 * tun.c: Contains all TUN functionality. Should be able to handle multiple
 * tunnels in the same program. Each tunnel is identified by the socket. 
 * I suppose that no other state information than the socket is needed.
 *
 *  - tun_newtun: Initialise TUN tunnel.
 *  - tun_freetun: Free a device previously created with tun_newtun.
 *  - tun_encaps: Encapsulate packet in TUN tunnel and send off
 *  - tun_decaps: Extract packet from TUN tunnel and call function to
 *    ship it off as GTP encapsulated packet. 
 *
 * TODO:
 *  - Do we need to handle fragmentation?
 */


#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <errno.h>
#include <linux/if_tun.h>


#include "tun.h"


int tun_newtun(struct tun_t **tun)
{
  struct ifreq ifr;

  if (!(*tun = calloc(1, sizeof(struct tun_t)))) {
    syslog(LOG_ERR, "%s %d. calloc(nmemb=%d, size=%d) failed: Error = %s(%d)",
	   __FILE__, __LINE__, 1, sizeof(struct tun_t), 
	   strerror(errno), errno);
    return EOF;
  }

  if (((*tun)->fd  = open("/dev/net/tun", O_RDWR)) < 0) {
    syslog(LOG_ERR, "TUN: open() failed");
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* Tun device, no packet info */
  strncpy(ifr.ifr_name, (*tun)->devname, IFNAMSIZ);

  if (ioctl((*tun)->fd, TUNSETIFF, (void *) &ifr) < 0) {
    syslog(LOG_ERR, "TUN: ioctl() failed");
    close((*tun)->fd);
    return -1;
  } 

  ioctl((*tun)->fd, TUNSETNOCSUM, 1); /* Disable checksums */

  strncpy((*tun)->devname, ifr.ifr_name, IFNAMSIZ);

  return (*tun)->fd;
}

int tun_freetun(struct tun_t *tun)
{
  if (close(tun->fd)) {
    syslog(LOG_ERR, "%s %d. close(fd=%d) failed: Error = %s", 
	   __FILE__, __LINE__, tun->fd, strerror(errno));
    return EOF;
  }
  free(tun);
  return 0;
}


int tun_decaps(struct tun_t *tun, 
	       int (*cb) (void *cl, struct tun_t*, void *pack, unsigned len),
	       void *cl)
{
	unsigned char buffer[PACKET_MAX + 64 /*TODO: ip header */ ];
	int status;


	if ((status = read(tun->fd, buffer, sizeof(buffer))) <= 0) {
		syslog(LOG_ERR, "TUN: read(fd=%d,buffer=%lx,len=%d) from network failed: status = %d error = %s",
		       tun->fd, (unsigned long) buffer, sizeof(buffer), status, status ? strerror(errno) : "No error");
		return -1;
	}

	/* Need to include code to verify packet src and dest addresses */
	return cb(cl, tun, buffer, status);
}

int tun_encaps(struct tun_t *tun, void *pack, unsigned len)
{
	return write(tun->fd, pack, len);
}
