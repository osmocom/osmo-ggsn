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

#ifndef _TUN_H
#define _TUN_H

#define hton8(x)  (x)
#define ntoh8(x)  (x)
#define hton16(x) htons(x)
#define ntoh16(x) ntohs(x)
#define hton32(x) htonl(x)
#define ntoh32(x) ntohl(x)

#define PACKET_MAX      8196 /* TODO */

/* ***********************************************************
 * Information storage for each tun instance
 *************************************************************/

struct tun_t {
  int fd;                /* File descriptor to network interface */
  struct in_addr addr;   /* IP address of tun interface */
  char devname[IFNAMSIZ];/* Name of the tun device */
};


extern int tun_newtun(struct tun_t **tun);
extern int tun_freetun(struct tun_t *tun);
extern int tun_decaps(struct tun_t *tun, 
     int (*cb) (void *cl, struct tun_t*, void *pack, unsigned len),
		      void *cl);
extern int tun_encaps(struct tun_t *tun, void *pack, unsigned len);


#endif	/* !_TUN_H */
