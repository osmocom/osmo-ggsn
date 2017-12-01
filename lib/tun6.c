#include <unistd.h>
#include <string.h>
#include <stropts.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/ipv6.h>

#include "tun.h"
#include "syserr.h"

/* Defined in tun.c */
int tun_sifflags(struct tun_t *this, int flags);

int tun_setaddr6(struct tun_t *this, struct in6_addr *addr, struct in6_addr *dstaddr,
			size_t prefixlen)
{
	struct in6_ifreq ifr;
	int fd;

	memset(&ifr, 0, sizeof(ifr));

#if defined(__linux__)
	ifr.ifr6_prefixlen = prefixlen;
	ifr.ifr6_ifindex = if_nametoindex(this->devname);
	if (ifr.ifr6_ifindex == 0) {
		SYS_ERR(DTUN, LOGL_ERROR, 0, "Error getting ifindex for %s\n", this->devname);
		return -1;
	}
#elif defined(__FreeBSD__) || defined (__APPLE__)
	strncpy(ifr.ifr_name, this->devname, IFNAMSIZ);
#endif

	/* Create a channel to the NET kernel */
	if ((fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, 0, "socket() failed");
		return -1;
	}

#if defined(__linux__)
	if (addr) {
		memcpy(&ifr.ifr6_addr, addr, sizeof(*addr));
		if (ioctl(fd, SIOCSIFADDR, (void *) &ifr) < 0) {
			if (errno != EEXIST) {
				SYS_ERR(DTUN, LOGL_ERROR, 0, "ioctl(SIOCSIFADDR) failed");
			} else {
				SYS_ERR(DTUN, LOGL_NOTICE, 0, "ioctl(SIOCSIFADDR): Address already exists");
			}
			close(fd);
			return -1;
		}
	}

#if 0
	/* FIXME: looks like this is not possible/necessary for IPv6? */
	if (dstaddr) {
		memcpy(&this->dstaddr, dstaddr, sizeof(*dstaddr));
		memcpy(&ifr.ifr6_addr, dstaddr, sizeof(*dstaddr));
		if (ioctl(fd, SIOCSIFDSTADDR, (caddr_t *) &ifr) < 0) {
			SYS_ERR(DTUN, LOGL_ERROR, "ioctl(SIOCSIFDSTADDR) failed");
			close(fd);
			return -1;
		}
	}
#endif

#elif defined(__FreeBSD__) || defined (__APPLE__)
	if (addr)
		memcpy(&ifr.ifr_ifru.ifru_addr, addr, sizeof(ifr.ifr_ifru.ifru_addr));
	if (dstaddr)
		memcpy(&ifr.ifr_ifru.ifru_dstaddr, dstaddr, sizeof(ifr.ifr_ifru.ifru_dstaddr));

	if (ioctl(fd, SIOCSIFADDR_IN6, (struct ifreq *)&ifr) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, 0, "ioctl(SIOCSIFADDR_IN6) failed");
		close(fd);
		return -1;
	}
#endif

	close(fd);
	this->addrs++;

	/* On linux the route to the interface is set automatically
	   on FreeBSD we have to do this manually */

	/* TODO: How does it work on Solaris? */

	tun_sifflags(this, IFF_UP | IFF_RUNNING);

#if 0	/* FIXME */
//#if defined(__FreeBSD__) || defined (__APPLE__)
	tun_addroute6(this, dstaddr, addr, prefixlen);
	this->routes = 1;
#endif

	return 0;
}
