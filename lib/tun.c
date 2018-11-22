/*
 * TUN interface functions.
 * Copyright (C) 2002, 2003, 2004 Mondru AB.
 * Copyright (C) 2017-2018 by Harald Welte <laforge@gnumonks.org>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

/*
 * tun.c: Contains all TUN functionality. Is able to handle multiple
 * tunnels in the same program. Each tunnel is identified by the struct,
 * which is passed to functions.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <errno.h>
#include <net/route.h>
#include <net/if.h>

#if defined(__linux__)
#include <linux/if_tun.h>

#elif defined (__FreeBSD__)
#include <net/if_tun.h>
#include <net/if_var.h>
#include <netinet/in_var.h>

#elif defined (__APPLE__)
#include <net/if.h>

#else
#error  "Unknown platform!"
#endif

#include "tun.h"
#include "syserr.h"
#include "gtp-kernel.h"

static int tun_setaddr4(struct tun_t *this, struct in_addr *addr,
			struct in_addr *dstaddr, struct in_addr *netmask)
{
	int rc;
	rc = netdev_setaddr4(this->devname, addr, dstaddr, netmask);
	if (rc < 0)
		return rc;

	if (addr) {
		this->addr.len = sizeof(struct in_addr);
		this->addr.v4.s_addr = addr->s_addr;
	}
	if (dstaddr) {
		this->dstaddr.len = sizeof(struct in_addr);
		this->dstaddr.v4.s_addr = dstaddr->s_addr;
	}
	if (netmask)
		this->netmask.s_addr = netmask->s_addr;
	this->addrs++;
#if defined(__FreeBSD__) || defined (__APPLE__)
	this->routes = 1;
#endif

	return rc;
}

static int tun_setaddr6(struct tun_t *this, struct in6_addr *addr, struct in6_addr *dstaddr,
			size_t prefixlen)
{
	int rc;
	rc = netdev_setaddr6(this->devname, addr, dstaddr, prefixlen);
	if (rc < 0)
		return rc;
	if (dstaddr) {
		this->dstaddr.len = sizeof(*dstaddr);
		memcpy(&this->dstaddr.v6, dstaddr, sizeof(*dstaddr));
	}
	this->addrs++;
#if defined(__FreeBSD__) || defined (__APPLE__)
	this->routes = 1;
#endif

	return rc;
}

static int tun_addaddr4(struct tun_t *this, struct in_addr *addr,
			struct in_addr *dstaddr, struct in_addr *netmask)
{
	int rc;

	/* TODO: Is this needed on FreeBSD? */
	if (!this->addrs)	/* Use ioctl for first addr to make ping work */
		return tun_setaddr4(this, addr, dstaddr, netmask);	/* TODO dstaddr */

	rc = netdev_addaddr4(this->devname, addr, dstaddr, netmask);
	if (rc < 0)
		return rc;

	this->addrs++;

	return rc;
}

static int tun_addaddr6(struct tun_t *this,
		struct in6_addr *addr,
		struct in6_addr *dstaddr, int prefixlen)
{
	int rc;

	if (!this->addrs)	/* Use ioctl for first addr to make ping work */
		return tun_setaddr6(this, addr, dstaddr, prefixlen);

	rc = netdev_addaddr6(this->devname, addr, dstaddr, prefixlen);
	if (rc < 0)
		return rc;

	this->addrs++;

	return rc;
}

int tun_addaddr(struct tun_t *this, struct in46_addr *addr, struct in46_addr *dstaddr, size_t prefixlen)
{
	struct in_addr netmask;
	switch (addr->len) {
	case 4:
		netmask.s_addr = htonl(0xffffffff << (32 - prefixlen));
		return tun_addaddr4(this, &addr->v4, dstaddr ? &dstaddr->v4 : NULL, &netmask);
	case 16:
		return tun_addaddr6(this, &addr->v6, dstaddr ? &dstaddr->v6 : NULL, prefixlen);
	default:
		return -1;
	}
}

int tun_new(struct tun_t **tun, const char *dev_name, bool use_kernel, int fd0, int fd1u)
{

#if defined(__linux__)
	struct ifreq ifr;

#elif defined(__FreeBSD__) || defined (__APPLE__)
	char devname[IFNAMSIZ + 5];	/* "/dev/" + ifname */
	int devnum;
	struct ifaliasreq areq;
	int fd;
#endif

	if (!(*tun = calloc(1, sizeof(struct tun_t)))) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "calloc() failed");
		return EOF;
	}

	(*tun)->cb_ind = NULL;
	(*tun)->addrs = 0;
	(*tun)->routes = 0;

#if defined(__linux__)
	if (!use_kernel) {
		/* Open the actual tun device */
		if (((*tun)->fd = open("/dev/net/tun", O_RDWR)) < 0) {
			SYS_ERR(DTUN, LOGL_ERROR, errno, "open() failed");
			goto err_free;
		}

		/* Set device flags. For some weird reason this is also the method
		   used to obtain the network interface name */
		memset(&ifr, 0, sizeof(ifr));
		if (dev_name)
			strcpy(ifr.ifr_name, dev_name);
		ifr.ifr_flags = IFF_TUN | IFF_NO_PI;	/* Tun device, no packet info */
		if (ioctl((*tun)->fd, TUNSETIFF, (void *)&ifr) < 0) {
			SYS_ERR(DTUN, LOGL_ERROR, errno, "ioctl() failed");
			goto err_close;
		}

		strncpy((*tun)->devname, ifr.ifr_name, IFNAMSIZ);
		(*tun)->devname[IFNAMSIZ - 1] = 0;

		/* Disable checksums */
		if (ioctl((*tun)->fd, TUNSETNOCSUM, 1) < 0) {
			SYS_ERR(DTUN, LOGL_NOTICE, errno, "could not disable checksum on %s", (*tun)->devname);
		}
		return 0;
	} else {
		strncpy((*tun)->devname, dev_name, IFNAMSIZ);
		(*tun)->devname[IFNAMSIZ - 1] = 0;
		(*tun)->fd = -1;

		if (gtp_kernel_create(-1, dev_name, fd0, fd1u) < 0) {
			LOGP(DTUN, LOGL_ERROR, "cannot create GTP tunnel device: %s\n",
				strerror(errno));
			return -1;
		}
		LOGP(DTUN, LOGL_NOTICE, "GTP kernel configured\n");
		return 0;
	}

#elif defined(__FreeBSD__) || defined (__APPLE__)

	if (use_kernel) {
		LOGP(DTUN, LOGL_ERROR, "No kernel GTP-U support in FreeBSD!\n");
		return -1;
	}

	/* Find suitable device */
	for (devnum = 0; devnum < 255; devnum++) {	/* TODO 255 */
		snprintf(devname, sizeof(devname), "/dev/tun%d", devnum);
		if (((*tun)->fd = open(devname, O_RDWR)) >= 0)
			break;
		if (errno != EBUSY)
			break;
	}
	if ((*tun)->fd < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno,
			"Can't find tunnel device");
		goto err_free;
	}

	snprintf((*tun)->devname, sizeof((*tun)->devname), "tun%d", devnum);
	(*tun)->devname[sizeof((*tun)->devname)-1] = 0;

	/* The tun device we found might have "old" IP addresses allocated */
	/* We need to delete those. This problem is not present on Linux */

	memset(&areq, 0, sizeof(areq));

	/* Set up interface name */
	strncpy(areq.ifra_name, (*tun)->devname, IFNAMSIZ);
	areq.ifra_name[IFNAMSIZ - 1] = 0;	/* Make sure to terminate */

	/* Create a channel to the NET kernel. */
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "socket() failed");
		goto err_close;
	}

	/* Delete any IP addresses until SIOCDIFADDR fails */
	while (ioctl(fd, SIOCDIFADDR, (void *)&areq) != -1) ;

	close(fd);
	return 0;
#endif

err_close:
	close((*tun)->fd);
err_free:
	free(*tun);
	*tun = NULL;
	return -1;
}

int tun_free(struct tun_t *tun)
{

	if (tun->routes) {
		netdev_delroute(&tun->dstaddr.v4, &tun->addr.v4, &tun->netmask);
	}

	if (tun->fd >= 0) {
		if (close(tun->fd)) {
			SYS_ERR(DTUN, LOGL_ERROR, errno, "close() failed");
		}
	}

	gtp_kernel_stop(tun->devname);

	/* TODO: For solaris we need to unlink streams */

	free(tun);
	return 0;
}

int tun_set_cb_ind(struct tun_t *this,
		   int (*cb_ind) (struct tun_t * tun, void *pack, unsigned len))
{
	this->cb_ind = cb_ind;
	return 0;
}

int tun_decaps(struct tun_t *this)
{
	unsigned char buffer[PACKET_MAX];
	int status;

	if ((status = read(this->fd, buffer, sizeof(buffer))) <= 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "read() failed");
		return -1;
	}

	if (this->cb_ind)
		return this->cb_ind(this, buffer, status);

	return 0;
}

int tun_encaps(struct tun_t *tun, void *pack, unsigned len)
{
	return write(tun->fd, pack, len);
}

int tun_runscript(struct tun_t *tun, char *script)
{

	char buf[TUN_SCRIPTSIZE];
	char snet[TUN_ADDRSIZE];
	char smask[TUN_ADDRSIZE];
	int rc;

	strncpy(snet, inet_ntoa(tun->addr.v4), sizeof(snet));
	snet[sizeof(snet) - 1] = 0;
	strncpy(smask, inet_ntoa(tun->netmask), sizeof(smask));
	smask[sizeof(smask) - 1] = 0;

	/* system("ipup /dev/tun0 192.168.0.10 255.255.255.0"); */
	snprintf(buf, sizeof(buf), "%s %s %s %s",
		 script, tun->devname, snet, smask);
	buf[sizeof(buf) - 1] = 0;
	rc = system(buf);
	if (rc == -1) {
		SYS_ERR(DTUN, LOGL_ERROR, errno,
			"Error executing command %s", buf);
		return -1;
	}
	return 0;
}

/*! Obtain the local address of the tun device.
 *  \param[in] tun Target device owning the IP
 *  \param[out] prefix_list List of prefix structures to fill with each IPv4/6 and prefix length found.
 *  \param[in] prefix_size Amount of elements allowed to be fill in the prefix_list array.
 *  \param[in] flags Specify which kind of IP to look for: IP_TYPE_IPv4, IP_TYPE_IPv6_LINK, IP_TYPE_IPv6_NONLINK
 *  \returns The number of ips found following the criteria specified by flags, -1 on error.
 *
 * This function will fill prefix_list with up to prefix_size IPs following the
 * criteria specified by flags parameter. It returns the number of IPs matching
 * the criteria. As a result, the number returned can be bigger than
 * prefix_size. It can be used with prefix_size=0 to get an estimate of the size
 * needed for prefix_list.
 */
int tun_ip_local_get(const struct tun_t *tun, struct in46_prefix *prefix_list, size_t prefix_size, int flags)
{
	return netdev_ip_local_get(tun->devname, prefix_list, prefix_size, flags);
}
