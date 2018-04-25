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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

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

#if defined(__linux__)

#include <linux/ipv6.h>

static int tun_nlattr(struct nlmsghdr *n, int nsize, int type, void *d, int dlen)
{
	int len = RTA_LENGTH(dlen);
	int alen = NLMSG_ALIGN(n->nlmsg_len);
	struct rtattr *rta = (struct rtattr *)(((void *)n) + alen);
	if (alen + len > nsize)
		return -1;
	rta->rta_len = len;
	rta->rta_type = type;
	memcpy(RTA_DATA(rta), d, dlen);
	n->nlmsg_len = alen + len;
	return 0;
}
#endif

static int netdev_sifflags(const char *devname, int flags)
{
	struct ifreq ifr;
	int fd;

	memset(&ifr, '\0', sizeof(ifr));
	ifr.ifr_flags = flags;
	strncpy(ifr.ifr_name, devname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;	/* Make sure to terminate */
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "socket() failed");
		return -1;
	}
	if (ioctl(fd, SIOCSIFFLAGS, &ifr)) {
		SYS_ERR(DTUN, LOGL_ERROR, errno,
			"ioctl(SIOCSIFFLAGS) failed");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int tun_setaddr4(struct tun_t *this, struct in_addr *addr,
			struct in_addr *dstaddr, struct in_addr *netmask)
{
	struct ifreq ifr;
	int fd;

	memset(&ifr, '\0', sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	ifr.ifr_dstaddr.sa_family = AF_INET;

#if defined(__linux__)
	ifr.ifr_netmask.sa_family = AF_INET;

#elif defined(__FreeBSD__) || defined (__APPLE__)
	((struct sockaddr_in *)&ifr.ifr_addr)->sin_len =
	    sizeof(struct sockaddr_in);
	((struct sockaddr_in *)&ifr.ifr_dstaddr)->sin_len =
	    sizeof(struct sockaddr_in);
#endif

	strncpy(ifr.ifr_name, this->devname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;	/* Make sure to terminate */

	/* Create a channel to the NET kernel. */
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "socket() failed");
		return -1;
	}

	if (addr) {		/* Set the interface address */
		this->addr.s_addr = addr->s_addr;
		memcpy(&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, addr,
		       sizeof(*addr));
		if (ioctl(fd, SIOCSIFADDR, (void *)&ifr) < 0) {
			if (errno != EEXIST) {
				SYS_ERR(DTUN, LOGL_ERROR, errno,
					"ioctl(SIOCSIFADDR) failed");
			} else {
				SYS_ERR(DTUN, LOGL_NOTICE, errno,
					"ioctl(SIOCSIFADDR): Address already exists");
			}
			close(fd);
			return -1;
		}
	}

	if (dstaddr) {		/* Set the destination address */
		this->dstaddr.s_addr = dstaddr->s_addr;
		memcpy(&((struct sockaddr_in *)&ifr.ifr_dstaddr)->sin_addr,
		       dstaddr, sizeof(*dstaddr));
		if (ioctl(fd, SIOCSIFDSTADDR, (caddr_t) & ifr) < 0) {
			SYS_ERR(DTUN, LOGL_ERROR, errno,
				"ioctl(SIOCSIFDSTADDR) failed");
			close(fd);
			return -1;
		}
	}

	if (netmask) {		/* Set the netmask */
		this->netmask.s_addr = netmask->s_addr;
#if defined(__linux__)
		memcpy(&((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr,
		       netmask, sizeof(*netmask));

#elif defined(__FreeBSD__) || defined (__APPLE__)
		((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr =
		    netmask->s_addr;
#endif

		if (ioctl(fd, SIOCSIFNETMASK, (void *)&ifr) < 0) {
			SYS_ERR(DTUN, LOGL_ERROR, errno,
				"ioctl(SIOCSIFNETMASK) failed");
			close(fd);
			return -1;
		}
	}

	close(fd);
	this->addrs++;

	/* On linux the route to the interface is set automatically
	   on FreeBSD we have to do this manually */

	/* TODO: How does it work on Solaris? */

	netdev_sifflags(this->devname, IFF_UP | IFF_RUNNING);

#if defined(__FreeBSD__) || defined (__APPLE__)
	tun_addroute(this, dstaddr, addr, &this->netmask);
	this->routes = 1;
#endif

	return 0;
}

static int tun_setaddr6(struct tun_t *this, struct in6_addr *addr, struct in6_addr *dstaddr,
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

	netdev_sifflags(this->devname, IFF_UP | IFF_RUNNING);

#if 0	/* FIXME */
//#if defined(__FreeBSD__) || defined (__APPLE__)
	tun_addroute6(this, dstaddr, addr, prefixlen);
	this->routes = 1;
#endif

	return 0;
}

int tun_setaddr(struct tun_t *this, struct in46_addr *addr, struct in46_addr *dstaddr, size_t prefixlen)
{
	struct in_addr netmask;
	switch (addr->len) {
	case 4:
		netmask.s_addr = htonl(0xffffffff << (32 - prefixlen));
		return tun_setaddr4(this, &addr->v4, dstaddr ? &dstaddr->v4 : NULL, &netmask);
	case 16:
		return tun_setaddr6(this, &addr->v6, dstaddr ? &dstaddr->v6 : NULL, prefixlen);
	default:
		return -1;
	}
}

static int tun_addaddr4(struct tun_t *this,
		struct in_addr *addr,
		struct in_addr *dstaddr, struct in_addr *netmask)
{

#if defined(__linux__)
	struct {
		struct nlmsghdr n;
		struct ifaddrmsg i;
		char buf[TUN_NLBUFSIZE];
	} req;

	struct sockaddr_nl local;
	socklen_t addr_len;
	int fd;
	int status;

	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg;

	if (!this->addrs)	/* Use ioctl for first addr to make ping work */
		return tun_setaddr4(this, addr, dstaddr, netmask);

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWADDR;
	req.i.ifa_family = AF_INET;
	req.i.ifa_prefixlen = 32;	/* 32 FOR IPv4 */
	req.i.ifa_flags = 0;
	req.i.ifa_scope = RT_SCOPE_HOST;	/* TODO or 0 */
	req.i.ifa_index = if_nametoindex(this->devname);
	if (!req.i.ifa_index) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "Unable to get ifindex for %s", this->devname);
		return -1;
	}

	tun_nlattr(&req.n, sizeof(req), IFA_ADDRESS, addr, sizeof(*addr));
	if (dstaddr)
		tun_nlattr(&req.n, sizeof(req), IFA_LOCAL, dstaddr, sizeof(*dstaddr));

	if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "socket() failed");
		return -1;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = 0;

	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "bind() failed");
		close(fd);
		return -1;
	}

	addr_len = sizeof(local);
	if (getsockname(fd, (struct sockaddr *)&local, &addr_len) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno,
			"getsockname() failed");
		close(fd);
		return -1;
	}

	if (addr_len != sizeof(local)) {
		SYS_ERR(DTUN, LOGL_ERROR, 0,
			"Wrong address length %d", addr_len);
		close(fd);
		return -1;
	}

	if (local.nl_family != AF_NETLINK) {
		SYS_ERR(DTUN, LOGL_ERROR, 0,
			"Wrong address family %d", local.nl_family);
		close(fd);
		return -1;
	}

	iov.iov_base = (void *)&req.n;
	iov.iov_len = req.n.nlmsg_len;

	msg.msg_name = (void *)&nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	req.n.nlmsg_seq = 0;
	req.n.nlmsg_flags |= NLM_F_ACK;

	status = sendmsg(fd, &msg, 0);
	if (status != req.n.nlmsg_len) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "sendmsg() failed, returned %d", status);
		close(fd);
		return -1;
	}

	status = netdev_sifflags(this->devname, IFF_UP | IFF_RUNNING);
	if (status == -1) {
		close(fd);
		return -1;
	}


	close(fd);
	this->addrs++;
	return 0;

#elif defined (__FreeBSD__) || defined (__APPLE__)

	int fd;
	struct ifaliasreq areq;

	/* TODO: Is this needed on FreeBSD? */
	if (!this->addrs)	/* Use ioctl for first addr to make ping work */
		return tun_setaddr4(this, addr, dstaddr, netmask);	/* TODO dstaddr */

	memset(&areq, 0, sizeof(areq));

	/* Set up interface name */
	strncpy(areq.ifra_name, this->devname, IFNAMSIZ);
	areq.ifra_name[IFNAMSIZ - 1] = 0;	/* Make sure to terminate */

	((struct sockaddr_in *)&areq.ifra_addr)->sin_family = AF_INET;
	((struct sockaddr_in *)&areq.ifra_addr)->sin_len =
	    sizeof(areq.ifra_addr);
	((struct sockaddr_in *)&areq.ifra_addr)->sin_addr.s_addr = addr->s_addr;

	((struct sockaddr_in *)&areq.ifra_mask)->sin_family = AF_INET;
	((struct sockaddr_in *)&areq.ifra_mask)->sin_len =
	    sizeof(areq.ifra_mask);
	((struct sockaddr_in *)&areq.ifra_mask)->sin_addr.s_addr =
	    netmask->s_addr;

	/* For some reason FreeBSD uses ifra_broadcast for specifying dstaddr */
	((struct sockaddr_in *)&areq.ifra_broadaddr)->sin_family = AF_INET;
	((struct sockaddr_in *)&areq.ifra_broadaddr)->sin_len =
	    sizeof(areq.ifra_broadaddr);
	((struct sockaddr_in *)&areq.ifra_broadaddr)->sin_addr.s_addr =
	    dstaddr->s_addr;

	/* Create a channel to the NET kernel. */
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "socket() failed");
		return -1;
	}

	if (ioctl(fd, SIOCAIFADDR, (void *)&areq) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno,
			"ioctl(SIOCAIFADDR) failed");
		close(fd);
		return -1;
	}

	close(fd);
	this->addrs++;
	return 0;

#endif

}

static int tun_addaddr6(struct tun_t *this,
		struct in6_addr *addr,
		struct in6_addr *dstaddr, int prefixlen)
{

#if defined(__linux__)
	struct {
		struct nlmsghdr n;
		struct ifaddrmsg i;
		char buf[TUN_NLBUFSIZE];
	} req;

	struct sockaddr_nl local;
	socklen_t addr_len;
	int fd;
	int status;

	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg;

	if (!this->addrs)	/* Use ioctl for first addr to make ping work */
		return tun_setaddr6(this, addr, dstaddr, prefixlen);

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWADDR;
	req.i.ifa_family = AF_INET6;
	req.i.ifa_prefixlen = 64;	/* 64 FOR IPv6 */
	req.i.ifa_flags = 0;
	req.i.ifa_scope = RT_SCOPE_HOST;	/* TODO or 0 */
	req.i.ifa_index = if_nametoindex(this->devname);
	if (!req.i.ifa_index) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "Unable to get ifindex for %s", this->devname);
		return -1;
	}

	tun_nlattr(&req.n, sizeof(req), IFA_ADDRESS, addr, sizeof(*addr));
	if (dstaddr)
		tun_nlattr(&req.n, sizeof(req), IFA_LOCAL, dstaddr, sizeof(*dstaddr));

	if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "socket() failed");
		return -1;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = 0;

	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "bind() failed");
		close(fd);
		return -1;
	}

	addr_len = sizeof(local);
	if (getsockname(fd, (struct sockaddr *)&local, &addr_len) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno,
			"getsockname() failed");
		close(fd);
		return -1;
	}

	if (addr_len != sizeof(local)) {
		SYS_ERR(DTUN, LOGL_ERROR, 0,
			"Wrong address length %d", addr_len);
		close(fd);
		return -1;
	}

	if (local.nl_family != AF_NETLINK) {
		SYS_ERR(DTUN, LOGL_ERROR, 0,
			"Wrong address family %d", local.nl_family);
		close(fd);
		return -1;
	}

	iov.iov_base = (void *)&req.n;
	iov.iov_len = req.n.nlmsg_len;

	msg.msg_name = (void *)&nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	req.n.nlmsg_seq = 0;
	req.n.nlmsg_flags |= NLM_F_ACK;

	status = sendmsg(fd, &msg, 0);
	if (status != req.n.nlmsg_len) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "sendmsg() failed, returned %d", status);
		close(fd);
		return -1;
	}

	status = netdev_sifflags(this->devname, IFF_UP | IFF_RUNNING);
	if (status == -1) {
		close(fd);
		return -1;
	}


	close(fd);
	this->addrs++;
	return 0;

#elif defined (__FreeBSD__) || defined (__APPLE__)

	int fd;
	struct ifaliasreq areq;

	/* TODO: Is this needed on FreeBSD? */
	if (!this->addrs)	/* Use ioctl for first addr to make ping work */
		return tun_setaddr6(this, addr, dstaddr, netmask);	/* TODO dstaddr */

	memset(&areq, 0, sizeof(areq));

	/* Set up interface name */
	strncpy(areq.ifra_name, this->devname, IFNAMSIZ);
	areq.ifra_name[IFNAMSIZ - 1] = 0;	/* Make sure to terminate */

	((struct sockaddr_in6 *)&areq.ifra_addr)->sin6_family = AF_INET6;
	((struct sockaddr_in6 *)&areq.ifra_addr)->sin6_len = sizeof(areq.ifra_addr);
	((struct sockaddr_in6 *)&areq.ifra_addr)->sin6_addr.s6_addr = addr->s6_addr;

	((struct sockaddr_in6 *)&areq.ifra_mask)->sin6_family = AF_INET6;
	((struct sockaddr_in6 *)&areq.ifra_mask)->sin6_len = sizeof(areq.ifra_mask);
	((struct sockaddr_in6 *)&areq.ifra_mask)->sin6_addr.s6_addr = netmask->s6_addr;

	/* For some reason FreeBSD uses ifra_broadcast for specifying dstaddr */
	((struct sockaddr_in6 *)&areq.ifra_broadaddr)->sin6_family = AF_INET6;
	((struct sockaddr_in6 *)&areq.ifra_broadaddr)->sin6_len = sizeof(areq.ifra_broadaddr);
	((struct sockaddr_in6 *)&areq.ifra_broadaddr)->sin6_addr.s6_addr = dstaddr->s6_addr;

	/* Create a channel to the NET kernel. */
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "socket() failed");
		return -1;
	}

	if (ioctl(fd, SIOCAIFADDR, (void *)&areq) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno,
			"ioctl(SIOCAIFADDR) failed");
		close(fd);
		return -1;
	}

	close(fd);
	this->addrs++;
	return 0;

#endif

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

static int tun_route(struct tun_t *this,
	      struct in_addr *dst,
	      struct in_addr *gateway, struct in_addr *mask, int delete)
{

#if defined(__linux__)

	struct rtentry r;
	int fd;

	memset(&r, '\0', sizeof(r));
	r.rt_flags = RTF_UP | RTF_GATEWAY;	/* RTF_HOST not set */

	/* Create a channel to the NET kernel. */
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "socket() failed");
		return -1;
	}

	r.rt_dst.sa_family = AF_INET;
	r.rt_gateway.sa_family = AF_INET;
	r.rt_genmask.sa_family = AF_INET;
	memcpy(&((struct sockaddr_in *)&r.rt_dst)->sin_addr, dst, sizeof(*dst));
	memcpy(&((struct sockaddr_in *)&r.rt_gateway)->sin_addr, gateway,
	       sizeof(*gateway));
	memcpy(&((struct sockaddr_in *)&r.rt_genmask)->sin_addr, mask,
	       sizeof(*mask));

	if (delete) {
		if (ioctl(fd, SIOCDELRT, (void *)&r) < 0) {
			SYS_ERR(DTUN, LOGL_ERROR, errno,
				"ioctl(SIOCDELRT) failed");
			close(fd);
			return -1;
		}
	} else {
		if (ioctl(fd, SIOCADDRT, (void *)&r) < 0) {
			SYS_ERR(DTUN, LOGL_ERROR, errno,
				"ioctl(SIOCADDRT) failed");
			close(fd);
			return -1;
		}
	}
	close(fd);
	return 0;

#elif defined(__FreeBSD__) || defined (__APPLE__)

	struct {
		struct rt_msghdr rt;
		struct sockaddr_in dst;
		struct sockaddr_in gate;
		struct sockaddr_in mask;
	} req;

	int fd;
	struct rt_msghdr *rtm;

	if ((fd = socket(AF_ROUTE, SOCK_RAW, 0)) == -1) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "socket() failed");
		return -1;
	}

	memset(&req, 0x00, sizeof(req));

	rtm = &req.rt;

	rtm->rtm_msglen = sizeof(req);
	rtm->rtm_version = RTM_VERSION;
	if (delete) {
		rtm->rtm_type = RTM_DELETE;
	} else {
		rtm->rtm_type = RTM_ADD;
	}
	rtm->rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;	/* TODO */
	rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	rtm->rtm_pid = getpid();
	rtm->rtm_seq = 0044;	/* TODO */

	req.dst.sin_family = AF_INET;
	req.dst.sin_len = sizeof(req.dst);
	req.mask.sin_family = AF_INET;
	req.mask.sin_len = sizeof(req.mask);
	req.gate.sin_family = AF_INET;
	req.gate.sin_len = sizeof(req.gate);

	req.dst.sin_addr.s_addr = dst->s_addr;
	req.mask.sin_addr.s_addr = mask->s_addr;
	req.gate.sin_addr.s_addr = gateway->s_addr;

	if (write(fd, rtm, rtm->rtm_msglen) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "write() failed");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
#endif

}

int tun_addroute(struct tun_t *this,
		 struct in_addr *dst,
		 struct in_addr *gateway, struct in_addr *mask)
{
	return tun_route(this, dst, gateway, mask, 0);
}

int tun_delroute(struct tun_t *this,
		 struct in_addr *dst,
		 struct in_addr *gateway, struct in_addr *mask)
{
	return tun_route(this, dst, gateway, mask, 1);
}

int tun_new(struct tun_t **tun, const char *dev_name)
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

	ioctl((*tun)->fd, TUNSETNOCSUM, 1);	/* Disable checksums */
	return 0;

#elif defined(__FreeBSD__) || defined (__APPLE__)

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
		tun_delroute(tun, &tun->dstaddr, &tun->addr, &tun->netmask);
	}

	if (close(tun->fd)) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "close() failed");
	}

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

	strncpy(snet, inet_ntoa(tun->addr), sizeof(snet));
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

#include <ifaddrs.h>

/*! Obtain the local address of a network device
 *  \param[in] devname Target device owning the IP
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
int netdev_ip_local_get(const char *devname, struct in46_prefix *prefix_list, size_t prefix_size, int flags)
{
	static const uint8_t ll_prefix[] = { 0xfe,0x80, 0,0, 0,0, 0,0 };
	struct ifaddrs *ifaddr, *ifa;
	struct in46_addr netmask;
	size_t count = 0;
	bool is_ipv6_ll;

	if (getifaddrs(&ifaddr) == -1) {
		return -1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		if (strcmp(ifa->ifa_name, devname))
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET && (flags & IP_TYPE_IPv4)) {
			struct sockaddr_in *sin4 = (struct sockaddr_in *) ifa->ifa_addr;
			struct sockaddr_in *netmask4 = (struct sockaddr_in *) ifa->ifa_netmask;

			if (count < prefix_size) {
				netmask.len = sizeof(netmask4->sin_addr);
				netmask.v4 = netmask4->sin_addr;
				prefix_list[count].addr.len = sizeof(sin4->sin_addr);
				prefix_list[count].addr.v4 = sin4->sin_addr;
				prefix_list[count].prefixlen = in46a_netmasklen(&netmask);
			}
			count++;
		}

		if (ifa->ifa_addr->sa_family == AF_INET6 && (flags & IP_TYPE_IPv6)) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) ifa->ifa_addr;
			struct sockaddr_in6 *netmask6 = (struct sockaddr_in6 *) ifa->ifa_netmask;

			is_ipv6_ll = !memcmp(sin6->sin6_addr.s6_addr, ll_prefix, sizeof(ll_prefix));
			if ((flags & IP_TYPE_IPv6_NONLINK) && is_ipv6_ll)
				continue;
			if ((flags & IP_TYPE_IPv6_LINK) && !is_ipv6_ll)
				continue;

			if (count < prefix_size) {
				netmask.len = sizeof(netmask6->sin6_addr);
				netmask.v6 = netmask6->sin6_addr;
				prefix_list[count].addr.len = sizeof(sin6->sin6_addr);
				prefix_list[count].addr.v6 = sin6->sin6_addr;
				prefix_list[count].prefixlen = in46a_netmasklen(&netmask);
			}
			count++;
		}
	}

	freeifaddrs(ifaddr);
	return count;
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
