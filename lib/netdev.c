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
 * netdev.c: Contains generic network device related functionality.
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

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "netdev.h"
#include "syserr.h"

#include <linux/ipv6.h>

static int netdev_route4(struct in_addr *dst, struct in_addr *gateway, struct in_addr *mask, int delete)
{
	int fd;
#if defined(__linux__)
	struct rtentry r;

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
#elif defined(__FreeBSD__) || defined (__APPLE__)
	struct {
		struct rt_msghdr rt;
		struct sockaddr_in dst;
		struct sockaddr_in gate;
		struct sockaddr_in mask;
	} req;
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
#endif
	close(fd);
	return 0;
}

static int netdev_route6(struct in6_addr *dst, struct in6_addr *gateway, int prefixlen, const char *gw_iface, int delete)
{
	int fd;
#if defined(__linux__)
	struct in6_rtmsg r;
	struct ifreq ifr;

	memset(&r, 0, sizeof(r));
	r.rtmsg_flags = RTF_UP | RTF_GATEWAY; /* RTF_HOST not set */
	r.rtmsg_metric = 1;

	/* Create a channel to the NET kernel. */
	if ((fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "socket() failed");
		return -1;
	}

	if (gw_iface) {
		strncpy(ifr.ifr_name, gw_iface, IFNAMSIZ);
		ifr.ifr_name[IFNAMSIZ - 1] = 0; /* Make sure to terminate */
		if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
			SYS_ERR(DTUN, LOGL_ERROR, errno,
				"ioctl(SIOCGIFINDEX) failed");
			close(fd);
			return -1;
		}
		r.rtmsg_ifindex = ifr.ifr_ifindex;
	}

	memcpy(&r.rtmsg_dst, dst->s6_addr, sizeof(struct in6_addr));
	memcpy(&r.rtmsg_gateway, gateway->s6_addr, sizeof(struct in6_addr));
	r.rtmsg_dst_len = prefixlen;

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
#endif
	return 0;
}

int netdev_addroute4(struct in_addr *dst, struct in_addr *gateway, struct in_addr *mask)
{
	return netdev_route4(dst, gateway, mask, 0);
}

int netdev_delroute4(struct in_addr *dst, struct in_addr *gateway, struct in_addr *mask)
{
	return netdev_route4(dst, gateway, mask, 1);
}

int netdev_addroute6(struct in6_addr *dst, struct in6_addr *gateway, int prefixlen, const char *gw_iface)
{
	return netdev_route6(dst, gateway, prefixlen, gw_iface, 0);
}

int netdev_delroute6(struct in6_addr *dst, struct in6_addr *gateway, int prefixlen, const char *gw_iface)
{
	return netdev_route6(dst, gateway, prefixlen, gw_iface, 1);
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
