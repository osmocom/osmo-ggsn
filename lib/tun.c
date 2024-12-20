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

#include <linux/if_tun.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>

#include "tun.h"
#include "syserr.h"
#include "gtp-kernel.h"

int tun_addaddr(struct tun_t *this, struct in46_addr *addr, size_t prefixlen)
{
	struct osmo_sockaddr osa = {0};
	int rc;
	OSMO_ASSERT(this->netdev);
	OSMO_ASSERT(addr);

	switch (addr->len) {
	case 4:
		osa.u.sin.sin_family = AF_INET;
		memcpy(&osa.u.sin.sin_addr, &addr->v4, sizeof(struct in_addr));
		/* Store first IPv4 IP address to be used in ipup script: */
		if (this->addrs == 0) {
			this->addr.len = sizeof(struct in_addr);
			this->addr.v4.s_addr = addr->v4.s_addr;
			this->netmask.s_addr = htonl(0xffffffff << (32 - prefixlen));
		}
		break;
	case 16:
		osa.u.sin.sin_family = AF_INET6;
		memcpy(&osa.u.sin6.sin6_addr, &addr->v6, sizeof(struct in6_addr));
		break;
	default:
		return -1;
	}

	rc = osmo_netdev_add_addr(this->netdev, &osa, prefixlen);
	if (rc < 0)
		return rc;

	this->addrs++;
	return rc;
}

static int tun_tundev_data_ind_cb(struct osmo_tundev *tundev, struct msgb *msg)
{
	struct tun_t *tun = osmo_tundev_get_priv_data(tundev);
	int rc = 0;
	if (tun->cb_ind)
		rc = tun->cb_ind(tun, msgb_data(msg), msgb_length(msg));
	msgb_free(msg);
	return rc;
}

static struct tun_t *tun_alloc_common(const char *devname)
{
	struct tun_t *tun;

	tun = talloc_zero(NULL, struct tun_t);
	if (!tun) {
		LOGP(DTUN, LOGL_ERROR, "tun_alloc_common() failed\n");
		return NULL;
	}

	tun->cb_ind = NULL;
	tun->addrs = 0;
	tun->tundev.fd = -1;

	OSMO_STRLCPY_ARRAY(tun->devname, devname);

	return tun;
}

struct tun_t *tun_alloc_tundev(const char *devname)
{
	struct tun_t *tun;
	int rc;

	tun = tun_alloc_common(devname);
	if (!tun)
		return NULL;

	tun->tundev.tundev = osmo_tundev_alloc(tun, tun->devname);
	if (!tun->tundev.tundev)
		goto err_free;
	osmo_tundev_set_priv_data(tun->tundev.tundev, tun);
	osmo_tundev_set_data_ind_cb(tun->tundev.tundev, tun_tundev_data_ind_cb);
	rc = osmo_tundev_set_dev_name(tun->tundev.tundev, tun->devname);
	if (rc < 0)
		goto err_free_tundev;

	/* Open the actual tun device */
	rc = osmo_tundev_open(tun->tundev.tundev);
	if (rc < 0)
		goto err_free_tundev;
	tun->tundev.fd = osmo_tundev_get_fd(tun->tundev.tundev);
	tun->netdev = osmo_tundev_get_netdev(tun->tundev.tundev);

	/* Disable checksums */
	if (ioctl(tun->tundev.fd, TUNSETNOCSUM, 1) < 0) {
		SYS_ERR(DTUN, LOGL_NOTICE, errno, "could not disable checksum on %s", tun->devname);
	}

	LOGP(DTUN, LOGL_NOTICE, "tun %s configured\n", tun->devname);
	return tun;

err_free_tundev:
	osmo_tundev_free(tun->tundev.tundev);
err_free:
	talloc_free(tun);
	return NULL;
}

struct tun_t *tun_alloc_gtpdev(const char *devname, int fd0, int fd1u)
{
	struct tun_t *tun;
	int rc;

	tun = tun_alloc_common(devname);
	if (!tun)
		return NULL;

	if (gtp_kernel_create(-1, tun->devname, fd0, fd1u) < 0) {
		LOGP(DTUN, LOGL_ERROR, "cannot create GTP tunnel device: %s\n",
			strerror(errno));
		goto err_free;
	}
	tun->netdev = osmo_netdev_alloc(tun, tun->devname);
	if (!tun->netdev)
		goto err_kernel_create;
	rc = osmo_netdev_set_ifindex(tun->netdev, if_nametoindex(tun->devname));
	if (rc < 0)
		goto err_netdev_free;
	rc = osmo_netdev_register(tun->netdev);
	if (rc < 0)
		goto err_netdev_free;
	LOGP(DTUN, LOGL_NOTICE, "GTP kernel configured\n");
	return tun;

err_netdev_free:
	osmo_netdev_free(tun->netdev);
err_kernel_create:
	gtp_kernel_stop(tun->devname);
err_free:
	talloc_free(tun);
	return NULL;
}

int tun_free(struct tun_t *tun)
{
	if (tun->tundev.tundev) {
		if (osmo_tundev_close(tun->tundev.tundev) < 0) {
			SYS_ERR(DTUN, LOGL_ERROR, errno, "osmo_tundev_close() failed");
		}
		osmo_tundev_free(tun->tundev.tundev);
		tun->tundev.tundev = NULL;
		/* netdev is owned by tundev: */
		tun->netdev = NULL;
	} else {
		gtp_kernel_stop(tun->devname);
		/* netdev was allocated directly, free it: */
		osmo_netdev_free(tun->netdev);
		tun->netdev = NULL;
	}

	talloc_free(tun);
	return 0;
}

int tun_set_cb_ind(struct tun_t *this,
		   int (*cb_ind) (struct tun_t * tun, void *pack, unsigned len))
{
	this->cb_ind = cb_ind;
	return 0;
}

int tun_inject_pkt(struct tun_t *tun, void *pack, unsigned len)
{
	struct msgb *msg;
	int rc;

	if (!tun->tundev.tundev) {
		LOGTUN(LOGL_ERROR, tun,
		       "Injecting decapsulated packet not supported in kernel gtp mode: %s\n",
		       osmo_hexdump(pack, len));
		return -ENOTSUP;
	}

	msg = msgb_alloc(PACKET_MAX, "tun_tx");
	OSMO_ASSERT(msg);
	memcpy(msgb_put(msg, len), pack, len);
	rc = osmo_tundev_send(tun->tundev.tundev, msg);
	if (rc < 0) {
		SYS_ERR(DTUN, LOGL_ERROR, errno, "TUN(%s): write() failed", tun->devname);
	}
	return rc;
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
