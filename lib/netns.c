/*
 * Copyright (C) 2014-2017, Travelping GmbH <info@travelping.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#if defined(__linux__)

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <fcntl.h>
#include <errno.h>

#include "netns.h"

#define NETNS_PATH "/var/run/netns"

static int default_nsfd;

int switch_ns(int nsfd, sigset_t *oldmask)
{
	sigset_t intmask;
	int rc;

	if (sigfillset(&intmask) < 0)
		return -errno;
	if ((rc = sigprocmask(SIG_BLOCK, &intmask, oldmask)) != 0)
		return -rc;

	if (setns(nsfd, CLONE_NEWNET) < 0)
		return -errno;
	return 0;
}

int restore_ns(sigset_t *oldmask)
{
	int rc;
	if (setns(default_nsfd, CLONE_NEWNET) < 0)
		return -errno;

	if ((rc = sigprocmask(SIG_SETMASK, oldmask, NULL)) != 0)
		return -rc;
	return 0;
}

int open_ns(int nsfd, const char *pathname, int flags)
{
	sigset_t intmask, oldmask;
	int fd;
	int rc;

	if (sigfillset(&intmask) < 0)
		return -errno;
	if ((rc = sigprocmask(SIG_BLOCK, &intmask, &oldmask)) != 0)
		return -rc;

	if (setns(nsfd, CLONE_NEWNET) < 0)
		return -errno;
	if ((fd = open(pathname, flags)) < 0)
		return -errno;
	if (setns(default_nsfd, CLONE_NEWNET) < 0) {
		close(fd);
		return -errno;
	}
	if ((rc = sigprocmask(SIG_SETMASK, &oldmask, NULL)) != 0) {
		close(fd);
		return -rc;
	}

	return 0;
}

int socket_ns(int nsfd, int domain, int type, int protocol)
{
	sigset_t intmask, oldmask;
	int sk;
	int rc;

	if (sigfillset(&intmask) < 0)
		return -errno;
	if ((rc = sigprocmask(SIG_BLOCK, &intmask, &oldmask)) != 0)
		return -rc;

	if (setns(nsfd, CLONE_NEWNET) < 0)
		return -errno;
	if ((sk = socket(domain, type, protocol)) < 0)
		return -errno;
	if (setns(default_nsfd, CLONE_NEWNET) < 0) {
		close(sk);
		return -errno;
	}

	if ((rc = sigprocmask(SIG_SETMASK, &oldmask, NULL)) != 0) {
		close(sk);
		return -rc;
	}
	return sk;
}

int init_netns()
{
	if ((default_nsfd = open("/proc/self/ns/net", O_RDONLY)) < 0)
		return -errno;
	return 0;
}

int get_nsfd(const char *name)
{
	int rc;
	int fd;
	sigset_t intmask, oldmask;
	char path[MAXPATHLEN] = NETNS_PATH;

	rc = mkdir(path, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
	if (rc < 0 && errno != EEXIST)
		return rc;

	snprintf(path, sizeof(path), "%s/%s", NETNS_PATH, name);
	fd = open(path, O_RDONLY|O_CREAT|O_EXCL, 0);
	if (fd < 0) {
		if (errno == EEXIST) {
			if ((fd = open(path, O_RDONLY)) < 0)
				return -errno;
			return fd;
		}
		return -errno;
	}
	if (close(fd) < 0)
		return -errno;

	if (sigfillset(&intmask) < 0)
		return -errno;
	if ((rc = sigprocmask(SIG_BLOCK, &intmask, &oldmask)) != 0)
		return -rc;

	if (unshare(CLONE_NEWNET) < 0)
		return -errno;
	if (mount("/proc/self/ns/net", path, "none", MS_BIND, NULL) < 0)
		return -errno;

	if (setns(default_nsfd, CLONE_NEWNET) < 0)
		return -errno;

	if ((rc = sigprocmask(SIG_SETMASK, &oldmask, NULL)) != 0)
		return -rc;

	if ((fd = open(path, O_RDONLY)) < 0)
		return -errno;
	return fd;
}

#endif
