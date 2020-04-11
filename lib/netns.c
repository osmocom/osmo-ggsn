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

/*! default namespace of the GGSN process */
static int default_nsfd;

/*! switch to a (non-default) namespace, store existing signal mask in oldmask.
 *  \param[in] nsfd file descriptor representing the namespace to whch we shall switch
 *  \param[out] oldmask caller-provided memory location to which old signal mask is stored
 *  \ returns 0 on success or negative (errno) in case of error */
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

/*! switch back to the default namespace, restoring signal mask.
 *  \param[in] oldmask signal mask to restore after returning to default namespace
 *  \returns 0 on successs; negative errno value in case of error */
int restore_ns(sigset_t *oldmask)
{
	int rc;
	if (setns(default_nsfd, CLONE_NEWNET) < 0)
		return -errno;

	if ((rc = sigprocmask(SIG_SETMASK, oldmask, NULL)) != 0)
		return -rc;
	return 0;
}

/*! open a file from within specified network namespace */
int open_ns(int nsfd, const char *pathname, int flags)
{
	sigset_t intmask, oldmask;
	int fd;
	int rc;

	/* mask off all signals, store old signal mask */
	if (sigfillset(&intmask) < 0)
		return -errno;
	if ((rc = sigprocmask(SIG_BLOCK, &intmask, &oldmask)) != 0)
		return -rc;

	/* associate the calling thread with namespace file descriptor */
	if (setns(nsfd, CLONE_NEWNET) < 0)
		return -errno;
	/* open the requested file/path */
	if ((fd = open(pathname, flags)) < 0)
		return -errno;
	/* return back to default namespace */
	if (setns(default_nsfd, CLONE_NEWNET) < 0) {
		close(fd);
		return -errno;
	}
	/* restore process mask */
	if ((rc = sigprocmask(SIG_SETMASK, &oldmask, NULL)) != 0) {
		close(fd);
		return -rc;
	}

	return fd;
}

/*! create a socket in another namespace.
 *  Switches temporarily to namespace indicated by nsfd, creates a socket in
 *  that namespace and then returns to the default namespace.
 *  \param[in] nsfd File descriptor of the namspace in which to create socket
 *  \param[in] domain Domain of the socket (AF_INET, ...)
 *  \param[in] type Type of the socket (SOCK_STREAM, ...)
 *  \param[in] protocol Protocol of the socket (IPPROTO_TCP, ...)
 *  \returns 0 on success; negative errno in case of error */
int socket_ns(int nsfd, int domain, int type, int protocol)
{
	sigset_t intmask, oldmask;
	int sk;
	int rc;

	/* mask off all signals, store old signal mask */
	if (sigfillset(&intmask) < 0)
		return -errno;
	if ((rc = sigprocmask(SIG_BLOCK, &intmask, &oldmask)) != 0)
		return -rc;

	/* associate the calling thread with namespace file descriptor */
	if (setns(nsfd, CLONE_NEWNET) < 0)
		return -errno;

	/* create socket of requested domain/type/proto */
	if ((sk = socket(domain, type, protocol)) < 0)
		return -errno;

	/* return back to default namespace */
	if (setns(default_nsfd, CLONE_NEWNET) < 0) {
		close(sk);
		return -errno;
	}

	/* restore process mask */
	if ((rc = sigprocmask(SIG_SETMASK, &oldmask, NULL)) != 0) {
		close(sk);
		return -rc;
	}
	return sk;
}

/*! initialize this network namespace helper module.
 *  Must be called before using any other functions of this file.
 *  \returns 0 on success; negative errno in case of error */
int init_netns()
{
	/* store the default namespace for later reference */
	if ((default_nsfd = open("/proc/self/ns/net", O_RDONLY)) < 0)
		return -errno;
	return 0;
}

/*! create obtain file descriptor for network namespace of give name.
 *  Creates /var/run/netns  if it doesn't exist already.
 *  \param[in] name Name of the network namespace (in /var/run/netns/)
 *  \returns File descriptor of network namespace; negative errno in case of error */
int get_nsfd(const char *name)
{
	int rc;
	int fd;
	sigset_t intmask, oldmask;
	char path[MAXPATHLEN] = NETNS_PATH;

	/* create /var/run/netns, if it doesn't exist already */
	rc = mkdir(path, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
	if (rc < 0 && errno != EEXIST)
		return rc;

	/* create /var/run/netns/[name], if it doesn't exist already */
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

	/* mask off all signals, store old signal mask */
	if (sigfillset(&intmask) < 0)
		return -errno;
	if ((rc = sigprocmask(SIG_BLOCK, &intmask, &oldmask)) != 0)
		return -rc;

	/* create a new network namespace */
	if (unshare(CLONE_NEWNET) < 0)
		return -errno;
	if (mount("/proc/self/ns/net", path, "none", MS_BIND, NULL) < 0)
		return -errno;

	/* switch back to default namespace */
	if (setns(default_nsfd, CLONE_NEWNET) < 0)
		return -errno;

	/* restore process mask */
	if ((rc = sigprocmask(SIG_SETMASK, &oldmask, NULL)) != 0)
		return -rc;

	/* finally, open the created namespace file descriptor from default ns */
	if ((fd = open(path, O_RDONLY)) < 0)
		return -errno;

	return fd;
}

#endif
