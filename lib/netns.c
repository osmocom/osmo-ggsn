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

	sigfillset(&intmask);
	sigprocmask(SIG_BLOCK, &intmask, oldmask);

	return setns(nsfd, CLONE_NEWNET);
}

void restore_ns(sigset_t *oldmask)
{
	setns(default_nsfd, CLONE_NEWNET);

	sigprocmask(SIG_SETMASK, oldmask, NULL);
}

int open_ns(int nsfd, const char *pathname, int flags)
{
	sigset_t intmask, oldmask;
	int fd;
	int errsv;

	sigfillset(&intmask);
	sigprocmask(SIG_BLOCK, &intmask, &oldmask);

	setns(nsfd, CLONE_NEWNET);
	fd = open(pathname, flags);
	errsv = errno;
	setns(default_nsfd, CLONE_NEWNET);

	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	errno = errsv;
	return fd;
}

int socket_ns(int nsfd, int domain, int type, int protocol)
{
	sigset_t intmask, oldmask;
	int sk;
	int errsv;

	sigfillset(&intmask);
	sigprocmask(SIG_BLOCK, &intmask, &oldmask);

	setns(nsfd, CLONE_NEWNET);
	sk = socket(domain, type, protocol);
	errsv = errno;
	setns(default_nsfd, CLONE_NEWNET);

	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	errno = errsv;
	return sk;
}

void init_netns()
{
	if ((default_nsfd = open("/proc/self/ns/net", O_RDONLY)) < 0) {
		perror("init_netns");
		exit(EXIT_FAILURE);
	}
}

int get_nsfd(const char *name)
{
	int r;
	sigset_t intmask, oldmask;
	char path[MAXPATHLEN] = NETNS_PATH;

	r = mkdir(path, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
	if (r < 0 && errno != EEXIST)
		return r;

	snprintf(path, sizeof(path), "%s/%s", NETNS_PATH, name);
	r = open(path, O_RDONLY|O_CREAT|O_EXCL, 0);
	if (r < 0) {
		if (errno == EEXIST)
			return open(path, O_RDONLY);

		return r;
	}
	close(r);

	sigfillset(&intmask);
	sigprocmask(SIG_BLOCK, &intmask, &oldmask);

	unshare(CLONE_NEWNET);
	mount("/proc/self/ns/net", path, "none", MS_BIND, NULL);

	setns(default_nsfd, CLONE_NEWNET);

	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	return open(path, O_RDONLY);
}

#endif
