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

#ifndef __NETNS_H
#define __NETNS_H

#if defined(__linux__)

void init_netns(void);

int switch_ns(int nsfd, sigset_t *oldmask);
void restore_ns(sigset_t *oldmask);

int open_ns(int nsfd, const char *pathname, int flags);
int socket_ns(int nsfd, int domain, int type, int protocol);
int get_nsfd(const char *name);

#endif

#endif
