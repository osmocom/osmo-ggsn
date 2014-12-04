/* 
 * Syslog functions.
 * Copyright (C) 2003, 2004 Mondru AB.
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "syserr.h"

static FILE* err_log;

void sys_err_setlogfile(FILE* log)
{
	err_log = log;
}

void sys_err(int pri, char *fn, int ln, int en, char *fmt, ...)
{
	va_list args;
	char buf[SYSERR_MSGSIZE];

	va_start(args, fmt);
	vsnprintf(buf, SYSERR_MSGSIZE, fmt, args);
	va_end(args);
	buf[SYSERR_MSGSIZE - 1] = 0;	/* Make sure it is null terminated */
	if (en) {
		if (err_log)
			fprintf(err_log, "%s: %d: %d (%s) %s\n",
				fn, ln, en, strerror(en), buf);
		syslog(pri, "%s: %d: %d (%s) %s", fn, ln, en, strerror(en),
		       buf);
	} else {
		if (err_log)
			fprintf(err_log, "%s: %d: %s\n", fn, ln, buf);
		syslog(pri, "%s: %d: %s", fn, ln, buf);
	}
}

