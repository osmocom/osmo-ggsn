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

#ifndef _SYSERR_H
#define _SYSERR_H

#include <osmocom/core/logging.h>

enum {
	DIP,
	DTUN,
	DGGSN,
	DSGSN,
};

#define SYS_ERR(sub, pri, en, fmt, args...)				\
	if (en) {							\
		logp2(sub, pri, __FILE__, __LINE__, 0,			\
			"errno=%d/%s " fmt "\n", en, strerror(en),	\
			##args);					\
	} else {							\
		logp2(sub, pri, __FILE__, __LINE__, 0,			\
			fmt "\n", ##args);				\
	}

extern const struct log_info log_info;

#endif /* !_SYSERR_H */
