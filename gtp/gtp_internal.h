#pragma once

#include <stdint.h>
#include <talloc.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define GTP_LOGPKG(pri, peer, pack, len, fmt, args...)		\
logp2(DLGTP, pri, __FILE__, __LINE__, 0,			\
	"Packet from %s:%u, length: %d content: %s: " fmt,	\
	inet_ntoa((peer)->sin_addr), ntohs((peer)->sin_port),	\
	len, osmo_hexdump((const uint8_t *) pack, len),		\
	##args)

#define LOGP_WITH_ADDR(ss, level, peer, fmt, args...)		\
LOGP(ss, level, "addr(%s:%d) " fmt,				\
	inet_ntoa((peer)->sin_addr), ntohs((peer)->sin_port),	\
	##args)

uint64_t gtp_imsi_str2gtp(const char *str);

extern TALLOC_CTX *tall_libgtp_ctx;
