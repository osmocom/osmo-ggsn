/*
 * MIT License
 *
 * Copyright (c) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 *
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* For more info see:
 * 3GPP TS 29.060 (GTPv1 and GTPv0)
 * 3GPP TS 29.274 (GTPv2C)
 */

#include "../config.h"

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>

#define GTP1C_PORT	2123
#define GTP_MSGTYPE_ECHO_REQ	1
#define GTP_MSGTYPE_ECHO_RSP	2
#define GTP1C_IE_RECOVERY 14
#define GTP2C_IE_RECOVERY 3
#define GTP2C_IE_NODE_FEATURES 152

struct gtp1_hdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint8_t pn:1, s:1, e:1, spare:1, pt:1, version:3;
#else
	uint8_t version:3, pt:1, spare:1, e:1, s:1, pn:1;
#endif
	uint8_t type;
	uint16_t length;
	uint32_t tei;
	uint16_t seq;
	uint8_t npdu;
	uint8_t next;
} __attribute__((packed));

struct gtp2_hdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint8_t reserved:3, t:1, p:1, version:3;
#else
	uint8_t version:3, p:1, t:1, reserved:1;
#endif
	uint8_t type;
	uint16_t length;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint32_t reserved2:8, seq:24;
#else
	uint8_t seq:24, reserved2:1;
#endif
} __attribute__((packed));

struct gtp_echo_resp_state {
	struct {
		char laddr[INET6_ADDRSTRLEN];
		uint8_t recovery_ctr;
		uint8_t node_features;
	} cfg;
	struct sockaddr_storage laddr_gtpc;
	int fd_gtpc;
};

struct gtp_echo_resp_state *g_st;

static void print_usage(void)
{
	printf("Usage: gtp-echo-responder [-h] [-V] [-l listen_addr]\n");
}

static void print_help(void)
{
	printf("  Some useful help...\n"
	       "  -h --help		This help text\n"
	       "  -V --version		Print the version of gtp-echo-responder\n"
	       "  -l --listen-addr	Listend address for GTPCv1 and GTPCv2\n"
	       "  -R --recovery-counter GTP Recovery Counter to transmit in GTP Echo Response message\n"
	       "  -n --node-features	GTPCv2 Node Features bitmask to transmit in GTP Echo Response message\n"
	       );
}

static void print_version(void)
{
	printf("gtp-echo-responder version %s\n", PACKAGE_VERSION);
}

static uint8_t parse_node_features_mask(const char *arg)
{
	unsigned long res;
	char *end;
	errno = 0;

	res = strtoul(arg, &end, 0);
	if ((errno == ERANGE && res == ULONG_MAX) || (errno && !res) ||
	    arg == end) {
		fprintf(stderr, "Failed parsing Node Features bitmask: '%s'\n", arg);
		exit(1);
	}
	if (res > 0xff) {
		fprintf(stderr, "Failed parsing Node Features bitmask: '%s' > 0xFF\n", arg);
		exit(1);
	}
	return (uint8_t)res;
}
static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'V' },
			{ "listen-addr", 1, 0, 'l'},
			{ "recovery-counter", 1, 0, 'R'},
			{ "node-features", 1, 0, 'N'},
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hVl:R:N:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 'V':
			print_version();
			exit(0);
			break;
		case 'l':
			strncpy(&g_st->cfg.laddr[0], optarg, sizeof(g_st->cfg.laddr));
			g_st->cfg.laddr[sizeof(g_st->cfg.laddr) - 1] = '\0';
			break;
		case 'R':
			g_st->cfg.recovery_ctr = (uint8_t)atoi(optarg);
			break;
		case 'N':
			g_st->cfg.node_features = parse_node_features_mask(optarg);
			break;
		}
	}
}

static int init_socket(void)
{
	struct in_addr addr;
	struct in6_addr addr6;
	struct sockaddr_in *saddr;
	struct sockaddr_in6 *saddr6;
	int family;

	if (inet_pton(AF_INET6, g_st->cfg.laddr, &addr6) == 1) {
		family = AF_INET6;
		saddr6 = (struct sockaddr_in6 *)&g_st->laddr_gtpc;
		saddr6->sin6_family = family;
		saddr6->sin6_port = htons(GTP1C_PORT);
		memcpy(&saddr6->sin6_addr, &addr6, sizeof(addr6));
	} else if (inet_pton(AF_INET, g_st->cfg.laddr, &addr) == 1) {
		family = AF_INET;
		saddr = (struct sockaddr_in *)&g_st->laddr_gtpc;
		saddr->sin_family = family;
		saddr->sin_port = htons(GTP1C_PORT);
		memcpy(&saddr->sin_addr, &addr, sizeof(addr));
	} else {
		fprintf(stderr, "Failed parsing address %s\n", g_st->cfg.laddr);
		return -1;
	}

	if ((g_st->fd_gtpc = socket(family, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
		return -2;
	}

	if (bind(g_st->fd_gtpc, (struct sockaddr *)&g_st->laddr_gtpc, sizeof(g_st->laddr_gtpc)) < 0) {
		fprintf(stderr, "bind() failed: %s\n", strerror(errno));
		return -3;
	}

	return 0;
}

static const char *sockaddr2str(const struct sockaddr *saddr)
{
	static char _rem_addr_str[INET6_ADDRSTRLEN];
	struct sockaddr_in *saddr4;
	struct sockaddr_in6 *saddr6;

	switch (saddr->sa_family) {
	case AF_INET6:
		saddr6 = (struct sockaddr_in6 *)saddr;
		if (!inet_ntop(saddr6->sin6_family, &saddr6->sin6_addr, _rem_addr_str, sizeof(_rem_addr_str)))
			strcpy(_rem_addr_str, "unknown");
		return _rem_addr_str;
	case AF_INET:
		saddr4 = (struct sockaddr_in *)saddr;
		if (!inet_ntop(saddr4->sin_family, &saddr4->sin_addr, _rem_addr_str, sizeof(_rem_addr_str)))
			strcpy(_rem_addr_str, "unknown");
		return _rem_addr_str;
	default:
		strcpy(_rem_addr_str, "unknown-family");
		return _rem_addr_str;
	}
}

static int write_cb(int fd, const uint8_t *buf, size_t buf_len, const struct sockaddr *rem_saddr)
{
	ssize_t rc;

	rc = sendto(fd, buf, buf_len, 0, rem_saddr, sizeof(struct sockaddr_storage));
	if (rc < 0) {
		fprintf(stderr, "sendto() failed: %s\n", strerror(errno));
		return -1;
	}
	if (rc != buf_len) {
		fprintf(stderr, "sendto() short write: %zd vs exp %zu\n", rc, buf_len);
		return -1;
	}
	return 0;
}

static int gen_gtpc1_echo_rsp(uint8_t *buf, struct gtp1_hdr *echo_req)
{
	int offset = 0;
	struct gtp1_hdr *echo_rsp = (struct gtp1_hdr *)buf;
	unsigned exp_hdr_len = (echo_req->s || echo_req->pn || echo_req->e) ? 12 : 8;

	memcpy(echo_rsp, echo_req, exp_hdr_len);
	echo_rsp->type = GTP_MSGTYPE_ECHO_RSP;
	offset = exp_hdr_len;
	buf[offset++] = GTP1C_IE_RECOVERY;
	buf[offset++] = g_st->cfg.recovery_ctr;

	/* Update Length */
	echo_rsp->length = htons(offset - 8);
	return offset;
}

static int gen_gtpc2_echo_rsp(uint8_t *buf, struct gtp2_hdr *echo_req)
{
	int offset = 0;
	struct gtp1_hdr *echo_rsp = (struct gtp1_hdr *)buf;
	unsigned exp_hdr_len = 8;

	memcpy(echo_rsp, echo_req, exp_hdr_len);
	echo_rsp->type = GTP_MSGTYPE_ECHO_RSP;
	offset = exp_hdr_len;

	/* 3GPP TS 29.274 sec 8.5 Recovery (Restart Counter) */
	buf[offset++] = GTP2C_IE_RECOVERY;
	buf[offset++] = 0; /* IE Length (high) */
	buf[offset++] = 1; /* IE Length (low) */
	buf[offset++] = 0; /* Spare=0 | Instance=0 (Table 7.1.1-1) */
	buf[offset++] = g_st->cfg.recovery_ctr;

	/* 3GPP TS 29.274 sec 8.83 Node Features */
	if (g_st->cfg.node_features > 0) {
		buf[offset++] = GTP2C_IE_NODE_FEATURES;
		buf[offset++] = 0; /* IE Length (high) */
		buf[offset++] = 1; /* IE Length (low) */
		buf[offset++] = 0; /* Spare=0 | Instance=0 (Table 7.1.1-1) */
		buf[offset++] = g_st->cfg.node_features;
	}

	/* Update Length */
	echo_rsp->length = htons(offset - 4);
	return offset;
}

static int rx_gtpc1_echo_req(struct gtp1_hdr *echo_req, unsigned buf_len, const struct sockaddr *rem_saddr)
{
	int rc;
	const size_t tx_buf_len = buf_len + 128; /* Leave some extra room */
	uint8_t *tx_buf = alloca(tx_buf_len);

	printf("Rx GTPCv1_ECHO_REQ from %s, Tx GTPCv1_ECHO_RSP\n", sockaddr2str(rem_saddr));

	memset(tx_buf, 0, tx_buf_len);
	rc = gen_gtpc1_echo_rsp(tx_buf, echo_req);
	return write_cb(g_st->fd_gtpc, tx_buf, rc, rem_saddr);
}

static int rx_gtpc1(struct gtp1_hdr *hdr, unsigned buf_len, const struct sockaddr *rem_saddr)
{
	unsigned exp_hdr_len = (hdr->s || hdr->pn || hdr->e) ? 12 : 8;
	unsigned pdu_len;

	if (buf_len < exp_hdr_len) {
		fprintf(stderr, "GTPCv1 packet size smaller than header! %u < exp %u\n", buf_len, exp_hdr_len);
		return -1;
	}

	pdu_len = ntohs(hdr->length);
	if (buf_len < 8 + pdu_len) {
		fprintf(stderr, "GTPCv1 packet size smaller than announced! %u < exp %u\n", buf_len, 8 + pdu_len);
		return -1;
	}

	if (hdr->pt != 1) {
		fprintf(stderr, "GTPCv1 Protocol Type GTP' not supported!\n");
		return -1;
	}

	switch (hdr->type) {
	case GTP_MSGTYPE_ECHO_REQ:
		return rx_gtpc1_echo_req(hdr, buf_len, rem_saddr);
	default:
		fprintf(stderr, "Silently ignoring unexpected packet of type %u\n", hdr->type);
		return 0;
	}
}

static int rx_gtpc2_echo_req(struct gtp2_hdr *echo_req, unsigned buf_len, const struct sockaddr *rem_saddr)
{
	int rc;
	const size_t tx_buf_len = buf_len + 128; /* Leave some extra room */
	uint8_t *tx_buf = alloca(tx_buf_len);

	if (echo_req->t) {
		fprintf(stderr, "GTPCv2 ECHO message should contain T=0!\n");
		return -1;
	}

	printf("Rx GTPCv2_ECHO_REQ from %s, Tx GTPCv2_ECHO_RSP\n", sockaddr2str(rem_saddr));

	memset(tx_buf, 0, tx_buf_len);
	rc = gen_gtpc2_echo_rsp(tx_buf, echo_req);
	return write_cb(g_st->fd_gtpc, tx_buf, rc, rem_saddr);
}

static int rx_gtpc2(struct gtp2_hdr *hdr, unsigned buf_len, const struct sockaddr *rem_saddr)
{
	unsigned exp_hdr_len = hdr->t ? 12 : 8;
	unsigned pdu_len;

	if (hdr->p) {
		fprintf(stderr, "GTPCv2 piggybacked message not supported!\n");
		return -1;
	}

	if (buf_len < exp_hdr_len) {
		fprintf(stderr, "GTPCv2 packet size smaller than header! %u < exp %u\n", buf_len, exp_hdr_len);
		return -1;
	}

	pdu_len = ntohs(hdr->length);
	/* 3GPP TS 29.274 sec 5.5.1: "Octets 3 to 4 represent the Message Length
	 * field. This field shall indicate the length of the message in octets
	 * excluding the mandatory part of the GTP-C header (the first 4
	 * octets). The TEID (if present) and the Sequence  Number shall be
	 * included in the length count" */
	if (buf_len < 4 + pdu_len) {
		fprintf(stderr, "GTPCv2 packet size smaller than announced! %u < exp %u\n", buf_len, 4 + pdu_len);
		return -1;
	}

	switch (hdr->type) {
	case GTP_MSGTYPE_ECHO_REQ:
		return rx_gtpc2_echo_req(hdr, buf_len, rem_saddr);
	default:
		fprintf(stderr, "Silently ignoring unexpected packet of type %u\n", hdr->type);
		return 0;
	}
}

static int read_cb(int fd)
{
	ssize_t sz;
	uint8_t buf[4096];
	struct sockaddr_storage rem_saddr;
	socklen_t rem_saddr_len = sizeof(rem_saddr);
	struct gtp1_hdr *hdr1;

	if ((sz = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&rem_saddr, &rem_saddr_len)) < 0) {
		fprintf(stderr, "recvfrom() failed: %s\n", strerror(errno));
		return -1;
	}
	if (sz == 0) {
		fprintf(stderr, "recvfrom() read zero bytes!\n");
		return -1;
	}

	hdr1 = (struct gtp1_hdr *)&buf[0];
	switch (hdr1->version) {
	case 1:
		return rx_gtpc1(hdr1, sz, (const struct sockaddr *)&rem_saddr);
	case 2:
		return rx_gtpc2((struct gtp2_hdr *)&buf[0], sz, (const struct sockaddr *)&rem_saddr);
	default:
		fprintf(stderr, "Rx GTPv%u: not supported (flags=0x%x)\n", hdr1->version, buf[0]);
		return -1;
	}
}

static int loop(void)
{
	int rc;
	fd_set rfds;
	int nfds;

	while (true) {
		FD_ZERO(&rfds);
		FD_SET(g_st->fd_gtpc, &rfds);
		nfds = g_st->fd_gtpc + 1;
		rc = select(nfds, &rfds, NULL, NULL, NULL);
		if (rc == 0)
			continue;
		if (rc < 0) {
			fprintf(stderr, "select() failed: %s\n", strerror(errno));
			return -1;
		}

		if (FD_ISSET(g_st->fd_gtpc, &rfds))
			read_cb(g_st->fd_gtpc);
	}
}

int main(int argc, char **argv)
{
	g_st = calloc(1, sizeof(struct gtp_echo_resp_state));

	strcpy(g_st->cfg.laddr, "::");

	handle_options(argc, argv);

	printf("Listening on: %s\n", g_st->cfg.laddr);

	if (init_socket() < 0)
		exit(1);

	printf("Socket bound successfully, listening for requests...\n");

	if (loop() < 0)
		exit(1);

	return 0;
}
