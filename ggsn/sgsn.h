#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>

#include <osmocom/gtp/pdp.h>

struct ggsn_ctx;
struct pdp_priv_t;

struct sgsn_peer {
	struct llist_head entry; /* to be included into ggsn_ctx */
	struct ggsn_ctx *ggsn; /* backpointer to ggsn_ctx */
	struct in_addr addr;	/* Addr of the sgsn peer */
	unsigned int gtp_version; /* GTP version */
	int remote_restart_ctr; /* Last received Restart Ctr from sgsn peer, -1 == unknown */
	/* list of pdp contexts associated with this sgsn */
	struct llist_head pdp_list;
	/* Sends echo request towards SGSN on expiration. Echo Resp is received
	   through cb_recovery2(), and echo Req timeout through
	   cb_conf(GTP_ECHO_REQ, EOF, NULL, cbp); */
	struct osmo_timer_list echo_timer;
	/* Number of GTP messages in libgtp transmit queue */
	unsigned int tx_msgs_queued;
};

struct sgsn_peer *sgsn_peer_allocate(struct ggsn_ctx *ggsn, struct in_addr *ia, unsigned int gtp_version);
void sgsn_peer_add_pdp_priv(struct sgsn_peer *sgsn, struct pdp_priv_t *pdp_priv);
void sgsn_peer_remove_pdp_priv(struct pdp_priv_t *pdp_priv);

void sgsn_echo_timer_start(struct sgsn_peer *sgsn);
void sgsn_echo_timer_stop(struct sgsn_peer *sgsn);

void sgsn_peer_echo_resp(struct sgsn_peer *sgsn, bool timeout);
unsigned int sgsn_peer_drop_all_pdp(struct sgsn_peer *sgsn);
int sgsn_peer_handle_recovery(struct sgsn_peer *sgsn, struct pdp_t *pdp, uint8_t recovery);

#define LOGSGSN(level, sgsn, fmt, args...) { \
	char _buf[INET_ADDRSTRLEN]; \
	LOGP(DGGSN, level, "SGSN(%s): " fmt, inet_ntop(AF_INET, &sgsn->addr, _buf, sizeof(_buf)), ## args); \
	} while (0)
