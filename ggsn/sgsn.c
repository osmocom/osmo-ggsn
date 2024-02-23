#include "sgsn.h"
#include "ggsn.h"
#include "../gtp/gtp_internal.h"

static bool sgsn_peer_attempt_free(struct sgsn_peer *sgsn)
{
	/* We have to be careful here, since if all pdp ctx for that sgsn were
	   deactivated in-between we sent the Echo Req and receivied the timeout
	   indication, the sgsn (cbp) may be already gone. We need to add some
	   counter reference of echo requets in flight and only free sgsn
	   structures when it goes to zero decreased for all Echo Resp. We do it
	   this way because currently in libgtp there's no understanding of "gsn
	   peer" for which messages are grouped and hence we cannot request
	   libgtp to drop all queued messages for a specific peer. */
	if (sgsn->tx_msgs_queued) {
		LOGSGSN(LOGL_INFO, sgsn, "Delaying delete, still %u echo messages queued\n",
			sgsn->tx_msgs_queued);
		return false;
	}
	llist_del(&sgsn->entry);
	LOGSGSN(LOGL_INFO, sgsn, "Deleting SGSN\n");
	talloc_free(sgsn);
	return true;
}

static void sgsn_peer_echo_req(struct sgsn_peer *sgsn)
{
	struct ggsn_ctx *ggsn = sgsn->ggsn;
	LOGSGSN(LOGL_INFO, sgsn, "Tx Echo Request\n");
	gtp_echo_req(ggsn->gsn, sgsn->gtp_version, sgsn, &sgsn->addr);
	sgsn->tx_msgs_queued++;
}

void sgsn_peer_echo_resp(struct sgsn_peer *sgsn, bool timeout)
{
	if (timeout) {
		LOGSGSN(LOGL_NOTICE, sgsn, "Rx Echo Request timed out!\n");
		sgsn_peer_drop_all_pdp(sgsn);
	} else {
		LOGSGSN(LOGL_INFO, sgsn, "Rx Echo Response\n");
	}

	/* We decrement it here after dropping all pdps to make sure sgsn was
	   not freed upon last pdp ctx deleted and is still alive now */
	sgsn->tx_msgs_queued--;
	if (llist_empty(&sgsn->pdp_list))
		sgsn_peer_attempt_free(sgsn);
}

void sgsn_echo_timer_start(struct sgsn_peer *sgsn)
{
	if (sgsn->ggsn->cfg.echo_interval == 0)
		return;
	sgsn_peer_echo_req(sgsn);
	osmo_timer_schedule(&sgsn->echo_timer, sgsn->ggsn->cfg.echo_interval, 0);
}

void sgsn_echo_timer_stop(struct sgsn_peer *sgsn)
{
	osmo_timer_del(&sgsn->echo_timer);
}

static void sgsn_echo_timer_cb(void *data)
{
	struct sgsn_peer *sgsn = (struct sgsn_peer *) data;
	sgsn_echo_timer_start(sgsn);
}

struct sgsn_peer *sgsn_peer_allocate(struct ggsn_ctx *ggsn, struct in_addr *ia, unsigned int gtp_version)
{
	struct sgsn_peer *sgsn;

	sgsn = talloc_zero_size(ggsn, sizeof(struct sgsn_peer));
	sgsn->ggsn = ggsn;
	sgsn->addr = *ia;
	sgsn->gtp_version = gtp_version;
	sgsn->remote_restart_ctr = -1;
	INIT_LLIST_HEAD(&sgsn->pdp_list);
	INIT_LLIST_HEAD(&sgsn->entry);

	osmo_timer_setup(&sgsn->echo_timer, sgsn_echo_timer_cb, sgsn);

	LOGSGSN(LOGL_INFO, sgsn, "Discovered\n");
	return sgsn;
}

void sgsn_peer_add_pdp_priv(struct sgsn_peer *sgsn, struct pdp_priv_t *pdp_priv)
{
	bool was_empty = llist_empty(&sgsn->pdp_list);
	pdp_priv->sgsn = sgsn;
	llist_add(&pdp_priv->entry, &sgsn->pdp_list);
	if (was_empty)
		sgsn_echo_timer_start(sgsn);
}

void sgsn_peer_remove_pdp_priv(struct pdp_priv_t* pdp_priv)
{
	struct sgsn_peer *sgsn = pdp_priv->sgsn;
	llist_del(&pdp_priv->entry);
	if (sgsn && llist_empty(&sgsn->pdp_list)) {
		/* No PDP contexts associated to this SGSN, no need to keep it */
		sgsn_echo_timer_stop(sgsn);
		/* sgsn may not be freed if there are some messages still queued
		   in libgtp which could return a pointer to it */
		sgsn_peer_attempt_free(sgsn);
	}

	pdp_priv->sgsn = NULL;
}

/* High-level function to be called in case a GGSN has disappeared or
 * otherwise lost state (recovery procedure). It will detach all related pdp ctx
 * from a ggsn and communicate deact to MS. Optionally (!NULL), one pdp ctx can
 * be kept alive to allow handling later message which contained the Recovery IE. */
static unsigned int sgsn_peer_drop_all_pdp_except(struct sgsn_peer *sgsn, struct pdp_priv_t *except)
{
	unsigned int num = 0;
	char buf[INET_ADDRSTRLEN];
	unsigned int count = llist_count(&sgsn->pdp_list);

	inet_ntop(AF_INET, &sgsn->addr, buf, sizeof(buf));

	struct pdp_priv_t *pdp, *pdp2;
	llist_for_each_entry_safe(pdp, pdp2, &sgsn->pdp_list, entry) {
		if (pdp == except)
			continue;
		ggsn_close_one_pdp(pdp->lib);
		num++;
		if (num == count) {
			/* Note: if except is NULL, all pdp contexts are freed and sgsn
			 * is most probably already freed at this point.
			 * As a result, last access to sgsn->pdp_list before exiting
			 * loop would access already freed memory. Avoid it by exiting
			 * the loop without the last check, and make sure sgsn is not
			 * accessed after this loop. */
			 break;
		}
	}

	LOGP(DGGSN, LOGL_INFO, "SGSN(%s) Dropped %u PDP contexts\n", buf, num);

	return num;
}

unsigned int sgsn_peer_drop_all_pdp(struct sgsn_peer *sgsn)
{
	return sgsn_peer_drop_all_pdp_except(sgsn, NULL);
}

int sgsn_peer_handle_recovery(struct sgsn_peer *sgsn, struct pdp_t *pdp, uint8_t recovery)
{
	struct pdp_priv_t *pdp_priv = NULL;

	if (sgsn->remote_restart_ctr == -1) {
		/* First received ECHO RESPONSE, note the restart ctr */
		sgsn->remote_restart_ctr = recovery;
	} else if (sgsn->remote_restart_ctr != recovery) {
		/* counter has changed (SGSN restart): release all PDP */
		LOGSGSN(LOGL_NOTICE, sgsn, "SGSN recovery (%u->%u) pdp=%p, "
		     "releasing all%s PDP contexts\n",
		     sgsn->remote_restart_ctr, recovery, pdp, pdp ? " other" : "");
		sgsn->remote_restart_ctr = recovery;
		if (pdp)
			pdp_priv = pdp->priv;
		sgsn_peer_drop_all_pdp_except(sgsn, pdp_priv);
	}
	return 0;
}
