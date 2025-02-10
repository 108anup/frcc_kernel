/*
NDD: A provably fair and robust congestion controller
*/

#include <net/tcp.h>
#include <linux/build_bug.h>

#define NDD_DEBUG

#define P_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains) */
#define P_UNIT (1 << P_SCALE)

static const u32 p_ub_rtprop_us = 100000;  // 100 ms
static const u32 p_ub_rtterr_us = 10000;  // 10 ms
static const u32 p_contract_min_qdel_us = p_ub_rtprop_us / 2;

// TODO: check if these floating values make sense given the UNIT. Should we
// change the unit?
static const u32 p_cwnd_averaging_factor_unit = P_UNIT * 1 / 2;
static const u32 p_cwnd_clamp_high_unit = P_UNIT * 6 / 5;
static const u32 p_cwnd_clamp_low_unit = P_UNIT * 11 / 10;
static const u32 p_probe_multiplier_unit = P_UNIT * 4;
static const u32 p_probe_duration = p_ub_rtterr_us; // ? Do we want something else here?

static u32 id = 0;
struct ndd_data {
	u32 id;

	// State variables
	u64 s_min_rtprop_us;

	u32 s_round_min_rtt_us;
	u32 s_round_max_rate_pps;  // packets per second (1500 bytes per sec to 6.44 Terabytes per second)
	u32 s_slot_max_qdel_us;

	bool s_probe_ongoing;
	u32 s_probe_min_excess_delay_us;
	u32 s_probe_prev_cwnd_pkts;
};

static void ndd_init(struct sock *sk)
{
	struct ndd_data *ndd = inet_csk_ca(sk);
	// ndd->min_rtt_us = U32_MAX;
	++id;
	ndd->id = id;
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}

static u32 ndd_get_mss(struct tcp_sock *tsk)
{
	// TODO: Figure out if mss_cache is the one to use
	return tsk->mss_cache;
}

/* was the ndd struct fully inited */
static bool ndd_valid(struct ndd_data *ndd) { return (ndd); }

static bool part_of_probe(struct ndd_data *ndd, struct tcp_sock *tsk) {
	return false;
}

static void update_estimates(struct ndd_data *ndd, struct tcp_sock *tsk, const struct rate_sample *rs, u32 rtt_us) {
	u32 this_qdel = rtt_us - ndd->s_min_rtprop_us;

	ndd->s_min_rtprop_us = min_t(u32, ndd->s_min_rtprop_us, rtt_us);
	ndd->s_round_min_rtt_us = min_t(u32, ndd->s_round_min_rtt_us, rtt_us);

	if (ndd->s_probe_ongoing && part_of_probe(ndd, tsk)) {
		u32 this_excess_delay_us = rtt_us - ndd->s_round_min_rtt_us;
		ndd->s_probe_min_excess_delay_us = min_t(u32, ndd->s_probe_min_excess_delay_us, this_excess_delay_us);
	}
	else {
		ndd->s_slot_max_qdel_us = max_t(u32, ndd->s_slot_max_qdel_us, this_qdel);
		// TODO: Should we use the rate sample here?
		u64 this_rate_pps = tsk->snd_cwnd * USEC_PER_SEC / rtt_us;
		ndd->s_round_max_rate_pps = max_t(u64, ndd->s_round_max_rate_pps, this_rate_pps);
	}
}

static void reset_round_estimates(struct ndd_data *ndd) {
	ndd->s_round_min_rtt_us = U32_MAX;
	ndd->s_round_max_rate_pps = 0;
}

static u32 get_initial_rtt(struct tcp_sock *tsk) {
	// Get initial RTT - as measured by SYN -> SYN-ACK.  If information
	// does not exist - use U32_MAX as RTT
	u32 rtt_us;
	if (tsk->srtt_us) {
		rtt_us = max_t(u32, tsk->srtt_us >> 3, 1U);
	} else {
		rtt_us = U32_MAX;
	}
	return rtt_us;
}

static bool probe_ended(struct ndd_data *ndd, struct tcp_sock *tsk, u32 rtt_us) {
	return false;
}

static bool cruise_ended(struct ndd_data *ndd, struct tcp_sock *tsk, u32 rtt_us) {
  return false;
}

static bool should_init_probe_end(struct ndd_data *ndd, struct tcp_sock *tsk) {
	return false;
}

static bool round_ended(struct ndd_data *ndd, struct tcp_sock *tsk) {
	return false;
}

static bool should_probe(struct ndd_data *ndd, struct tcp_sock *tsk) {
	return false;
}

static void update_state_after_probe_end(struct ndd_data *ndd) {
	ndd->s_probe_ongoing = false;
	ndd->s_probe_min_excess_delay_us = U32_MAX;
}

static void update_cwnd(struct ndd_data *ndd, struct tcp_sock *tsk) {

}

static void start_probe(struct ndd_data *ndd, struct tcp_sock *tsk) {
  u32 qdel_us;
  u32 target_flow_count;
  u32 excess_pkts;

  ndd->s_probe_ongoing = true;
  ndd->s_probe_min_excess_delay_us = U32_MAX;
  qdel_us = ndd->s_round_min_rtt_us - ndd->s_min_rtprop_us;
  target_flow_count = qdel_us / p_contract_min_qdel_us;
  excess_pkts =
      p_probe_multiplier_unit * target_flow_count * ndd->s_round_max_rate_pps * p_ub_rtterr_us;
  ndd->s_probe_prev_cwnd_pkts = tsk->snd_cwnd + excess_pkts;
}

static void ndd_cong_ctrl(struct sock *sk, const struct rate_sample *rs)
{
	struct ndd_data *ndd = inet_csk_ca(sk);
	struct tcp_sock *tsk = tcp_sk(sk);
	u32 rtt_us;
	u64 now_us = tsk->tcp_mstamp;
	// u32 latest_inflight_segments = rs->prior_in_flight;

	// Is struct valid? Is rate sample valid? Is RTT valid?
	if (!ndd_valid(ndd) || rs->delivered < 0 || rs->interval_us < 0 || rs->rtt_us < 0)
		return;

	rtt_us = rs->rtt_us;
	update_estimates(ndd, tsk, rs, rtt_us);

	if (ndd->s_probe_ongoing && should_init_probe_end(ndd, tsk)) {
		tsk->snd_cwnd = ndd->s_probe_prev_cwnd_pkts;
	}

	if (cruise_ended(ndd, tsk, rtt_us) || probe_ended(ndd, tsk, rtt_us)) {
		if (ndd->s_probe_ongoing) {
			update_state_after_probe_end(ndd);
			update_cwnd(ndd, tsk);
		}

		if (round_ended(ndd, tsk)) {
			reset_round_estimates(ndd);
		}

		if (should_probe(ndd, tsk)) {
			start_probe(ndd, tsk);
		}
	}

	// Update intervals
	// BUILD_BUG_ON(ndd_history_periods * 2 != ndd_num_intervals);
	// if (tcp_stamp_us_delta(timestamp, ndd->last_update_tstamp) >= ndd->min_rtt_us) {
	// ndd->intervals[ndd->intervals_head].pkts_acked = rs->acked_sacked;
	// ndd->intervals[ndd->intervals_head].pkts_lost = rs->losses;
	// ndd->intervals[ndd->intervals_head].app_limited = rs->is_app_limited;
	// ndd->intervals[ndd->intervals_head].min_rtt_us = rs->rtt_us;
	// ndd->intervals[ndd->intervals_head].max_rtt_us = rs->rtt_us;
	// ndd->intervals[ndd->intervals_head].ic_bytes_sent = tsk->bytes_sent;
	// ndd->intervals[ndd->intervals_head].ic_rs_prior_mstamp = rs->prior_mstamp;
	// ndd->intervals[ndd->intervals_head].ic_rs_prior_delivered = rs->prior_delivered;
	// ndd->intervals[ndd->intervals_head].ic_delivered = tsk->delivered;
	// ndd->intervals[ndd->intervals_head].processed = false;
	// ndd->intervals[ndd->intervals_head].invalid = false;
	// ndd->intervals[ndd->intervals_head].ic_sending_rate = sk->sk_pacing_rate / ndd_get_mss(tsk);

	// lower bound clamps
	// tsk->snd_cwnd = max_t(u32, tsk->snd_cwnd, ndd_alpha_segments);
	// sk->sk_pacing_rate = max_t(u64, sk->sk_pacing_rate, ndd_alpha_rate);

#ifdef NDD_DEBUG
	// printk(KERN_INFO
	// 		"ndd flow %u cwnd %u pacing %lu rtt %u mss %u timestamp %llu "
	// 		"interval %ld state %d",
	// 		ndd->id, tsk->snd_cwnd, sk->sk_pacing_rate, rtt_us,
	// 		tsk->mss_cache, timestamp, rs->interval_us, ndd->state);
	// printk(KERN_INFO
	// 		"ndd pkts_acked %u hist_us %u pacing %lu loss_happened %d "
	// 		"app_limited %d rs_limited %d latest_inflight_segments %u "
	// 		"delivered_bytes %llu",
	// 		pkts_acked, hist_us, sk->sk_pacing_rate,
	// 		(int)ndd->loss_happened, (int)app_limited,
	// 		(int)rs->is_app_limited, latest_inflight_segments,
	// 		((u64) ndd_get_mss(tsk)) * tsk->delivered);
#endif
	// printk(KERN_INFO "ndd_cong_ctrl got rtt_us %lu", rs->rtt_us);
	// printk(KERN_INFO "ndd_cong_ctrl cwnd %u pacing %lu", tsk->snd_cwnd, sk->sk_pacing_rate);
}

static void ndd_release(struct sock *sk) {
	struct ndd_data *ndd = inet_csk_ca(sk);
	// kfree(ndd->intervals);
}

static u32 ndd_ssthresh(struct sock *sk) { return TCP_INFINITE_SSTHRESH; }

static void ndd_cong_avoid(struct sock *sk, u32 ack, u32 acked) {}

static struct tcp_congestion_ops tcp_ndd_cong_ops __read_mostly = {
	.flags = TCP_CONG_NON_RESTRICTED,
	.name = "ndd",
	.owner = THIS_MODULE,
	.init = ndd_init,
	.release = ndd_release,
	.cong_control = ndd_cong_ctrl,
	/* Since NDD does reduce cwnd on loss. We use reno's undo method. */
	.undo_cwnd = tcp_reno_undo_cwnd,
	/* Slow start threshold will not exist */
	.ssthresh = ndd_ssthresh,
	.cong_avoid = ndd_cong_avoid,
};

static int __init ndd_register(void) {
	BUILD_BUG_ON(sizeof(struct ndd_data) > ICSK_CA_PRIV_SIZE);
#ifdef NDD_DEBUG
	printk(KERN_INFO "ndd init reg\n");
#endif
	return tcp_register_congestion_control(&tcp_ndd_cong_ops);
}

static void __exit ndd_unregister(void) {
	tcp_unregister_congestion_control(&tcp_ndd_cong_ops);
}

module_init(ndd_register);
module_exit(ndd_unregister);

MODULE_AUTHOR("Anup Agarwal <108anup@gmail.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP NDD (Provably fair and robust CC)");
MODULE_VERSION("0.1");