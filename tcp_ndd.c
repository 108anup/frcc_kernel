/*
NDD: A provably fair and robust congestion controller
*/

#include <net/tcp.h>

#define NDD_DEBUG
#define P_SCALE 8 /* scaling factor for fractions (e.g. gains) */
#define P_UNIT (1 << P_SCALE)

// Assumptions about network scenarios
static const u32 p_ub_rtprop_us = 100000; // 100 ms
static const u32 p_ub_rtterr_us = 10000; // 10 ms
static const u32 p_ub_flow_count = 10;

// Design parameters
// TODO: check if these floating values make sense given the UNIT. Should we
// change the unit?
static const u32 p_contract_min_qdel_us = p_ub_rtprop_us / 2;
static const u32 p_probe_duration_us =
	p_ub_rtterr_us; // ? Do we want something else here?
static const u32 p_probe_multiplier_unit = P_UNIT * 4;
static const u32 p_cwnd_averaging_factor_unit = P_UNIT * 1 / 2;
static const u32 p_cwnd_clamp_hi_unit = P_UNIT * 6 / 5;
static const u32 p_cwnd_clamp_lo_unit = P_UNIT * 11 / 10;
static const u32 p_slot_load_factor_unit = P_UNIT * 2;
static const u32 p_slots_per_round =
	(((u64)p_slot_load_factor_unit) * p_ub_flow_count) << P_SCALE;

static u32 id = 0;
struct ndd_data {
	u32 id;

	// State variables
	u64 s_min_rtprop_us;

	u32 s_round_slots_till_now;
	u32 s_round_min_rtt_us;
	u32 s_round_max_rate_pps;
	u32 s_round_probe_slot_idx;
	bool s_round_probed;
	// pps = packets per second, supports range: [1500 bytes per sec to
	// 6.44 terabytes per second]

	u32 s_slot_max_qdel_us;
	u64 s_slot_start_time_us;
	u32 s_slot_max_rate_pps; // for logging only

	bool s_probe_ongoing;
	u32 s_probe_min_rtt_us; // for logging only
	u32 s_probe_min_excess_delay_us;
	u32 s_probe_prev_cwnd_pkts;
	u32 s_probe_excess_pkts;
	bool s_probe_end_initiated;

	u32 s_probe_start_seq;
	u32 s_probe_inflightmatch_seq;
	u32 s_probe_first_seq;
	u32 s_probe_last_seq;
	u64 s_probe_first_seq_snd_time;
};

static void ndd_init(struct sock *sk)
{
	struct ndd_data *ndd = inet_csk_ca(sk);
	++id;
	ndd->id = id;

	ndd->s_min_rtprop_us = p_ub_rtprop_us;

	ndd->s_round_slots_till_now = 0;
	ndd->s_round_min_rtt_us = U32_MAX;
	ndd->s_round_max_rate_pps = 0;
	ndd->s_round_probe_slot_idx = 1 + prandom_u32_max(p_slots_per_round);
	ndd->s_round_probed = false;

	ndd->s_slot_max_qdel_us = 0;
	ndd->s_slot_start_time_us = 0;
	ndd->s_slot_max_rate_pps = 0;

	ndd->s_probe_ongoing = false;
	ndd->s_probe_min_excess_delay_us = U32_MAX;
	ndd->s_probe_min_rtt_us = U32_MAX;
	ndd->s_probe_prev_cwnd_pkts = 0;
	ndd->s_probe_excess_pkts = 0;
	ndd->s_probe_end_initiated = false;

	ndd->s_probe_start_seq = 0;
	ndd->s_probe_inflightmatch_seq = 0;
	ndd->s_probe_first_seq = 0;
	ndd->s_probe_last_seq = 0;
	ndd->s_probe_first_seq_snd_time = 0;

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}

static u32 ndd_get_mss(struct tcp_sock *tsk)
{
	// TODO: Figure out if mss_cache is the one to use
	return tsk->mss_cache;
}

/* was the ndd struct fully inited */
static bool ndd_valid(struct ndd_data *ndd)
{
	return (ndd);
}

// TODO: Check what sequence numbers to use
static u32 get_last_snd_seq(struct tcp_sock *tsk)
{
	return tsk->data_segs_out;
}

static u32 get_last_rcv_seq(struct tcp_sock *tsk)
{
	return tsk->data_segs_in;
}

static bool part_of_probe(struct ndd_data *ndd, struct tcp_sock *tsk)
{
	u64 last_rcv_seq = get_last_rcv_seq(tsk);
	if (ndd->s_probe_start_seq > 0) {
		if (ndd->s_probe_last_seq > 0) {
			return !before(last_rcv_seq, ndd->s_probe_start_seq) &&
			       !after(last_rcv_seq, ndd->s_probe_last_seq);
		} else {
			return !before(last_rcv_seq, ndd->s_probe_start_seq);
		}
	}
	return false;
}

static u32 get_initial_rtt(struct tcp_sock *tsk)
{
	// TODO: Should we be calling this every packet?
	// Get initial RTT - as measured by SYN -> SYN-ACK.  If information
	// does not exist - use U32_MAX
	u32 init_rtt_us;
	if (tsk->srtt_us) {
		init_rtt_us = max_t(u32, tsk->srtt_us >> 3, 1U);
	} else {
		init_rtt_us = U32_MAX;
	}
	return init_rtt_us;
}

static void update_pacing_rate(struct sock *sk, struct tcp_sock *tsk, u32 rtt_us)
{
	// TODO: should we use tsk->srtt instead of latest rtt_us?
	u64 next_rate_bps = 2 * tsk->snd_cwnd * ndd_get_mss(tsk) * USEC_PER_SEC;
	do_div(next_rate_bps, rtt_us);
	sk->sk_pacing_rate = next_rate_bps;
}


static void update_estimates(struct ndd_data *ndd, struct tcp_sock *tsk,
			     const struct rate_sample *rs, u32 rtt_us)
{
	u32 this_qdel = rtt_us - ndd->s_min_rtprop_us;
	u32 init_rtt_us = get_initial_rtt(tsk);
	// TODO: Should we use the rs->delivered instead of snd_cwnd?
	u64 this_rate_pps = tsk->snd_cwnd * USEC_PER_SEC;
	do_div(this_rate_pps, rtt_us);

	ndd->s_min_rtprop_us = min_t(u32, ndd->s_min_rtprop_us, init_rtt_us);
	ndd->s_min_rtprop_us = min_t(u32, ndd->s_min_rtprop_us, rtt_us);

	ndd->s_round_min_rtt_us = min_t(u32, ndd->s_round_min_rtt_us, rtt_us);

	if (ndd->s_probe_ongoing && part_of_probe(ndd, tsk)) {
		u32 this_excess_delay_us = rtt_us - ndd->s_round_min_rtt_us;
		ndd->s_probe_min_excess_delay_us =
			min_t(u32, ndd->s_probe_min_excess_delay_us,
			      this_excess_delay_us);
		ndd->s_probe_min_rtt_us =
			min_t(u32, ndd->s_probe_min_rtt_us, rtt_us);
	} else if (!ndd->s_probe_ongoing) {
		ndd->s_slot_max_qdel_us =
			max_t(u32, ndd->s_slot_max_qdel_us, this_qdel);
		ndd->s_round_max_rate_pps =
			max_t(u64, ndd->s_round_max_rate_pps, this_rate_pps);
		ndd->s_slot_max_rate_pps =
			max_t(u64, ndd->s_slot_max_rate_pps, this_rate_pps);
	}
}

static void reset_round_state(struct ndd_data *ndd)
{
	ndd->s_round_slots_till_now = 0;
	ndd->s_round_min_rtt_us = U32_MAX;
	ndd->s_round_max_rate_pps = 0;
	ndd->s_round_probe_slot_idx = 1 + prandom_u32_max(p_slots_per_round);
	ndd->s_round_probed = false;
}

static bool probe_ended(struct ndd_data *ndd, struct tcp_sock *tsk)
{
	u64 last_rcv_seq = get_last_rcv_seq(tsk);
	return ndd->s_probe_last_seq > 0 && after(last_rcv_seq, ndd->s_probe_last_seq);
}

static bool cruise_ended(struct ndd_data *ndd, u64 now_us)
{
	u64 slot_duration_us = 3 * (ndd->s_slot_max_qdel_us + p_ub_rtprop_us) +
			       p_probe_duration_us;
	u64 slot_end_us = ndd->s_slot_start_time_us + slot_duration_us;
	return time_after64(now_us, slot_end_us);
}

static bool should_init_probe_end(struct ndd_data *ndd, struct tcp_sock *tsk)
{
	u32 last_snd_seq = get_last_snd_seq(tsk);
	return ndd->s_probe_last_seq >= 0 &&
	       !before(last_snd_seq, ndd->s_probe_last_seq) &&
	       !ndd->s_probe_end_initiated;
}

static u64 get_slots_per_round(void)
{
	u64 slots_per_round;
	slots_per_round = p_ub_flow_count;
	slots_per_round *= p_slot_load_factor_unit;
	slots_per_round <<= P_SCALE;
	return slots_per_round;
}

static bool round_ended(struct ndd_data *ndd, struct tcp_sock *tsk)
{
	return ndd->s_round_slots_till_now >= p_slots_per_round;
}

static bool should_probe(struct ndd_data *ndd)
{
	return ndd->s_round_slots_till_now >= ndd->s_round_probe_slot_idx;
}

static void reset_probe_state(struct ndd_data *ndd)
{
	ndd->s_probe_ongoing = false;
	ndd->s_probe_min_rtt_us = U32_MAX;
	ndd->s_probe_min_excess_delay_us = U32_MAX;
	ndd->s_probe_prev_cwnd_pkts = 0; // should not be read anyway.
	ndd->s_probe_excess_pkts = 0; // should not be read anyway.
	ndd->s_probe_end_initiated = false;

	ndd->s_probe_start_seq = 0;
	ndd->s_probe_inflightmatch_seq = 0;
	ndd->s_probe_first_seq = 0;
	ndd->s_probe_last_seq = 0;
	ndd->s_probe_first_seq_snd_time = 0;
}

static u32 get_target_flow_count_unit(struct ndd_data *ndd)
{
	u32 round_qdel_us;
	u32 target_flow_count_unit;

	round_qdel_us = ndd->s_round_min_rtt_us - ndd->s_min_rtprop_us;
	target_flow_count_unit = P_UNIT;
	target_flow_count_unit *= round_qdel_us;
	do_div(target_flow_count_unit, p_contract_min_qdel_us);

	return target_flow_count_unit;
}

static u32 get_probe_excess(struct ndd_data *ndd)
{
	u32 target_flow_count_unit;
	u64 excess_pkts;

	target_flow_count_unit = get_target_flow_count_unit(ndd);
	excess_pkts = p_probe_multiplier_unit;
	excess_pkts *= target_flow_count_unit;
	excess_pkts >>= P_SCALE;
	excess_pkts *= ndd->s_round_max_rate_pps;
	excess_pkts *= p_ub_rtterr_us;
	excess_pkts >>= P_SCALE;
	excess_pkts = DIV_ROUND_UP_ULL(excess_pkts, USEC_PER_SEC);
	excess_pkts = max_t(u64, excess_pkts, 1);

	return excess_pkts;
}

static void start_probe(struct sock *sk, struct ndd_data *ndd,
			struct tcp_sock *tsk, u32 rtt_us)
{
	ndd->s_probe_ongoing = true;
	ndd->s_probe_min_rtt_us = U32_MAX;
	ndd->s_probe_min_excess_delay_us = U32_MAX;
	ndd->s_probe_prev_cwnd_pkts = tsk->snd_cwnd;
	ndd->s_probe_excess_pkts = get_probe_excess(ndd);
	ndd->s_probe_end_initiated = false;

	ndd->s_probe_start_seq = get_last_snd_seq(tsk);
	ndd->s_probe_inflightmatch_seq = 0;
	ndd->s_probe_first_seq = 0;
	ndd->s_probe_last_seq = 0;
	ndd->s_probe_first_seq_snd_time = 0;

	tsk->snd_cwnd += ndd->s_probe_excess_pkts;
	update_pacing_rate(sk, tsk, rtt_us);
}

static void start_new_slot(struct ndd_data *ndd, u64 now_us)
{
	ndd->s_slot_max_qdel_us = 0;
	ndd->s_slot_start_time_us = now_us;
	ndd->s_slot_max_rate_pps = 0;
}

static void update_probe_state(struct ndd_data *ndd, struct tcp_sock *tsk,
			       const struct rate_sample *rs, u64 now_us)
{
	u64 last_rcv_seq;
	u64 last_snd_seq;
	u64 end_seq_snd_time;

	last_rcv_seq = get_last_rcv_seq(tsk);
	last_snd_seq = get_last_snd_seq(tsk);
	// TODO: check if we should use last_snd_seq or last_snd_seq + 1

	if (ndd->s_probe_inflightmatch_seq == 0) {
		// TODO: currently assuming the inflight match will happen
		// within 1 RTT, ideally just check inflight = cwnd.
		if (after(last_rcv_seq, ndd->s_probe_start_seq)) {
			ndd->s_probe_inflightmatch_seq = last_snd_seq;
		}
	}
	else if (ndd->s_probe_first_seq == 0) {
		if (after(last_rcv_seq, ndd->s_probe_inflightmatch_seq)) {
			ndd->s_probe_first_seq = last_snd_seq;
			ndd->s_probe_first_seq_snd_time = now_us;
		}
	} else if (ndd->s_probe_last_seq == 0) {
		end_seq_snd_time = ndd->s_probe_first_seq_snd_time + p_probe_duration_us;
		if (time_after64(now_us, end_seq_snd_time)) {
			ndd->s_probe_last_seq = last_snd_seq;
		}
	}
}

static void log_cwnd_update(struct sock *sk, struct ndd_data *ndd,
			    struct tcp_sock *tsk, u32 rtt_us,
			    u64 bw_estimate_pps, u64 flow_count_belief_unit,
			    u64 target_flow_count_unit, u64 target_cwnd_unit,
			    u64 next_cwnd_unit)
{
#ifdef NDD_DEBUG
	printk(KERN_INFO
	       "ndd cwnd_update_1 flow %u cwnd %u pacing %lu rtt %u mss %u ",
	       ndd->id, tsk->snd_cwnd, sk->sk_pacing_rate, rtt_us,
	       tsk->mss_cache);
	printk(KERN_INFO
	       "ndd cwnd_update_2 flow %u unit %u"
	       "min_rtt_before %u min_rtt_after %u "
	       "prev_cwnd %u excess_pkts %u "
	       "excess_delay %u bw_estimate %llu "
	       "round_max_rate %u slot_max_rate %u "
	       "flow_count_target_unit %llu flow_count_belief_unit %llu "
	       "target_cwnd_unit %llu next_cwnd_unit %llu ",
	       ndd->id, P_UNIT, ndd->s_round_min_rtt_us,
	       ndd->s_probe_min_rtt_us, ndd->s_probe_prev_cwnd_pkts,
	       ndd->s_probe_excess_pkts, ndd->s_probe_min_excess_delay_us,
	       bw_estimate_pps, ndd->s_round_max_rate_pps,
	       ndd->s_slot_max_rate_pps, target_flow_count_unit,
	       flow_count_belief_unit, target_cwnd_unit, next_cwnd_unit);
#endif
}

static void log_slot_end(struct ndd_data *ndd, struct tcp_sock *tsk, u32 rtt_us)
{
}

static void update_cwnd(struct sock* sk, struct ndd_data *ndd, struct tcp_sock *tsk, u32 rtt_us)
{
	u64 bw_estimate_pps;
	u64 flow_count_belief_unit;
	u64 target_flow_count_unit;
	u64 fc_belief_hi_clamp;
	u64 fc_belief_lo_clamp;
	u64 target_cwnd_unit;
	u64 next_cwnd_unit;

	bw_estimate_pps = ndd->s_probe_excess_pkts;
	bw_estimate_pps *= USEC_PER_SEC;
	do_div(bw_estimate_pps, ndd->s_probe_min_excess_delay_us);

	flow_count_belief_unit = P_UNIT;
	flow_count_belief_unit *= bw_estimate_pps;
	do_div(flow_count_belief_unit, ndd->s_round_max_rate_pps);

	target_flow_count_unit = get_target_flow_count_unit(ndd);
	fc_belief_hi_clamp =
		(target_flow_count_unit * p_cwnd_clamp_hi_unit) >> P_SCALE;
	fc_belief_lo_clamp =
		(target_flow_count_unit * p_cwnd_clamp_lo_unit) >> P_SCALE;

	flow_count_belief_unit =
		min_t(u64, flow_count_belief_unit, fc_belief_hi_clamp);

	if (target_flow_count_unit < P_UNIT) {
		flow_count_belief_unit = fc_belief_hi_clamp;
	} else {
		flow_count_belief_unit =
			max_t(u64, flow_count_belief_unit, fc_belief_lo_clamp);
	}

	target_cwnd_unit = tsk->snd_cwnd << P_SCALE;
	target_cwnd_unit *= flow_count_belief_unit;
	do_div(target_cwnd_unit, target_flow_count_unit);

	next_cwnd_unit =
		(1 - p_cwnd_averaging_factor_unit) * tsk->snd_cwnd +
		((p_cwnd_averaging_factor_unit * target_cwnd_unit) >> P_SCALE);
	tsk->snd_cwnd = DIV_ROUND_UP_ULL(next_cwnd_unit, P_UNIT);

	update_pacing_rate(sk, tsk, rtt_us);

	log_cwnd_update(sk, ndd, tsk, rtt_us, bw_estimate_pps,
			flow_count_belief_unit, target_flow_count_unit,
			target_cwnd_unit, next_cwnd_unit);
}

static void on_ack(struct sock *sk, const struct rate_sample *rs)
{
	struct ndd_data *ndd = inet_csk_ca(sk);
	struct tcp_sock *tsk = tcp_sk(sk);
	u32 rtt_us;
	u64 now_us = tsk->tcp_mstamp;
	// u32 latest_inflight_segments = rs->prior_in_flight;

	// Is struct valid? Is rate sample valid? Is RTT valid?
	if (!ndd_valid(ndd) || rs->delivered < 0 || rs->interval_us < 0 ||
	    rs->rtt_us < 0)
		return;

	rtt_us = rs->rtt_us;
	update_estimates(ndd, tsk, rs, rtt_us);

	if (ndd->s_probe_ongoing) {
		update_probe_state(ndd, tsk, rs, now_us);
	}

	if (ndd->s_probe_ongoing && should_init_probe_end(ndd, tsk)) {
		ndd->s_probe_end_initiated = true;
		tsk->snd_cwnd = ndd->s_probe_prev_cwnd_pkts;
		update_pacing_rate(sk, tsk, rtt_us);
	}

	if (cruise_ended(ndd, now_us) || probe_ended(ndd, tsk)) {
		ndd->s_round_slots_till_now++;

		// probe ended
		if (ndd->s_probe_ongoing) {
			update_cwnd(sk, ndd, tsk, rtt_us);
			reset_probe_state(ndd);
		}

		if (round_ended(ndd, tsk)) {
			reset_round_state(ndd);
		}

		if (ndd->s_round_slots_till_now >= 1 && !ndd->s_round_probed &&
		    should_probe(ndd)) {
			ndd->s_round_probed = true;
			start_probe(sk, ndd, tsk, rtt_us);
		}
		start_new_slot(ndd, now_us);
	}
}

static void ndd_release(struct sock *sk)
{
	// struct ndd_data *ndd = inet_csk_ca(sk);
	// kfree(ndd->intervals);
}

static u32 ndd_ssthresh(struct sock *sk)
{
	return TCP_INFINITE_SSTHRESH;
}

static void ndd_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
}

static struct tcp_congestion_ops tcp_ndd_cong_ops __read_mostly = {
	.flags = TCP_CONG_NON_RESTRICTED,
	.name = "ndd",
	.owner = THIS_MODULE,
	.init = ndd_init,
	.release = ndd_release,
	.cong_control = on_ack,
	// Since NDD does reduce cwnd on loss. We use reno's undo method.
	.undo_cwnd = tcp_reno_undo_cwnd,
	// Slow start threshold will not exist
	.ssthresh = ndd_ssthresh,
	.cong_avoid = ndd_cong_avoid,
};

static int __init ndd_register(void)
{
	BUILD_BUG_ON(sizeof(struct ndd_data) > ICSK_CA_PRIV_SIZE);
#ifdef NDD_DEBUG
	printk(KERN_INFO "ndd module_install ");
#endif
	return tcp_register_congestion_control(&tcp_ndd_cong_ops);
}

static void __exit ndd_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_ndd_cong_ops);
}

module_init(ndd_register);
module_exit(ndd_unregister);

MODULE_AUTHOR("Anup Agarwal <108anup@gmail.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP NDD (Provably fair and robust CC)");
MODULE_VERSION("0.1");