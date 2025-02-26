/*
NDD: A provably fair and robust congestion controller
*/

#include <net/tcp.h>

// #define NDD_DEBUG_VERBOSE
// #define NDD_DEBUG
#define NDD_INFO

#define USE_RTPROP_PROBE
// #define WAIT_RTT_AFTER_PROBE

#define P_SCALE 8 /* scaling factor for fractions (e.g. gains) */
#define P_UNIT (1 << P_SCALE)

// Assumptions about network scenarios
static const u32 p_ub_rtprop_us = 10000; // 10 ms
static const u32 p_ub_rtterr_us = 10000; // 10 ms
static const u32 p_ub_flow_count = 5;

// Design parameters
// TODO: check if these floating values make sense given the UNIT. Should we
// change the unit?
static const u32 p_lb_cwnd_pkts = 4;
// ^^ this should be such that, p_cwnd_clamp_hi increases this by at least 1,
// otherwise even at the maximum increase, the cwnd will not increase due to
// integer arithmetic.
static const u32 p_contract_min_qdel_us = p_ub_rtprop_us / 2;
// for stability p_contract_min_qdel_us >= rtprop / ground_truth_flow_count,
// for error, we need p_contract_min_qdel_us >= 2 * p_ub_rtterr_us
static const u32 p_probe_duration_us = 10000; // 10 ms. How should this be set?
static const u32 p_probe_multiplier_unit = P_UNIT * 4;
static const u32 p_cwnd_averaging_factor_unit = P_UNIT * 1 / 2;
static const u32 p_inv_cwnd_averaging_factor_unit = P_UNIT * 1 - p_cwnd_averaging_factor_unit;
static const u32 p_cwnd_clamp_hi_unit = P_UNIT * 13 / 10;
static const u32 p_cwnd_clamp_lo_unit = P_UNIT * 10 / 13;
static const u32 p_slot_load_factor_unit = P_UNIT * 2;
static const u32 p_slots_per_round =
	(p_slot_load_factor_unit * p_ub_flow_count) >> P_SCALE;
static const u32 p_rprobe_interval_us = 30000000; // 30 seconds

static u32 id = 0;

struct probe_data {
	bool s_probe_ongoing;
	u32 s_probe_min_rtt_us; // for logging only
	u32 s_probe_min_excess_delay_us;
	u32 s_probe_prev_cwnd_pkts;
	u32 s_probe_excess_pkts;
	bool s_probe_end_initiated;

	u64 s_probe_start_seq;
	u64 s_probe_inflightmatch_seq;
	u64 s_probe_first_seq;
	u64 s_probe_last_seq;
	u64 s_probe_first_seq_snd_time;
};

struct rprobe_data {
	bool s_rprobe_ongoing;
	u64 s_rprobe_prev_start_time_us;
	u64 s_rprobe_start_time_us;
	u64 s_rprobe_init_end_time_us;
	u32 s_rprobe_prev_cwnd_pkts;
	bool s_rprobe_end_initiated;
};

struct ndd_data {
	u32 id;
	u64 last_log_time_us;

	// State variables
	u32 s_min_rtprop_us;

	bool s_ss_done;
	bool s_ss_end_initiated;
	u64 s_ss_last_seq;

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
	u32 s_slot_min_rtt_us; // for logging only
	u32 s_slot_max_rtt_us; // for logging only

	struct probe_data *s_probe;
	struct rprobe_data *s_rprobe;
};

enum cwnd_event {
	SLOW_START,
	PROBE_GAIN,
	PROBE_DRAIN,
	PROBE_UPDATE,
	RPROBE_DRAIN,
	RPROBE_REFILL,
};

static void ndd_init(struct sock *sk)
{
	struct ndd_data *ndd = inet_csk_ca(sk);
	++id;
	ndd->id = id;
	ndd->last_log_time_us = 0;

	ndd->s_min_rtprop_us = U32_MAX;
	// TODO: we should reset this at some time to accommodate path changes.

	ndd->s_ss_done = false;
	ndd->s_ss_end_initiated = false;
	ndd->s_ss_last_seq = 0;

	ndd->s_round_slots_till_now = 0;
	ndd->s_round_min_rtt_us = U32_MAX;
	ndd->s_round_max_rate_pps = 0;
	ndd->s_round_probe_slot_idx = 1 + prandom_u32_max(p_slots_per_round);
	ndd->s_round_probed = false;

	ndd->s_slot_max_qdel_us = 0;
	ndd->s_slot_start_time_us = 0;
	ndd->s_slot_max_rate_pps = 0;
	ndd->s_slot_min_rtt_us = U32_MAX;
	ndd->s_slot_max_rtt_us = 0;

	ndd->s_probe = kzalloc(sizeof(struct probe_data), GFP_KERNEL);
	ndd->s_probe->s_probe_ongoing = false;
	ndd->s_probe->s_probe_min_excess_delay_us = U32_MAX;
	ndd->s_probe->s_probe_min_rtt_us = U32_MAX;
	ndd->s_probe->s_probe_prev_cwnd_pkts = 0;
	ndd->s_probe->s_probe_excess_pkts = 0;
	ndd->s_probe->s_probe_end_initiated = false;

	ndd->s_probe->s_probe_start_seq = 0;
	ndd->s_probe->s_probe_inflightmatch_seq = 0;
	ndd->s_probe->s_probe_first_seq = 0;
	ndd->s_probe->s_probe_last_seq = 0;
	ndd->s_probe->s_probe_first_seq_snd_time = 0;

	ndd->s_rprobe = kzalloc(sizeof(struct rprobe_data), GFP_KERNEL);
	ndd->s_rprobe->s_rprobe_ongoing = false;
	ndd->s_rprobe->s_rprobe_prev_start_time_us = 0;
	ndd->s_rprobe->s_rprobe_start_time_us = 0;
	ndd->s_rprobe->s_rprobe_init_end_time_us = 0;
	ndd->s_rprobe->s_rprobe_prev_cwnd_pkts = 0;
	ndd->s_rprobe->s_rprobe_end_initiated = false;

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

static u64 get_last_snd_seq(struct tcp_sock *tsk)
{
	// return tsk->segs_out;
	return tsk->snd_nxt;
}

static u64 get_last_rcv_seq(struct tcp_sock *tsk)
{
	// return tsk->segs_in;
	return tsk->snd_una;
}

static bool part_of_probe(struct ndd_data *ndd, struct tcp_sock *tsk)
{
	u64 last_rcv_seq = get_last_rcv_seq(tsk);
	if (ndd->s_probe->s_probe_first_seq > 0) {
		if (ndd->s_probe->s_probe_last_seq > 0) {
			return !before(last_rcv_seq,
				       ndd->s_probe->s_probe_first_seq) &&
			       !after(last_rcv_seq,
				      ndd->s_probe->s_probe_last_seq);
		} else {
			return !before(last_rcv_seq,
				       ndd->s_probe->s_probe_first_seq);
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
	u32 this_qdel;
	u32 init_rtt_us = get_initial_rtt(tsk);
	// TODO: Should we use the rs->delivered instead of snd_cwnd?
	u64 this_rate_pps = tsk->snd_cwnd * USEC_PER_SEC;
	do_div(this_rate_pps, rtt_us);

	ndd->s_min_rtprop_us = min_t(u32, ndd->s_min_rtprop_us, init_rtt_us);
	ndd->s_min_rtprop_us = min_t(u32, ndd->s_min_rtprop_us, rtt_us);

	ndd->s_round_min_rtt_us = min_t(u32, ndd->s_round_min_rtt_us, rtt_us);
	this_qdel = rtt_us - ndd->s_min_rtprop_us;

	if (ndd->s_probe->s_probe_ongoing && part_of_probe(ndd, tsk)) {
		u32 this_excess_delay_us = rtt_us - ndd->s_round_min_rtt_us;
		ndd->s_probe->s_probe_min_excess_delay_us =
			min_t(u32, ndd->s_probe->s_probe_min_excess_delay_us,
			      this_excess_delay_us);
		ndd->s_probe->s_probe_min_rtt_us =
			min_t(u32, ndd->s_probe->s_probe_min_rtt_us, rtt_us);
	} else if (!ndd->s_probe->s_probe_ongoing) {
		ndd->s_round_max_rate_pps =
			max_t(u64, ndd->s_round_max_rate_pps, this_rate_pps);
	}
	ndd->s_slot_max_qdel_us =
		max_t(u32, ndd->s_slot_max_qdel_us, this_qdel);
	ndd->s_slot_max_rate_pps =
		max_t(u64, ndd->s_slot_max_rate_pps, this_rate_pps);
	ndd->s_slot_max_rtt_us = max_t(u32, ndd->s_slot_max_rtt_us, rtt_us);
	ndd->s_slot_min_rtt_us = min_t(u32, ndd->s_slot_min_rtt_us, rtt_us);
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
	return ndd->s_probe->s_probe_last_seq > 0 &&
	       after(last_rcv_seq, ndd->s_probe->s_probe_last_seq);
}

static bool cruise_ended(struct ndd_data *ndd, u64 now_us)
{
	// Super conservative
	// u64 slot_duration_us = 3 * (ndd->s_slot_max_qdel_us +
	// p_ub_rtprop_us) + p_probe_duration_us;
	u64 slot_end_us;
	u64 slot_duration_us = 3 * ndd->s_slot_max_qdel_us +
			       2 * p_ub_rtprop_us + p_probe_duration_us;
#ifndef WAIT_RTT_AFTER_PROBE
	slot_duration_us = 2 * ndd->s_slot_max_qdel_us + p_ub_rtprop_us +
			   p_probe_duration_us;
#endif
	slot_end_us = ndd->s_slot_start_time_us + slot_duration_us;
	return time_after64(now_us, slot_end_us);
}

static bool should_init_probe_end(struct ndd_data *ndd, struct tcp_sock *tsk)
{
	u32 last_snd_seq = get_last_snd_seq(tsk);
	return ndd->s_probe->s_probe_last_seq > 0 &&
	       !before(last_snd_seq, ndd->s_probe->s_probe_last_seq) &&
	       !ndd->s_probe->s_probe_end_initiated;
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
	ndd->s_probe->s_probe_ongoing = false;
	ndd->s_probe->s_probe_min_rtt_us = U32_MAX;
	ndd->s_probe->s_probe_min_excess_delay_us = U32_MAX;
	ndd->s_probe->s_probe_prev_cwnd_pkts = 0; // should not be read anyway.
	ndd->s_probe->s_probe_excess_pkts = 0; // should not be read anyway.
	ndd->s_probe->s_probe_end_initiated = false;

	ndd->s_probe->s_probe_start_seq = 0;
	ndd->s_probe->s_probe_inflightmatch_seq = 0;
	ndd->s_probe->s_probe_first_seq = 0;
	ndd->s_probe->s_probe_last_seq = 0;
	ndd->s_probe->s_probe_first_seq_snd_time = 0;
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

void log_cwnd(enum cwnd_event reason, struct sock *sk, struct ndd_data *ndd,
	struct tcp_sock *tsk, u32 rtt_us, u64 now_us)
{
#ifdef NDD_INFO
  printk(KERN_INFO
	 "ndd cwnd_event flow %u reason %u now %llu cwnd %u pacing %lu rtt %u mss %u "
	 "min_rtprop %u round_min_rtt %u round_max_rate %u "
	 "slot_max_qdel %u slot_max_rate %u slot_min_rtt %u slot_max_rtt %u "
	 "probe_ongoing %u inflight %u "
	 "last_snd_seq %llu last_rcv_seq %llu",
	 ndd->id, reason, now_us, tsk->snd_cwnd, sk->sk_pacing_rate,
	 rtt_us, tsk->mss_cache, ndd->s_min_rtprop_us,
	 ndd->s_round_min_rtt_us, ndd->s_round_max_rate_pps,
	 ndd->s_slot_max_qdel_us, ndd->s_slot_max_rate_pps,
	 ndd->s_slot_min_rtt_us, ndd->s_slot_max_rtt_us,
	 ndd->s_probe->s_probe_ongoing, tsk->packets_out,
	 get_last_snd_seq(tsk), get_last_rcv_seq(tsk));
#endif
}

static void log_probe_start(struct sock *sk, struct ndd_data *ndd,
			    struct tcp_sock *tsk, u32 rtt_us, u64 now_us)
{
#ifdef NDD_INFO
	printk(KERN_INFO
	       "ndd probe_start flow %u now %llu cwnd %u pacing %lu rtt %u mss %u "
	       "min_rtt %u min_excess_delay %u "
	       "prev_cwnd %u excess_pkts %u probe_start_seq %llu",
	       ndd->id, now_us, tsk->snd_cwnd, sk->sk_pacing_rate, rtt_us,
	       tsk->mss_cache, ndd->s_probe->s_probe_min_rtt_us,
	       ndd->s_probe->s_probe_min_excess_delay_us, ndd->s_probe->s_probe_prev_cwnd_pkts,
	       ndd->s_probe->s_probe_excess_pkts, ndd->s_probe->s_probe_start_seq);
#endif
}

static void start_probe(struct sock *sk, struct ndd_data *ndd,
			struct tcp_sock *tsk, u32 rtt_us, u64 now_us)
{
	ndd->s_probe->s_probe_ongoing = true;
	ndd->s_probe->s_probe_min_rtt_us = U32_MAX;
	ndd->s_probe->s_probe_min_excess_delay_us = U32_MAX;
	ndd->s_probe->s_probe_prev_cwnd_pkts = tsk->snd_cwnd;
	ndd->s_probe->s_probe_excess_pkts = get_probe_excess(ndd);
	ndd->s_probe->s_probe_end_initiated = false;

	ndd->s_probe->s_probe_start_seq = get_last_snd_seq(tsk);
	ndd->s_probe->s_probe_inflightmatch_seq = 0;
	ndd->s_probe->s_probe_first_seq = 0;
	ndd->s_probe->s_probe_last_seq = 0;
	ndd->s_probe->s_probe_first_seq_snd_time = 0;

	tsk->snd_cwnd = tsk->snd_cwnd + ndd->s_probe->s_probe_excess_pkts;
	update_pacing_rate(sk, tsk, rtt_us);

	log_probe_start(sk, ndd, tsk, rtt_us, now_us);
	log_cwnd(PROBE_GAIN, sk, ndd, tsk, rtt_us, now_us);
}

static void start_new_slot(struct ndd_data *ndd, u64 now_us)
{
	ndd->s_slot_max_qdel_us = 0;
	ndd->s_slot_start_time_us = now_us;
	ndd->s_slot_max_rate_pps = 0;
	ndd->s_slot_min_rtt_us = U32_MAX;
	ndd->s_slot_max_rtt_us = 0;
}

static void update_probe_state(struct ndd_data *ndd, struct tcp_sock *tsk,
			       const struct rate_sample *rs, u32 rtt_us, u64 now_us)
{
	// TODO: use inflight = cwnd style checks for start and end of probe.
	// The RTT style checks are upper bounds.

	// TODO: The round durations will likely we off by one slot (because
	// probing slot duration may not be the same for all flows in this
	// tight interpretation) for flows with different propagation delays.
	// How might that affect things? We can just pad time if probe has
	// ended but slot has not.
	u64 last_rcv_seq;
	u64 last_snd_seq;
	u64 end_seq_snd_time;

	last_rcv_seq = get_last_rcv_seq(tsk);
	last_snd_seq = get_last_snd_seq(tsk);
	// TODO: check if we should use last_snd_seq or last_snd_seq + 1

#ifdef NDD_DEBUG_VERBOSE
	printk(KERN_INFO
	       "ndd probe_state flow %u now %llu probe_ongoing %u "
	       "last_snd_seq %llu last_rcv_seq %llu rtt %u cwnd %u inflight %u "
	       "probe_start_seq %llu probe_inflightmatch_seq %llu "
	       "probe_first_seq %llu probe_last_seq %llu part_of_probe %u ",
	       ndd->id, now_us, ndd->s_probe->s_probe_ongoing, last_snd_seq,
	       last_rcv_seq, rtt_us, tsk->snd_cwnd, tsk->packets_out,
	       ndd->s_probe->s_probe_start_seq,
	       ndd->s_probe->s_probe_inflightmatch_seq,
	       ndd->s_probe->s_probe_first_seq, ndd->s_probe->s_probe_last_seq,
	       part_of_probe(ndd, tsk));
#endif

	if (ndd->s_probe->s_probe_inflightmatch_seq == 0) {
		// The inflight match will happen after half pre-probe-RTT (old
		// RTT) under our pacing rate = 2 * new cwnd / old_rtt, i.e.,
		// last packet of new cwnd sent at time old_rtt/2.
		// Conservatively, we wait a full (packet timed) new RTT.
		// Alternatively, we can just check inflight = cwnd.
		if (after(last_rcv_seq, ndd->s_probe->s_probe_start_seq)) {
			ndd->s_probe->s_probe_inflightmatch_seq = last_snd_seq;
#ifndef WAIT_RTT_AFTER_PROBE
			ndd->s_probe->s_probe_first_seq = last_snd_seq;
			ndd->s_probe->s_probe_first_seq_snd_time = now_us;
#endif
#ifdef NDD_DEBUG
			printk(KERN_INFO
			       "ndd probe_inflightmatch flow %u "
			       "probe_inflightmatch_seq %llu probe_first_seq %llu last_snd_seq %llu last_rcv_seq %llu ",
			       ndd->id, ndd->s_probe->s_probe_inflightmatch_seq,
			       ndd->s_probe->s_probe_first_seq, last_snd_seq,
			       last_rcv_seq);
#endif
		}
	} else if (ndd->s_probe->s_probe_first_seq == 0) {
		if (after(last_rcv_seq,
			  ndd->s_probe->s_probe_inflightmatch_seq)) {
			ndd->s_probe->s_probe_first_seq = last_snd_seq;
			ndd->s_probe->s_probe_first_seq_snd_time = now_us;
#ifdef NDD_DEBUG
			printk(KERN_INFO
			       "ndd probe_first_seq flow %u probe_first_seq %llu "
			       "last_snd_seq %llu last_rcv_seq %llu now %llu ",
			       ndd->id, ndd->s_probe->s_probe_first_seq,
			       last_snd_seq, last_rcv_seq, now_us);
#endif
		}
	} else if (ndd->s_probe->s_probe_last_seq == 0) {
		end_seq_snd_time = ndd->s_probe->s_probe_first_seq_snd_time +
				   p_probe_duration_us;
		if (time_after64(now_us, end_seq_snd_time)) {
			ndd->s_probe->s_probe_last_seq = last_snd_seq;
#ifdef NDD_DEBUG
			printk(KERN_INFO
			       "ndd probe_last_seq flow %u probe_last_seq %llu "
			       "last_snd_seq %llu last_rcv_seq %llu now %llu ",
			       ndd->id, ndd->s_probe->s_probe_last_seq,
			       last_snd_seq, last_rcv_seq, now_us);
#endif
		}
	}
}

static void log_cwnd_update(struct sock *sk, struct ndd_data *ndd,
			    struct tcp_sock *tsk, u32 rtt_us,
			    u64 bw_estimate_pps, u64 flow_count_belief_unit,
			    u64 target_flow_count_unit, u64 target_cwnd_unit,
			    u64 next_cwnd_unit, u64 now_us)
{
#ifdef NDD_INFO
	printk(KERN_INFO
	       "ndd cwnd_update flow %u now %llu cwnd %u pacing %lu rtt %u mss %u "
	       "unit %u min_rtt_before %u min_rtt_after %u "
	       "prev_cwnd %u excess_pkts %u "
	       "excess_delay %u bw_estimate %llu "
	       "round_max_rate %u slot_max_qdel %u slot_max_rate %u slot_min_rtt %u slot_max_rtt %u "
	       "flow_count_target_unit %llu flow_count_belief_unit %llu "
	       "target_cwnd_unit %llu next_cwnd_unit %llu",
	       ndd->id, now_us, tsk->snd_cwnd, sk->sk_pacing_rate, rtt_us,
	       tsk->mss_cache, P_UNIT, ndd->s_round_min_rtt_us,
	       ndd->s_probe->s_probe_min_rtt_us, ndd->s_probe->s_probe_prev_cwnd_pkts,
	       ndd->s_probe->s_probe_excess_pkts, ndd->s_probe->s_probe_min_excess_delay_us,
	       bw_estimate_pps, ndd->s_round_max_rate_pps,
	       ndd->s_slot_max_qdel_us, ndd->s_slot_max_rate_pps,
	       ndd->s_slot_min_rtt_us, ndd->s_slot_max_rtt_us,
	       target_flow_count_unit, flow_count_belief_unit, target_cwnd_unit,
	       next_cwnd_unit);
#endif
}

static void log_slot_end(struct sock *sk, struct ndd_data *ndd,
			 struct tcp_sock *tsk, u32 rtt_us, u64 now_us)
{
#ifdef NDD_INFO
	u32 slot_duration_us =
		tcp_stamp_us_delta(now_us, ndd->s_slot_start_time_us);
	printk(KERN_INFO
	       "ndd slot_end flow %u now %llu cwnd %u pacing %lu rtt %u mss %u "
	       "slot_start %llu slot_end %llu "
	       "slot_duration %u probing %u slots_till_now %u "
	       "rtprop %u round_min_rtt %u round_max_rate %u "
	       "slot_max_qdel %u slot_max_rate %u slot_min_rtt %u slot_max_rtt %u",
	       ndd->id, now_us, tsk->snd_cwnd, sk->sk_pacing_rate, rtt_us,
	       tsk->mss_cache, ndd->s_slot_start_time_us, now_us,
	       slot_duration_us, ndd->s_probe->s_probe_ongoing,
	       ndd->s_round_slots_till_now, ndd->s_min_rtprop_us,
	       ndd->s_round_min_rtt_us, ndd->s_round_max_rate_pps,
	       ndd->s_slot_max_qdel_us, ndd->s_slot_max_rate_pps,
	       ndd->s_slot_min_rtt_us, ndd->s_slot_max_rtt_us);
#endif
}

static void update_cwnd(struct sock *sk, struct ndd_data *ndd,
			struct tcp_sock *tsk, u32 rtt_us, u64 now_us)
{
	u64 bw_estimate_pps;
	u64 flow_count_belief_unit;
	u64 target_flow_count_unit;
	u64 target_cwnd_unit;
	u64 next_cwnd_unit;
	u32 next_cwnd;
	u64 tcwnd_hi_clamp_unit = tsk->snd_cwnd * p_cwnd_clamp_hi_unit;
	u64 tcwnd_lo_clamp_unit = tsk->snd_cwnd * p_cwnd_clamp_lo_unit;

	bw_estimate_pps = U64_MAX;
	if (ndd->s_probe->s_probe_min_excess_delay_us > 0) {
		bw_estimate_pps = ndd->s_probe->s_probe_excess_pkts;
		bw_estimate_pps *= USEC_PER_SEC;
		do_div(bw_estimate_pps, ndd->s_probe->s_probe_min_excess_delay_us);
	}

	flow_count_belief_unit = p_ub_flow_count << P_SCALE;
	if (ndd->s_round_max_rate_pps > 0) {
		flow_count_belief_unit = P_UNIT;
		flow_count_belief_unit *= bw_estimate_pps;
		do_div(flow_count_belief_unit, ndd->s_round_max_rate_pps);
	}
	// TODO: is this needed? we clamp flow_count_belief anyway.
	// flow_count_belief_unit = min_t(u64, flow_count_belief_unit,
	// p_ub_flow_count << P_SCALE);
	flow_count_belief_unit = max_t(u64, flow_count_belief_unit, P_UNIT);

	target_flow_count_unit = get_target_flow_count_unit(ndd);

	// Even though in the proof we apply the clamps on Ni, we implement
	// clamps on target_cwnd because of integer arithmetic
	// (target_flow_count_unit might be small, so clamps times this might
	// be same as target_flow_count_unit). We expect cwnd to be large so
	// that the clamp times cwnd is a different value.
	if (target_flow_count_unit == 0) {
		target_cwnd_unit = tsk->snd_cwnd * p_cwnd_clamp_hi_unit;
	} else {
		target_cwnd_unit = tsk->snd_cwnd << P_SCALE;
		target_cwnd_unit *= flow_count_belief_unit;
		do_div(target_cwnd_unit, target_flow_count_unit);
	}
	target_cwnd_unit = max_t(u64, target_cwnd_unit, tcwnd_lo_clamp_unit);
	target_cwnd_unit = min_t(u64, target_cwnd_unit, tcwnd_hi_clamp_unit);

	next_cwnd_unit =
		p_inv_cwnd_averaging_factor_unit * tsk->snd_cwnd +
		((p_cwnd_averaging_factor_unit * target_cwnd_unit) >> P_SCALE);
#ifdef NDD_DEBUG
	printk(KERN_INFO
	       "ndd cwnd_update_debug flow %u alpha %u 1-alpha %u cwnd %u target_cwnd %llu next_cwnd %llu ",
	       ndd->id, p_cwnd_averaging_factor_unit,
	       p_inv_cwnd_averaging_factor_unit, tsk->snd_cwnd,
	       target_cwnd_unit, next_cwnd_unit);
#endif
	next_cwnd = DIV_ROUND_UP_ULL(next_cwnd_unit, P_UNIT);
	next_cwnd = max_t(u32, next_cwnd, p_lb_cwnd_pkts);
	tsk->snd_cwnd = next_cwnd;
	update_pacing_rate(sk, tsk, rtt_us);

	log_cwnd_update(sk, ndd, tsk, rtt_us, bw_estimate_pps,
			flow_count_belief_unit, target_flow_count_unit,
			target_cwnd_unit, next_cwnd_unit, now_us);
	log_cwnd(PROBE_UPDATE, sk, ndd, tsk, rtt_us, now_us);
}

static void log_periodic(struct sock *sk, struct ndd_data *ndd,
			 struct tcp_sock *tsk, u32 rtt_us, u64 now_us)
{
	if(time_after64(ndd->last_log_time_us + ndd->s_min_rtprop_us, now_us)) {
		return;
	}
	ndd->last_log_time_us = now_us;
#ifdef NDD_INFO
	printk(KERN_INFO
	       "ndd periodic flow %u now %llu cwnd %u pacing %lu rtt %u mss %u "
	       "min_rtprop %u round_min_rtt %u round_max_rate %u "
	       "slot_max_qdel %u slot_max_rate %u "
	       "probe_ongoing %u probe_min_rtt %u probe_min_excess_delay %u "
	       "probe_prev_cwnd %u probe_excess_pkts %u probe_end_initiated %u "
	       "probe_start_seq %llu probe_inflightmatch_seq %llu "
	       "probe_first_seq %llu probe_last_seq %llu inflight %u "
	       "last_snd_seq %llu last_rcv_seq %llu",
	       ndd->id, now_us, tsk->snd_cwnd, sk->sk_pacing_rate, rtt_us,
	       tsk->mss_cache, ndd->s_min_rtprop_us, ndd->s_round_min_rtt_us,
	       ndd->s_round_max_rate_pps, ndd->s_slot_max_qdel_us,
	       ndd->s_slot_max_rate_pps, ndd->s_probe->s_probe_ongoing,
	       ndd->s_probe->s_probe_min_rtt_us, ndd->s_probe->s_probe_min_excess_delay_us,
	       ndd->s_probe->s_probe_prev_cwnd_pkts, ndd->s_probe->s_probe_excess_pkts,
	       ndd->s_probe->s_probe_end_initiated, ndd->s_probe->s_probe_start_seq,
	       ndd->s_probe->s_probe_inflightmatch_seq,
	       ndd->s_probe->s_probe_first_seq, ndd->s_probe->s_probe_last_seq,
	       tsk->packets_out, get_last_snd_seq(tsk), get_last_rcv_seq(tsk));
#endif
}

static void slow_start(struct sock *sk, struct tcp_sock *tsk,
		       struct ndd_data *ndd, u64 now_us, u32 rtt_us)
{
	// Directly saying do slow start until target_flow_count is 1 is not
	// good because we use both min rtt to estimate rtprop and qdelay, so
	// the qdelay estimate is 0, as we only timeout after a round.

	// So instead we just say we want rtt to be more than min rtt +
	// contract_const + max_jitter, this ensures that we built a queue of
	// at least contract_const.

	// slot min rtt will be very small after slow start, it will be same as
	// the rtprop because both are min rtt since flow start, resetting the
	// slot min rtt will help get fresher estimate of queueing delay.

	// cwnd is continuously increasing, so if rtt goes above the target, it
	// will continue to increase, we want to reset slot and round estimates
	// when we expect the rtt to stop increasing.

	u64 last_recv_seq = get_last_rcv_seq(tsk);
	u64 last_snd_seq = get_last_snd_seq(tsk);
	bool should_init_ss_end = rtt_us > ndd->s_min_rtprop_us +
						   p_contract_min_qdel_us +
						   p_ub_rtterr_us;
	bool ss_ended = ndd->s_ss_last_seq > 0 &&
			after(last_recv_seq, ndd->s_ss_last_seq);

	if (!ndd->s_ss_end_initiated) {
		if (!should_init_ss_end) {
			tsk->snd_cwnd = tsk->snd_cwnd + 1;
			update_pacing_rate(sk, tsk, rtt_us);
			log_cwnd(SLOW_START, sk, ndd, tsk, rtt_us, now_us);
		} else {
			ndd->s_ss_end_initiated = true;
			ndd->s_ss_last_seq = last_snd_seq;
		}
	} else {
		if (ss_ended) {
			ndd->s_ss_done = true;
			reset_round_state(ndd);
			start_new_slot(ndd, now_us);
		} else {
			// ss end initiated but not yet ended. do nothing.
		}
	}
}

static u64 get_rprobe_time(u64 time_us)
{
	return (time_us / p_rprobe_interval_us) * p_rprobe_interval_us;
}

static bool should_rprobe(struct ndd_data *ndd, u64 now_us)
{
	return tcp_stamp_us_delta(now_us,
				  ndd->s_rprobe->s_rprobe_prev_start_time_us) >
	       p_rprobe_interval_us;
}

static void rprobe(struct sock *sk, struct ndd_data *ndd, struct tcp_sock *tsk,
		   u32 rtt_us, u64 now_us)
{
	// Note, these values only make sense when the boolean conditions they
	// are used in are met.
	u64 rprobe_duration_us = ndd->s_slot_max_qdel_us + p_ub_rtprop_us;
	u64 init_rprobe_end_us =
		ndd->s_rprobe->s_rprobe_start_time_us + rprobe_duration_us;
	bool should_init_rprobe_end = time_after64(now_us, init_rprobe_end_us);
	u64 rprobe_end_us = ndd->s_rprobe->s_rprobe_init_end_time_us +
			    2 * rprobe_duration_us;
	// Above, we wait two RTTs becuase it takes one RTT to fill the
	// inflight and then one more RTT to get the ACK of the last packet of
	// the filled inflight.
	bool rprobe_ended = ndd->s_rprobe->s_rprobe_init_end_time_us > 0 &&
			    time_after64(now_us, rprobe_end_us);

	if (!ndd->s_rprobe->s_rprobe_ongoing) {
		ndd->s_rprobe->s_rprobe_ongoing = true;
		ndd->s_rprobe->s_rprobe_prev_start_time_us =
			get_rprobe_time(now_us);
		ndd->s_rprobe->s_rprobe_start_time_us = now_us;
		ndd->s_rprobe->s_rprobe_init_end_time_us = 0;
		ndd->s_rprobe->s_rprobe_prev_cwnd_pkts = tsk->snd_cwnd;
		ndd->s_rprobe->s_rprobe_end_initiated = false;

		tsk->snd_cwnd = p_lb_cwnd_pkts;
		// update_pacing_rate(sk, tsk, rtt_us);

		// do not update pacing rate here, as linux takes time to
		// increase rate after decrease.
		log_cwnd(RPROBE_DRAIN, sk, ndd, tsk, rtt_us, now_us);
		return;
	}

	// rprobe ongoing
	if (!ndd->s_rprobe->s_rprobe_end_initiated) {
		if (should_init_rprobe_end) {
			ndd->s_rprobe->s_rprobe_end_initiated = true;
			ndd->s_rprobe->s_rprobe_init_end_time_us = now_us;
			tsk->snd_cwnd =
				ndd->s_rprobe->s_rprobe_prev_cwnd_pkts;
			update_pacing_rate(sk, tsk, rtt_us);
			log_cwnd(RPROBE_REFILL, sk, ndd, tsk, rtt_us, now_us);
		}
	} else {
		if (rprobe_ended) {
			ndd->s_rprobe->s_rprobe_ongoing = false;
			ndd->s_rprobe->s_rprobe_prev_start_time_us =
				get_rprobe_time(
					ndd->s_rprobe
						->s_rprobe_start_time_us);
			ndd->s_rprobe->s_rprobe_start_time_us = 0;
			ndd->s_rprobe->s_rprobe_init_end_time_us = 0;
			ndd->s_rprobe->s_rprobe_end_initiated = false;
			ndd->s_rprobe->s_rprobe_prev_cwnd_pkts = 0;

			// slow start may also be ongoing, in that
			// case, we do not touch slow start state. If
			// if ss end had been initiated then rprobe end
			// does the same thing, if end was not
			// initiated, we go back to slow start, now
			// with a better rtprop estimate.
			reset_probe_state(ndd);
			reset_round_state(ndd);
			start_new_slot(ndd, now_us);
		}
	}
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
	    rs->rtt_us <= 0)
		return;

	rtt_us = rs->rtt_us;
	update_estimates(ndd, tsk, rs, rtt_us);

	if (ndd->s_probe->s_probe_ongoing) {
		update_probe_state(ndd, tsk, rs, rtt_us, now_us);
	}

	log_periodic(sk, ndd, tsk, rtt_us, now_us);

#ifdef USE_RTPROP_PROBE
	if (should_rprobe(ndd, now_us) || ndd->s_rprobe->s_rprobe_ongoing) {
		rprobe(sk, ndd, tsk, rtt_us, now_us);
		return;
	}
#endif

	if (!ndd->s_ss_done) {
		slow_start(sk, tsk, ndd, now_us, rtt_us);
		return;
	}


	if (ndd->s_probe->s_probe_ongoing && should_init_probe_end(ndd, tsk)) {
		ndd->s_probe->s_probe_end_initiated = true;
		tsk->snd_cwnd = ndd->s_probe->s_probe_prev_cwnd_pkts;
		update_pacing_rate(sk, tsk, rtt_us);
		log_cwnd(PROBE_DRAIN, sk, ndd, tsk, rtt_us, now_us);
	}

	if ((!ndd->s_probe->s_probe_ongoing && cruise_ended(ndd, now_us)) ||
	    (ndd->s_probe->s_probe_ongoing && probe_ended(ndd, tsk))) {
		ndd->s_round_slots_till_now++;
		log_slot_end(sk, ndd, tsk, rtt_us, now_us);

		// probe ended
		if (ndd->s_probe->s_probe_ongoing) {
			update_cwnd(sk, ndd, tsk, rtt_us, now_us);
			reset_probe_state(ndd);
		}

		if (round_ended(ndd, tsk)) {
			reset_round_state(ndd);
		}

		if (ndd->s_round_slots_till_now >= 1 && !ndd->s_round_probed &&
		    should_probe(ndd)) {
			ndd->s_round_probed = true;
			start_probe(sk, ndd, tsk, rtt_us, now_us);
		}
		start_new_slot(ndd, now_us);
	}
}

static void ndd_release(struct sock *sk)
{
	struct ndd_data *ndd = inet_csk_ca(sk);
	kfree(ndd->s_probe);
	kfree(ndd->s_rprobe);
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
#ifdef NDD_INFO
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