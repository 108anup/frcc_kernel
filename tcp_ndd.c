/*
NDD: A provably fair and robust congestion controller
*/

#include <net/tcp.h>
#include <linux/build_bug.h>

#define NDD_DEBUG
#define U64_S_TO_US ((u64) 1e6)
#define INIT_MAX_C ((u64) 1e5)
// ^^ This is roughly 1.20 Gbps for 1448 MSS
# define INIT_MIN_C ((u64) 1)
// ^^ This is roughly 12 Kbps for 1448 MSS

// Should be a power of two so ndd_num_intervals_mask can be set
static const u16 ndd_num_intervals = 16;
// ndd_num_intervals expressed as a mask. It is always equal to
// ndd_num_intervals-1
static const u16 ndd_num_intervals_mask = 15;
static const u32 ndd_alpha_segments = 5;
// Maximum tolerable loss rate, expressed as `loss_thresh / 1024`. Calculations
// are faster if things are powers of 2
static const u64 ndd_loss_thresh = 64;
static const u32 ndd_periods_between_large_loss = 8;
static const u32 ndd_history_periods = 8;
static const u32 ndd_timeout_period = 12;
static const u32 ndd_significant_mult_percent = 110;

static const u32 ndd_measurement_interval = 1;

enum ndd_state {
	SLOW_START,
	CONG_AVOID
};

// To keep track of the number of packets acked over a short period of time
struct ndd_interval {
	// Starting time of this interval
	u64 start_us;
	u32 pkts_acked;
	u32 pkts_lost;
	bool app_limited;
	u32 min_rtt_us;
	u32 max_rtt_us;

	// metrics at interval creation time
	u64 ic_rs_prior_mstamp;
	u32 ic_rs_prior_delivered;
	u64 ic_bytes_sent;
	u64 ic_delivered;
	u64 ic_sending_rate;  // segments per second

	bool processed;
	bool invalid;
};

struct belief_data {
	u64 min_c;  // segments or packets per second
	u64 max_c;  // segments or packets per second
	u32 min_qdel;  // in microseconds
	u64 min_c_lambda;  // segments or packets per second
	u64 last_min_c_lambda;  // segments or packets per second
	bool odd_even;
};

static u32 id = 0;
struct ndd_data {
	// Circular queue of intervals
	struct ndd_interval *intervals;
	// Index of the last interval to be added
	u16 intervals_head;

	u32 min_rtt_us;

	// debug helper
	u32 id;

	u32 last_decrease_seq;
	bool loss_happened;

	u64 last_update_tstamp;
	u64 last_segs_sent;
	u64 last_segs_delivered;
	u64 estimated_cumulative_segs_sent;

	// u64 last_loss_tstamp;

	struct belief_data *beliefs;

	u64 last_timeout_tstamp;
	u64 last_timeout_minc;
	u64 last_timeout_maxc;

	enum ndd_state state;
};

static void ndd_init(struct sock *sk)
{
	struct ndd_data *ndd = inet_csk_ca(sk);
	u16 i;

	ndd->intervals = kzalloc(sizeof(*(ndd->intervals)) * ndd_num_intervals,
				  GFP_KERNEL);
	for (i = 0; i < ndd_num_intervals; ++i) {
		ndd->intervals[i].start_us = 0;
		ndd->intervals[i].pkts_acked = 0;
		ndd->intervals[i].pkts_lost = 0;
		ndd->intervals[i].app_limited = false;
		ndd->intervals[i].min_rtt_us = U32_MAX;
		ndd->intervals[i].max_rtt_us = 0;

		ndd->intervals[i].ic_rs_prior_mstamp = 0;
		ndd->intervals[i].ic_rs_prior_delivered = 0;
		ndd->intervals[i].ic_bytes_sent = 0;
		ndd->intervals[i].ic_delivered = 0;

		ndd->intervals[i].processed = false;
		ndd->intervals[i].invalid = true;
	}
	ndd->intervals_head = 0;

	ndd->min_rtt_us = U32_MAX;
	++id;
	ndd->id = id;
	// At connection setup, assume just decreased.
	// We don't expect loss during initial part of slow start anyway.
	ndd->last_decrease_seq = tcp_sk(sk)->snd_nxt;

	// We want update to happen if it hasn't happened since Rm time.
	// Setting last time as 0 in the beginning should allow running cwnd update
	// the first time as long as min_rtt_us < timestamp.
	ndd->last_update_tstamp = 0; // tcp_sk(sk)->tcp_mstamp;
	ndd->last_segs_sent = 0;
	ndd->last_segs_delivered = 0;
	ndd->estimated_cumulative_segs_sent = 0;
	ndd->loss_happened = false;

	// ndd->last_loss_tstamp = 0; // tcp_sk(sk)->tcp_mstamp;

	ndd->beliefs = kzalloc(sizeof(*(ndd->beliefs)), GFP_KERNEL);
	ndd->beliefs->max_c = INIT_MAX_C;
	// Setting this as U32_MAX and then setting cwnd as U32_MAX causes issues
	// with the kernel... Earlier set as U32_MAX, even though, max_c is u64,
	// keeping it at u32_max so that we can multiply and divide by microseconds.
	ndd->beliefs->min_c = INIT_MIN_C;
	ndd->beliefs->min_qdel = 0;
	ndd->beliefs->min_c_lambda = INIT_MIN_C;
	ndd->beliefs->last_min_c_lambda = INIT_MIN_C;
	ndd->beliefs->odd_even = false;

	ndd->last_timeout_tstamp = 0;
	ndd->last_timeout_minc = INIT_MIN_C;
	ndd->last_timeout_maxc = INIT_MAX_C;

	ndd->state = SLOW_START;

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
	// printk(KERN_INFO "ndd: Initialized ndd with max_c %llu", ndd->beliefs->max_c);
}

static u32 ndd_get_mss(struct tcp_sock *tsk)
{
	// TODO: Figure out if mss_cache is the one to use
	return tsk->mss_cache;
}

/* was the ndd struct fully inited */
static bool ndd_valid(struct ndd_data *ndd)
{
	return (ndd && ndd->intervals);
}

static bool get_loss_mode(u32 pkts_acked, u32 pkts_lost) {
	bool loss_mode = (u64)pkts_lost * 1024 >
					 (u64)(pkts_acked + pkts_lost) * ndd_loss_thresh;
	return loss_mode;
}

static void update_beliefs(struct sock *sk) {
	struct tcp_sock *tsk = tcp_sk(sk);
	struct ndd_data *ndd = inet_csk_ca(sk);

	u16 st;
	u16 et = ndd->intervals_head;  // end time
	u64 et_tstamp = ndd->intervals[et & ndd_num_intervals_mask].start_us;

	u32 this_min_rtt_us;

	u64 st_tstamp;
	u32 cum_pkts_acked = 0;
	// u64 cum_ack_rate;
	u32 window;

	bool this_loss;
	bool this_high_delay;
	bool this_utilized;
	bool cum_utilized;

	struct ndd_interval *this_interval;
	struct belief_data *beliefs = ndd->beliefs;
	u32 rtprop = ndd->min_rtt_us;
	u32 max_jitter = rtprop;

	u64 new_min_c = INIT_MIN_C;
	u64 new_max_c = INIT_MAX_C;
	u64 ndd_alpha_rate = (ndd_alpha_segments * ndd_get_mss(tsk) * U64_S_TO_US) / ndd->min_rtt_us;
	u64 max_c_lower_clamp = max_t(u64, INIT_MIN_C, ndd_alpha_rate);

	u64 now = et_tstamp;
	u32 time_since_last_timeout = tcp_stamp_us_delta(now, ndd->last_timeout_tstamp);
	bool timeout = time_since_last_timeout > ndd_timeout_period * ndd->min_rtt_us;

	// UPDATE QDEL BELIEFS
	this_interval = &ndd->intervals[et & ndd_num_intervals_mask];
	this_min_rtt_us = this_interval->min_rtt_us;
	if(this_min_rtt_us > rtprop + max_jitter && !(this_interval->invalid)) {
		beliefs->min_qdel = this_min_rtt_us - (rtprop + max_jitter);
	}
	else {
		beliefs->min_qdel = 0;
	}

	// UPDATE LINK RATE BELIEFS
	// The et interval might have just started with very few measurements. So
	// we ignore measurements in that interval (start st at 1 instead of 0). We
	// can perhaps keep a tstamp of the last measurement in that interval?
	for (st = 1; st < ndd_num_intervals; st++) {
		this_interval = &ndd->intervals[(et + st) & ndd_num_intervals_mask];
		if (this_interval->invalid) break;

		this_min_rtt_us = this_interval->min_rtt_us;
		st_tstamp = this_interval->start_us;
		window = tcp_stamp_us_delta(et_tstamp, st_tstamp);

		this_high_delay = this_min_rtt_us > rtprop + max_jitter;
		this_loss = get_loss_mode(this_interval->pkts_acked, this_interval->pkts_lost);
		// TODO: loss was detected in this interval does not mean this interval
		// was utilized. Things were utilized when pkt with sequence number just
		// less than the lost sequence number was sent.
		this_utilized = this_loss || this_high_delay;
		if (st == 1) {
			cum_utilized = this_utilized;
		} else {
			cum_utilized = cum_utilized && this_utilized;
		}

		cum_pkts_acked += this_interval->pkts_acked;
		// cum_ack_rate =
		// 	U64_S_TO_US * cum_pkts_acked / window;

		// current units = MSS/second
		// TODO: check precision loss here.
		new_min_c =
			max_t(u64, new_min_c, (U64_S_TO_US * cum_pkts_acked) / (window + max_jitter));

		if (cum_utilized && st > 1) {
			new_max_c =
				min_t(u64, new_max_c, (U64_S_TO_US * cum_pkts_acked) / (window - max_jitter));
		}
	}

	if(timeout) {
		bool minc_changed = new_min_c > ndd->last_timeout_minc;
		bool maxc_changed = new_max_c < ndd->last_timeout_maxc;
		bool minc_changed_significantly = new_min_c > (ndd_significant_mult_percent * ndd->last_timeout_minc) / 100;
		bool maxc_changed_significantly = (new_max_c * ndd_significant_mult_percent) / 100 < ndd->last_timeout_maxc;
		bool beliefs_invalid = new_max_c < new_min_c;
		bool minc_came_close = minc_changed && beliefs_invalid;
		bool maxc_came_close = maxc_changed && beliefs_invalid;
		bool timeout_minc = !minc_changed && (maxc_came_close || !maxc_changed_significantly);
		bool timeout_maxc = !maxc_changed && (minc_came_close || !minc_changed_significantly);

		if(timeout_minc) {
			// TODO: this should be replaced by recomputed minc since last timeout.
			beliefs->min_c = new_min_c;
		} else {
			beliefs->min_c = max_t(u64, beliefs->min_c, new_min_c);
		}

		if(timeout_maxc) {
			beliefs->max_c = min_t(u64, (beliefs->max_c * 3) / 2, new_max_c);
		} else {
			beliefs->max_c = min_t(u64, beliefs->max_c, new_max_c);
		}

		ndd->last_timeout_tstamp = now;
		ndd->last_timeout_minc = beliefs->min_c;
		ndd->last_timeout_maxc = beliefs->max_c;
	}
	else {
		beliefs->min_c = max_t(u64, beliefs->min_c, new_min_c);
		beliefs->max_c = min_t(u64, beliefs->max_c, new_max_c);
	}
	beliefs->max_c = max_t(u64, beliefs->max_c, max_c_lower_clamp);
	// printk(KERN_INFO "after update max_c %llu new_max_c %llu", ndd->beliefs->max_c, new_max_c);
}

static void update_beliefs_send(struct sock *sk, const struct rate_sample *rs)
{
	struct ndd_data *ndd = inet_csk_ca(sk);
	struct belief_data *beliefs = ndd->beliefs;
	struct tcp_sock *tsk = tcp_sk(sk);

	u16 st;
	u64 st_tstamp;
	u16 et = ndd->intervals_head;  // end time
	u64 et_tstamp = ndd->intervals[et & ndd_num_intervals_mask].start_us;

	struct ndd_interval *this_interval;
	struct ndd_interval *next_future_interval;
	u64 this_max_rtt_us;
	bool this_loss;
	bool this_high_delay;
	u64 delivered_1rtt_ago;
	u64 this_bytes_sent;
	u64 this_min_c_lambda;
	u64 this_interval_length;

	bool this_under_utilized;
	bool cum_under_utilized = true;

	u32 rtprop = ndd->min_rtt_us;
	u32 max_jitter = rtprop;
	u64 new_min_c_lambda = INIT_MIN_C;

	this_interval = &ndd->intervals[et & ndd_num_intervals_mask];
	delivered_1rtt_ago = this_interval->ic_rs_prior_delivered;
	this_max_rtt_us = this_interval->max_rtt_us;
	this_high_delay = this_max_rtt_us > rtprop + max_jitter;
	this_loss = get_loss_mode(this_interval->pkts_acked, this_interval->pkts_lost);
	this_under_utilized = !this_loss && !this_high_delay;
	cum_under_utilized = cum_under_utilized && this_under_utilized;

	// This is synchronized with the update_beliefs function.
	// Do better software engineering here.
	u64 now = et_tstamp;
	u32 time_since_last_timeout = tcp_stamp_us_delta(now, ndd->last_timeout_tstamp);
	bool timeout = time_since_last_timeout > ndd_timeout_period * ndd->min_rtt_us;

	// printk(KERN_INFO "update beliefs send begin min_c_lambda %llu", beliefs->min_c_lambda);

	for (st = 1; st < ndd_num_intervals; st++) {
		// This for loop iterates over intervals in descending order of time.
		this_interval = &ndd->intervals[(et + st) & ndd_num_intervals_mask];
		if (this_interval->invalid) break;

		next_future_interval = &ndd->intervals[(et + st - 1) & ndd_num_intervals_mask];
		st_tstamp = this_interval->start_us;

		this_max_rtt_us = this_interval->max_rtt_us;
		this_high_delay = this_max_rtt_us > rtprop + max_jitter;
		this_loss = get_loss_mode(this_interval->pkts_acked, this_interval->pkts_lost);
		this_under_utilized = !this_loss && !this_high_delay;
		cum_under_utilized = cum_under_utilized && this_under_utilized;

		// We only consider this interval if all packets sent were 1 RTT before
		// now.
		if (next_future_interval->ic_delivered > delivered_1rtt_ago) continue;

		// Since we want to recompute min_c_lambda, we need to re-process the intervals.
		// // Stop if we have already considered this and past intervals.
		// if (this_interval->processed) break;
		this_interval->processed = true;

		// If we saw any utilization signals then we stop updating min_c_lambda
		if (!cum_under_utilized) break;

		BUILD_BUG_ON(ndd_measurement_interval != 1);
		this_bytes_sent = next_future_interval->ic_bytes_sent - this_interval->ic_bytes_sent;
		this_interval_length = tcp_stamp_us_delta(next_future_interval->start_us, this_interval->start_us);
		this_min_c_lambda = ((this_bytes_sent * U64_S_TO_US) / ndd_get_mss(tsk)) / (this_interval_length + max_jitter);
		// ^^ We divide by ndd_get_mss(tsk) to convert from bytes to segments or packets.
		new_min_c_lambda = max_t(u64, new_min_c_lambda, this_min_c_lambda);
	}

	// printk(
	// 	KERN_INFO
	// 	"ndd update_beliefs_send end min_c_lambda %llu "
	// 	"new_min_c_lambda %llu last_min_c_lambda %llu",
	// 	beliefs->min_c_lambda, new_min_c_lambda,
	// 	beliefs->last_min_c_lambda);

	if(new_min_c_lambda > beliefs->min_c_lambda) {
		beliefs->last_min_c_lambda = beliefs->min_c_lambda;
		beliefs->min_c_lambda = new_min_c_lambda;
	} else if (timeout) {
		// even if new_min_c_lambda is greater than last_min_c_lambda, we don't
		// update last_min_c_lambda. last_min_c_lambda tracks the last probe
		// that does not cause high utilization. new_min_c_lambda may not have
		// this property.
		if(beliefs->min_c_lambda > beliefs->last_min_c_lambda) {
			beliefs->min_c_lambda = max_t(u64, beliefs->last_min_c_lambda, new_min_c_lambda);
		} else {
			beliefs->min_c_lambda = max_t(u64, (2 * beliefs->min_c_lambda) / 3, new_min_c_lambda);
		}
	} else {
		// Don't change min_c_lambda.
	}

	// if(timeout) {
	// 	beliefs->min_c_lambda = max_t(u64, 2 * beliefs->min_c_lambda / 3, new_min_c_lambda);
	// } else {
	// 	beliefs->min_c_lambda = max_t(u64, beliefs->min_c_lambda, new_min_c_lambda);
	// }
}

void print_beliefs(struct sock *sk){
	struct ndd_data *ndd = inet_csk_ca(sk);
	struct belief_data *beliefs = ndd->beliefs;
	struct tcp_sock *tsk = tcp_sk(sk);

	u16 i, id, nid;
	u32 window = 0;
	u32 ic_rs_window = 0;
	s32 delivered_delta = 0;
	s32 sent_delta_pkts = 0;
	u32 estimated_sent = 0;
	u64 sending_rate = 0;

	printk(KERN_INFO "ndd min_c %llu max_c %llu min_qdel %u min_c_lambda %llu",
		   beliefs->min_c, beliefs->max_c, beliefs->min_qdel,
		   beliefs->min_c_lambda);
	for (i = 0; i < ndd_num_intervals; ++i) {
		id = (ndd->intervals_head + i) & ndd_num_intervals_mask;
		nid = (id - 1) & ndd_num_intervals_mask;  // next id
		if (i >= 1 && !ndd->intervals[id].invalid) {
			window = tcp_stamp_us_delta(ndd->intervals[nid].start_us,
										ndd->intervals[id].start_us);
			ic_rs_window =
				tcp_stamp_us_delta(ndd->intervals[nid].ic_rs_prior_mstamp,
								   ndd->intervals[id].ic_rs_prior_mstamp);
			delivered_delta = (ndd->intervals[nid].ic_rs_prior_delivered -
							   ndd->intervals[id].ic_rs_prior_delivered);
			sent_delta_pkts = (((s64)ndd->intervals[nid].ic_bytes_sent) -
							   ndd->intervals[id].ic_bytes_sent) /
							  ndd_get_mss(tsk);
			estimated_sent = (ndd->intervals[nid].ic_sending_rate * window / U64_S_TO_US);
			sending_rate = ndd->intervals[nid].ic_sending_rate;
		}
		printk(KERN_INFO
			   "ndd intervals start_us %llu window %u acked %u lost %u "
			   // "ic_rs_prior_mstamp %llu ic_rs_prior_delivered %u "
			   "ic_rs_window %u delivered_delta %d "
			   "app_limited %d min_rtt_us %u max_rtt_us %u "
			   "i %u id %u invalid %d processed %d "
			   "ic_bytes_sent %llu sent_delta_pkts %d estimated_sent %u "
			   "sending_rate %llu",
			   ndd->intervals[id].start_us, window,
			   ndd->intervals[id].pkts_acked, ndd->intervals[id].pkts_lost,
			   // ndd->intervals[id].ic_rs_prior_mstamp,
			   // ndd->intervals[id].ic_rs_prior_delivered,
			   ic_rs_window,
			   delivered_delta, (int)ndd->intervals[id].app_limited,
			   ndd->intervals[id].min_rtt_us, ndd->intervals[id].max_rtt_us,
			   i, id, ndd->intervals[id].invalid,
			   ndd->intervals[id].processed, ndd->intervals[id].ic_bytes_sent,
			   sent_delta_pkts, estimated_sent, sending_rate);
	}
}

static void ndd_cong_ctrl(struct sock *sk, const struct rate_sample *rs)
{
	struct ndd_data *ndd = inet_csk_ca(sk);
	struct tcp_sock *tsk = tcp_sk(sk);
	struct belief_data *beliefs = ndd->beliefs;
	u32 rtt_us;
	u16 i, id;
	u32 hist_us;
	u64 timestamp;
	u32 interval_length;
	// Number of packets acked and lost in the last `hist_us`
	u32 pkts_acked, pkts_lost;
	bool loss_mode, app_limited;
	bool beliefs_updated = false;

	u64 ndd_alpha_rate;
	u32 latest_inflight_segments = rs->prior_in_flight; // upper bound on bottleneck queue size.

	// printk(KERN_INFO "ndd rate_sample rs_timestamp %llu tcp_timestamp %llu delivered %d", tsk->tcp_mstamp, rs->prior_mstamp);
	// printk(KERN_INFO "ndd rate_sample acked_sacked %u last_end_seq %u snd_nxt % u rcv_nxt %u", rs->acked_sacked, rs->last_end_seq, tsk->snd_nxt, tsk->rcv_nxt);

	if (!ndd_valid(ndd))
		return;

	// Is rate sample valid?
	if (rs->delivered < 0 || rs->interval_us < 0)
		return;

	// Get initial RTT - as measured by SYN -> SYN-ACK.  If information
	// does not exist - use U32_MAX as RTT
	if (tsk->srtt_us) {
		rtt_us = max(tsk->srtt_us >> 3, 1U);
	} else {
		rtt_us = U32_MAX;
	}

	if (rtt_us < ndd->min_rtt_us)
		ndd->min_rtt_us = rtt_us;

	if (ndd->min_rtt_us == U32_MAX)
		hist_us = U32_MAX;
	else
		hist_us = ndd_history_periods * ndd->min_rtt_us;

	// Update intervals
	timestamp = tsk->tcp_mstamp; // Most recent send/receive

	// The factor of 2 gives some headroom so that we always have
	// sufficient history. We end up storing more history than needed, but
	// that's ok
	interval_length = 2 * hist_us / ndd_num_intervals + 1; // round up

	BUILD_BUG_ON(ndd_history_periods * 2 != ndd_num_intervals);
	// Sync the history and rate/cwnd updates.
	// if (ndd->intervals[ndd->intervals_head].start_us + interval_length < timestamp) {
	if (tcp_stamp_us_delta(timestamp, ndd->last_update_tstamp) >= ndd->min_rtt_us) {
		// Push the buffer
		ndd->intervals_head = (ndd->intervals_head - 1) & ndd_num_intervals_mask;
		ndd->intervals[ndd->intervals_head].start_us = timestamp;
		ndd->intervals[ndd->intervals_head].pkts_acked = rs->acked_sacked;
		ndd->intervals[ndd->intervals_head].pkts_lost = rs->losses;
		ndd->intervals[ndd->intervals_head].app_limited = rs->is_app_limited;
		ndd->intervals[ndd->intervals_head].min_rtt_us = rs->rtt_us;
		ndd->intervals[ndd->intervals_head].max_rtt_us = rs->rtt_us;
		ndd->intervals[ndd->intervals_head].ic_bytes_sent = tsk->bytes_sent;
		ndd->intervals[ndd->intervals_head].ic_rs_prior_mstamp = rs->prior_mstamp;
		ndd->intervals[ndd->intervals_head].ic_rs_prior_delivered = rs->prior_delivered;
		ndd->intervals[ndd->intervals_head].ic_delivered = tsk->delivered;
		ndd->intervals[ndd->intervals_head].processed = false;
		ndd->intervals[ndd->intervals_head].invalid = false;
		ndd->intervals[ndd->intervals_head].ic_sending_rate = sk->sk_pacing_rate / ndd_get_mss(tsk);
		update_beliefs_send(sk, rs);
		update_beliefs(sk);
		print_beliefs(sk);
		beliefs_updated = true;
	} else {
		ndd->intervals[ndd->intervals_head].pkts_acked += rs->acked_sacked;
		ndd->intervals[ndd->intervals_head].pkts_lost += rs->losses;
		ndd->intervals[ndd->intervals_head].app_limited |= rs->is_app_limited;
		// TODO: check what kind of aggregation we want here.
		ndd->intervals[ndd->intervals_head].min_rtt_us =
			min_t(u32, (u32) rs->rtt_us, ndd->intervals[ndd->intervals_head].min_rtt_us);
		ndd->intervals[ndd->intervals_head].max_rtt_us =
			max_t(u32, (u32) rs->rtt_us, ndd->intervals[ndd->intervals_head].max_rtt_us);
	}

	// Find the statistics from the last `hist` seconds
	pkts_acked = 0;
	pkts_lost = 0;
	app_limited = false;
	for (i = 0; i < ndd_num_intervals; ++i) {
		id = (ndd->intervals_head + i) & ndd_num_intervals_mask;
		pkts_acked += ndd->intervals[id].pkts_acked;
		pkts_lost += ndd->intervals[id].pkts_lost;
		app_limited |= ndd->intervals[id].app_limited;
		if (ndd->intervals[id].start_us + hist_us < timestamp) {
			break;
		}
	}

	loss_mode = (u64) pkts_lost * 1024 > (u64) (pkts_acked + pkts_lost) * ndd_loss_thresh;
	ndd_alpha_rate = (ndd_alpha_segments * ndd_get_mss(tsk) * U64_S_TO_US) / ndd->min_rtt_us;
	if(loss_mode) ndd->state = CONG_AVOID;

	// if (beliefs_updated) {
	if (tcp_stamp_us_delta(timestamp, ndd->last_update_tstamp) >= ndd->min_rtt_us) {

		if(ndd->last_update_tstamp > 0) {

			u32 elapsed_since_last_update =
				tcp_stamp_us_delta(timestamp, ndd->last_update_tstamp);

			u64 this_estimated_segs_sent = (sk->sk_pacing_rate * elapsed_since_last_update / U64_S_TO_US) / ndd_get_mss(tsk);
			u64 tsk_sent = tsk->bytes_sent / ndd_get_mss(tsk);
			u64 tsk_delivered = tsk->delivered;
			u64 this_tsk_sent = tsk_sent - ndd->last_segs_sent;
			u64 this_tsk_delivered = tsk_delivered - ndd->last_segs_delivered;
			ndd->last_segs_sent = tsk_sent;
			ndd->last_segs_delivered = tsk_delivered;
			ndd->estimated_cumulative_segs_sent += this_estimated_segs_sent;

			printk(KERN_INFO
				   "ndd debug_sent elapsed_since_last_update %u "
				   "this_estimated_segs_sent %llu this_tsk_sent %llu "
				   "this_tsk_delivered %llu "
				   "estimated_cumulative_segs_sent %llu tsk_sent %llu "
				   "tsk_delivered %llu last_interval_sending_rate %llu",
				   elapsed_since_last_update,
				   this_estimated_segs_sent, this_tsk_sent, this_tsk_delivered,
				   ndd->estimated_cumulative_segs_sent, tsk_sent,
				   tsk_delivered, ((u64) sk->sk_pacing_rate) / ndd_get_mss(tsk));
		}

		ndd->last_update_tstamp = timestamp;

		// jitter + rtprop = 2 * ndd->min_rtt_us
		tsk->snd_cwnd = (2 * beliefs->max_c * (2 * (u64) ndd->min_rtt_us)) / U64_S_TO_US;

		if(ndd->state == SLOW_START) {
			if(beliefs->min_qdel > 0) {
				sk->sk_pacing_rate = (beliefs->min_c * ndd_get_mss(tsk)) / 2;
			}
			else {
				sk->sk_pacing_rate = 2 * beliefs->min_c * ndd_get_mss(tsk);
			}
		}
		else {
			if(ndd->state != CONG_AVOID) {
				printk(KERN_ERR "Invalid state for ndd: %d", ndd->state);
			}
			/**
			 * The 3 is basically R + D + quantization error.
			 * In the kernel the error is 0. Thus use 2 instead of 3.
			r_f = max alpha,
			if (+ 1bq_belief + -1alpha > 0):
				+ 1alpha
			else:
				+ 3min_c_lambda + 1alpha
			*/
			if(latest_inflight_segments > 2 * ndd_alpha_segments) {
				// sk->sk_pacing_rate = ndd_alpha_rate;

				// Do not decrease rate significantly. The kernel computes time
				// to send next packet based on pacing rate and uses that to
				// implement pacing. As a result, a very low rate results in
				// time for next packet to become very large, and even after we
				// increase the rate later, that increased rate only starts
				// applying after the large time to next packet time has
				// elapsed. This was very weird issue... As a hack we just
				// reduce cwnd to drain. This actually might help drain quicker
				// also :P

				tsk->snd_cwnd = ndd_alpha_segments;
			}
			else {
				sk->sk_pacing_rate = 2 * beliefs->min_c_lambda * ndd_get_mss(tsk) + ndd_alpha_rate;
			}
		}

		// lower bound clamps
		tsk->snd_cwnd = max_t(u32, tsk->snd_cwnd, ndd_alpha_segments);
		sk->sk_pacing_rate = max_t(u64, sk->sk_pacing_rate, ndd_alpha_rate);

		// if(ndd->beliefs->odd_even) {
		// 	sk->sk_pacing_rate = (u64) 4000 * ndd_get_mss(tsk);
		// } else {
		// 	// sk->sk_pacing_rate = (u64) 60 * ndd_get_mss(tsk);
		// 	tsk->snd_cwnd = ndd_alpha_segments;
		// }
		// ndd->beliefs->odd_even = !ndd->beliefs->odd_even;

#ifdef NDD_DEBUG
		printk(KERN_INFO
			   "ndd flow %u cwnd %u pacing %lu rtt %u mss %u timestamp %llu "
			   "interval %ld state %d",
			   ndd->id, tsk->snd_cwnd, sk->sk_pacing_rate, rtt_us,
			   tsk->mss_cache, timestamp, rs->interval_us, ndd->state);
		printk(KERN_INFO
			   "ndd pkts_acked %u hist_us %u pacing %lu loss_happened %d "
			   "app_limited %d rs_limited %d latest_inflight_segments %u "
			   "delivered_bytes %llu",
			   pkts_acked, hist_us, sk->sk_pacing_rate,
			   (int)ndd->loss_happened, (int)app_limited,
			   (int)rs->is_app_limited, latest_inflight_segments,
			   ((u64) ndd_get_mss(tsk)) * tsk->delivered);
		// print_beliefs(sk);
#endif
	}
	// printk(KERN_INFO "ndd_cong_ctrl got rtt_us %lu", rs->rtt_us);
	// printk(KERN_INFO "ndd_cong_ctrl cwnd %u pacing %lu", tsk->snd_cwnd, sk->sk_pacing_rate);
}

static void<ndd_release>(struct sock *sk) {
	struct ndd_data *ndd = inet_csk_ca(sk);
	kfree(ndd->intervals);
}

static u32 ndd_ssthresh(struct sock *sk) { return TCP_INFINITE_SSTHRESH; }

static void ndd_cong_avoid(struct sock *sk, u32 ack, u32 acked) {}

static struct tcp_congestion_ops tcp_ndd_cong_ops __read_mostly = {
	.flags = TCP_CONG_NON_RESTRICTED,
	.name = "ndd",
	.owner = THIS_MODULE,
	.init = ndd_init,
	.release = <ndd_release>,
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