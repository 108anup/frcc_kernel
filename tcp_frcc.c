// FRCC: A provably fair and robust congestion controller

#include <net/tcp.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/random.h>

#define FRCC_LOG_INFO
// #define FRCC_LOG_DEBUG
// #define FRCC_LOG_TRACE

#define P_SCALE 8 /* scaling factor for fractions (e.g. gains) */
#define P_UNIT (1 << P_SCALE)

// enum log_level {
// 	LOG_INFO,
// 	LOG_DEBUG,
// 	LOG_TRACE,
// };
// static enum log_level static_log_level = LOG_INFO;

// Assumptions about network scenarios
static u32 static_p_ub_rtprop_us = 100000; // 100 ms
static u32 static_p_ub_rtterr_us = 10000; // 10 ms
static u32 static_p_ub_flow_count = 3;

// Design parameters
// TODO: check if these floating values make sense given the UNIT. Should we
// change the unit?
static u32 static_p_lb_cwnd_pkts = 4;
// ^^ this should be such that, p_cwnd_clamp_hi increases this by at least 1,
// otherwise even at the maximum increase, the cwnd will not increase due to
// integer arithmetic.
static u32 static_p_contract_min_qdel_us = 10000; // static_p_ub_rtprop_us / 2;
// for stability, static_p_contract_min_qdel_us >= rtprop / ground_truth_flow_count,
// for error, we need static_p_contract_min_qdel_us >= 2 * static_p_ub_rtterr_us
static u32 static_p_probe_duration_us = 10000; // 10 ms. How should this be set?
static u32 static_p_probe_multiplier_unit = P_UNIT * 4; // gamma in the paper
static u32 static_p_cwnd_averaging_factor_unit =
	P_UNIT * 1; // alpha = 1/2 for non-stable design, otherwise 1.
static u32 static_p_cwnd_clamp_hi_unit = P_UNIT * 13 / 10;
static u32 static_p_cwnd_clamp_lo_unit = P_UNIT * 10 / 13;
static u32 static_p_slot_load_factor_unit = P_UNIT * 2;
static u32 static_p_ub_slots_per_round = 20;
static u32 static_p_rprobe_interval_us = 30000000; // 30 seconds
static u32 static_p_probe_wait_rtts = 2; // number of rtts to wait after probe

// Design features
static bool static_f_use_rtprop_probe = true;
static bool static_f_wait_rtt_after_probe = true;
static bool static_f_use_stable_cwnd_update = true;
static bool static_f_probe_wait_in_max_rtts = true;
static bool static_f_probe_duration_max_rtt = true;
static bool static_f_drain_over_rtt = true;
static bool static_f_probe_over_rtt = true;
static bool static_f_slot_greater_than_rtprop = true;
static bool static_f_slot_exactly_rtprop = true;

// Make all parameters runtime configurable
// https://devarea.com/linux-kernel-development-kernel-module-parameters/
module_param(static_p_ub_rtprop_us, uint, 0660);
module_param(static_p_ub_rtterr_us, uint, 0660);
module_param(static_p_ub_flow_count, uint, 0660);
module_param(static_p_lb_cwnd_pkts, uint, 0660);
module_param(static_p_contract_min_qdel_us, uint, 0660);
module_param(static_p_probe_duration_us, uint, 0660);
module_param(static_p_probe_multiplier_unit, uint, 0660);
module_param(static_p_cwnd_averaging_factor_unit, uint, 0660);
module_param(static_p_cwnd_clamp_hi_unit, uint, 0660);
module_param(static_p_cwnd_clamp_lo_unit, uint, 0660);
module_param(static_p_slot_load_factor_unit, uint, 0660);
module_param(static_p_ub_slots_per_round, uint, 0660);
module_param(static_p_rprobe_interval_us, uint, 0660);
module_param(static_p_probe_wait_rtts, uint, 0660);
module_param(static_f_use_rtprop_probe, bool, 0660);
module_param(static_f_wait_rtt_after_probe, bool, 0660);
module_param(static_f_use_stable_cwnd_update, bool, 0660);
module_param(static_f_probe_wait_in_max_rtts, bool, 0660);
module_param(static_f_probe_duration_max_rtt, bool, 0660);
module_param(static_f_drain_over_rtt, bool, 0660);
module_param(static_f_probe_over_rtt, bool, 0660);
module_param(static_f_slot_greater_than_rtprop, bool, 0660);
module_param(static_f_slot_exactly_rtprop, bool, 0660);
// module_param(static_log_level, uint, 0660);

static u32 id = 0;

struct param_data {
	// Priors about network
	u32 p_ub_rtprop_us;
	u32 p_ub_rtterr_us;
	u32 p_ub_flow_count;

	// Design parameters
	u32 p_lb_cwnd_pkts;
	u32 p_contract_min_qdel_us;
	u32 p_probe_duration_us;
	u32 p_probe_multiplier_unit;
	u32 p_cwnd_averaging_factor_unit;
	u32 p_inv_cwnd_averaging_factor_unit;
	u32 p_cwnd_clamp_hi_unit;
	u32 p_cwnd_clamp_lo_unit;
	u32 p_slot_load_factor_unit;
	u32 p_ub_slots_per_round;
	u32 p_rprobe_interval_us;
	u32 p_probe_wait_rtts;

	// Design features
	bool f_use_rtprop_probe;
	bool f_wait_rtt_after_probe;
	bool f_use_stable_cwnd_update;
	bool f_probe_wait_in_max_rtts;
	bool f_probe_duration_max_rtt;
	bool f_drain_over_rtt;
	bool f_probe_over_rtt;
	bool f_slot_greater_than_rtprop;
	bool f_slot_exactly_rtprop;
};

struct probe_data {
	bool s_probe_ongoing;
	u32 s_probe_min_rtt_before_us;
	u32 s_probe_min_rtt_us; // for logging only
	u32 s_probe_min_excess_delay_us;
	u32 s_probe_prev_cwnd_pkts;
	u32 s_probe_excess_pkts;
	bool s_probe_end_initiated;
	u32 s_probe_drain_pkts_unit;
	u32 s_probe_drain_pkts_rem_unit;

	u64 s_probe_start_time_us;
	u64 s_probe_start_seq;
	u64 s_probe_inflightmatch_seq;
	u64 s_probe_first_seq;
	u64 s_probe_last_seq;
	u64 s_probe_first_time_us;
};

struct rprobe_data {
	bool s_rprobe_ongoing;
	u64 s_rprobe_prev_start_time_us;
	u64 s_rprobe_start_time_us;
	u64 s_rprobe_init_end_time_us;
	u32 s_rprobe_prev_cwnd_pkts;
	bool s_rprobe_end_initiated;
};

struct round_data {
	u32 s_round_slots_till_now;
	u32 s_round_min_rtt_us;
	u32 s_round_max_rate_pps;
	u32 s_round_probe_slot_idx;
	bool s_round_probed;
	u32 s_round_slots_total;
	// pps = packets per second, supports range: [1500 bytes per sec to
	// 6.44 terabytes per second]
};

enum cwnd_event {
	SLOW_START,
	SLOW_START_END,
	PROBE_GAIN,
	PROBE_DRAIN,
	PROBE_UPDATE,
	RPROBE_DRAIN,
	RPROBE_REFILL,
};

struct frcc_data {
	struct param_data *p_params;

	u32 id;
	u64 last_log_time_us;
	// TODO: need to make space in this struct
	// enum log_level log_level;

	// State variables
	u32 s_min_rtprop_us;

	bool s_ss_done;
	bool s_ss_end_initiated;
	u64 s_ss_last_seq;

	u32 s_slot_max_qdel_us;
	u64 s_slot_start_time_us;
	u32 s_slot_max_rate_pps; // for logging only
	u32 s_slot_min_rtt_us; // for logging only
	u32 s_slot_max_rtt_us; // for logging only

	struct probe_data *s_probe;
	struct rprobe_data *s_rprobe;
	struct round_data *s_round;
};

#define BASE_FMT                                                               \
	"flow %u now %llu cwnd %u pacing %lu rtt %u mss %u min_rtprop_us %u "  \
	"inflight %u "
#define BASE_VARS                                                              \
	frcc->id, now_us, tsk->snd_cwnd, sk->sk_pacing_rate, rtt_us,           \
		tsk->mss_cache, frcc->s_min_rtprop_us, tsk->packets_out
#define ROUND_FMT                                                              \
	"round_min_rtt_us %u round_max_rate_pps %u "                           \
	"round_slots_till_now %u round_probe_slot_idx %u round_slots_total %u "
#define ROUND_VARS                                                             \
	frcc->s_round->s_round_min_rtt_us,                                     \
		frcc->s_round->s_round_max_rate_pps,                           \
		frcc->s_round->s_round_slots_till_now,                         \
		frcc->s_round->s_round_probe_slot_idx,                         \
		frcc->s_round->s_round_slots_total
#define SLOT_FMT                                                               \
	"slot_max_qdel_us %u slot_max_rate_pps %u "                            \
	"slot_min_rtt_us %u slot_max_rtt_us %u probe_ongoing %u "
#define SLOT_VARS                                                              \
	frcc->s_slot_max_qdel_us, frcc->s_slot_max_rate_pps,                   \
		frcc->s_slot_min_rtt_us, frcc->s_slot_max_rtt_us,              \
		frcc->s_probe->s_probe_ongoing
#define PROBE_FMT                                                              \
	"probe_ongoing %u probe_min_rtt_before_us %u probe_min_rtt_us %u "     \
	"probe_min_excess_delay_us %u "                                        \
	"probe_prev_cwnd_pkts %u probe_excess_pkts %u probe_end_initiated %u "
#define PROBE_VARS                                                             \
	frcc->s_probe->s_probe_ongoing,                                        \
		frcc->s_probe->s_probe_min_rtt_before_us,                      \
		frcc->s_probe->s_probe_min_rtt_us,                             \
		frcc->s_probe->s_probe_min_excess_delay_us,                    \
		frcc->s_probe->s_probe_prev_cwnd_pkts,                         \
		frcc->s_probe->s_probe_excess_pkts,                            \
		frcc->s_probe->s_probe_end_initiated
#define PROBE_DEBUG_FMT                                                        \
	"probe_start_seq %llu probe_inflightmatch_seq %llu "                   \
	"probe_first_seq %llu probe_last_seq %llu "                            \
	"probe_first_seq_snd_time %llu part_of_probe %u "
#define PROBE_DEBUG_VARS                                                       \
	frcc->s_probe->s_probe_start_seq,                                      \
		frcc->s_probe->s_probe_inflightmatch_seq,                      \
		frcc->s_probe->s_probe_first_seq,                              \
		frcc->s_probe->s_probe_last_seq,                               \
		frcc->s_probe->s_probe_first_seq_snd_time,                     \
		part_of_probe(frcc, tsk)
#define SEQ_FMT "last_snd_seq %llu last_rcv_seq %llu "
#define SEQ_VARS get_last_snd_seq(tsk), get_last_rcv_seq(tsk)

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

// void my_log(struct frcc_data *frcc, struct tcp_sock *tsk, u32 rtt_us, u64 now_us,
// 		enum log_level level, const char *log_type, const char *fmt, ...)
// {
// #ifdef FRCC_LOG
// 	va_list args;

// 	if (level > static_log_level) { // frcc->log_level) {
// 		return;
// 	}

// 	printk(KERN_INFO
// 		"frcc %s flow %u now %llu cwnd %u rtt %u mss %u min_rtprop_us %u "
// 		"inflight %u last_snd_seq %llu last_rcv_seq %llu ",
// 		log_type, frcc->id, now_us, tsk->snd_cwnd, rtt_us, tsk->mss_cache,
// 		frcc->s_min_rtprop_us, tsk->packets_out, get_last_snd_seq(tsk),
// 		get_last_rcv_seq(tsk));
// 	va_start(args, fmt);
// 	vprintk(fmt, args);
// 	va_end(args);
// #endif
// }

void log_params(struct sock *sk, struct frcc_data *frcc, struct tcp_sock *tsk,
		u64 now_us)
{
#ifdef FRCC_LOG_INFO
	struct param_data *p = frcc->p_params;
	u32 rtt_us = U32_MAX;
	printk(KERN_INFO
	       "frcc params " BASE_FMT
	       "ub_rtprop_us %u ub_rtterr_us %u ub_flow_count %u "
	       "p_lb_cwnd_pkts %u p_contract_min_qdel_us %u p_probe_duration_us %u "
	       "p_probe_multiplier_unit %u p_cwnd_averaging_factor_unit %u "
	       "p_inv_cwnd_averaging_factor_unit %u p_cwnd_clamp_hi_unit %u "
	       "p_cwnd_clamp_lo_unit %u p_slot_load_factor_unit %u "
	       "p_ub_slots_per_round %u p_rprobe_interval_us %u "
	       "f_use_rtprop_probe %u f_wait_rtt_after_probe %u f_use_stable_cwnd_update %u ",
	       BASE_VARS, p->p_ub_rtprop_us, p->p_ub_rtterr_us,
	       p->p_ub_flow_count, p->p_lb_cwnd_pkts, p->p_contract_min_qdel_us,
	       p->p_probe_duration_us, p->p_probe_multiplier_unit,
	       p->p_cwnd_averaging_factor_unit,
	       p->p_inv_cwnd_averaging_factor_unit, p->p_cwnd_clamp_hi_unit,
	       p->p_cwnd_clamp_lo_unit, p->p_slot_load_factor_unit,
	       p->p_ub_slots_per_round, p->p_rprobe_interval_us,
	       p->f_use_rtprop_probe, p->f_wait_rtt_after_probe,
	       p->f_use_stable_cwnd_update);
#endif
}

static void init_params(struct sock *sk, struct frcc_data *frcc,
			struct tcp_sock *tsk, u64 now_us)
{
	struct param_data *p = frcc->p_params;
	p->p_ub_rtprop_us = static_p_ub_rtprop_us;
	p->p_ub_rtterr_us = static_p_ub_rtterr_us;
	p->p_ub_flow_count = static_p_ub_flow_count;

	p->p_lb_cwnd_pkts = static_p_lb_cwnd_pkts;
	p->p_contract_min_qdel_us = static_p_contract_min_qdel_us;
	p->p_probe_duration_us = static_p_probe_duration_us;
	p->p_probe_multiplier_unit = static_p_probe_multiplier_unit;
	p->p_cwnd_averaging_factor_unit = static_p_cwnd_averaging_factor_unit;
	p->p_inv_cwnd_averaging_factor_unit =
		P_UNIT * 1 - p->p_cwnd_averaging_factor_unit;
	p->p_cwnd_clamp_hi_unit = static_p_cwnd_clamp_hi_unit;
	p->p_cwnd_clamp_lo_unit = static_p_cwnd_clamp_lo_unit;
	p->p_slot_load_factor_unit = static_p_slot_load_factor_unit;
	p->p_ub_slots_per_round = static_p_ub_slots_per_round;
	p->p_rprobe_interval_us = static_p_rprobe_interval_us;
	p->p_probe_wait_rtts = static_p_probe_wait_rtts;

	p->f_use_rtprop_probe = static_f_use_rtprop_probe;
	p->f_wait_rtt_after_probe = static_f_wait_rtt_after_probe;
	p->f_use_stable_cwnd_update = static_f_use_stable_cwnd_update;
	p->f_probe_wait_in_max_rtts = static_f_probe_wait_in_max_rtts;
	p->f_probe_duration_max_rtt = static_f_probe_duration_max_rtt;
	p->f_drain_over_rtt = static_f_drain_over_rtt;
	p->f_probe_over_rtt = static_f_probe_over_rtt;
	p->f_slot_greater_than_rtprop = static_f_slot_greater_than_rtprop;
	p->f_slot_exactly_rtprop = static_f_slot_exactly_rtprop;

	log_params(sk, frcc, tsk, now_us);
}

static u32 get_target_flow_count_unit(struct frcc_data *frcc)
{
	struct param_data *p = frcc->p_params;
	u32 round_qdel_us;
	u32 target_flow_count_unit;

	round_qdel_us =
		frcc->s_round->s_round_min_rtt_us - frcc->s_min_rtprop_us;
	target_flow_count_unit = P_UNIT;
	target_flow_count_unit *= round_qdel_us;
	do_div(target_flow_count_unit, p->p_contract_min_qdel_us);

	return target_flow_count_unit;
}

static u32 get_slots_per_round(struct frcc_data *frcc)
{
	struct param_data *p = frcc->p_params;
	u32 p_lb_slots_per_round =
		(p->p_ub_flow_count * p->p_slot_load_factor_unit) >> P_SCALE;
	u32 target_flow_count_unit = get_target_flow_count_unit(frcc);
	u32 p_slots_per_round =
		target_flow_count_unit * p->p_slot_load_factor_unit;
	// remove P_UNIT^2
	p_slots_per_round = p_slots_per_round >> P_SCALE;
	p_slots_per_round = p_slots_per_round >> P_SCALE;

	p_slots_per_round = max_t(u32, p_slots_per_round, p_lb_slots_per_round);
	p_slots_per_round =
		min_t(u32, p_slots_per_round, p->p_ub_slots_per_round);

	if (frcc->s_round->s_round_min_rtt_us == U32_MAX ||
	    frcc->s_min_rtprop_us == U32_MAX) {
		return p_lb_slots_per_round;
	}
	return p_slots_per_round;
}

static void reset_round_state(struct frcc_data *frcc)
{
	frcc->s_round->s_round_slots_total = get_slots_per_round(frcc);
	// ^^ Note: we need to compute this before resetting round min rtt.
	frcc->s_round->s_round_slots_till_now = 0;
	frcc->s_round->s_round_min_rtt_us = U32_MAX;
	frcc->s_round->s_round_max_rate_pps = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
	frcc->s_round->s_round_probe_slot_idx =
		1 +
		get_random_u32_below(frcc->s_round->s_round_slots_total - 1);
#else
	frcc->s_round->s_round_probe_slot_idx =
		1 + prandom_u32_max(frcc->s_round->s_round_slots_total - 1);
#endif
	frcc->s_round->s_round_probed = false;
	// Rationale for -1 in the input to prandom_u32_max: If there are 6
	// slots: 0 to 5, we want the slot idx to be in range [1,5]. Note, slot
	// 0 is not in the range because we do not probe in slot 0 to be able
	//   to obtain some information in the round.
}

static void reset_probe_state(struct frcc_data *frcc)
{
	frcc->s_probe->s_probe_ongoing = false;
	frcc->s_probe->s_probe_min_rtt_before_us = U32_MAX;
	frcc->s_probe->s_probe_min_rtt_us = U32_MAX;
	frcc->s_probe->s_probe_min_excess_delay_us = U32_MAX;
	frcc->s_probe->s_probe_prev_cwnd_pkts = 0; // should not be read anyway.
	frcc->s_probe->s_probe_excess_pkts = 0; // should not be read anyway.
	frcc->s_probe->s_probe_end_initiated = false;
	frcc->s_probe->s_probe_drain_pkts_unit = 0;
	frcc->s_probe->s_probe_drain_pkts_rem_unit = 0;

	frcc->s_probe->s_probe_start_time_us = 0;
	frcc->s_probe->s_probe_start_seq = 0;
	frcc->s_probe->s_probe_inflightmatch_seq = 0;
	frcc->s_probe->s_probe_first_seq = 0;
	frcc->s_probe->s_probe_last_seq = 0;
	frcc->s_probe->s_probe_first_time_us = 0;
}

static void start_new_slot(struct frcc_data *frcc, u64 now_us)
{
	frcc->s_slot_max_qdel_us = 0;
	frcc->s_slot_start_time_us = now_us;
	frcc->s_slot_max_rate_pps = 0;
	frcc->s_slot_min_rtt_us = U32_MAX;
	frcc->s_slot_max_rtt_us = 0;
}

static u64 get_rprobe_time(struct frcc_data *frcc, u64 time_us)
{
	// Round down to the nearest multiple of rprobe_interval_us
	struct param_data *p = frcc->p_params;
	return (time_us / p->p_rprobe_interval_us) * p->p_rprobe_interval_us;
}

static void reset_rprobe_state(struct frcc_data *frcc,
			       u64 current_rprobe_start_time_us)
{
	frcc->s_rprobe->s_rprobe_ongoing = false;
	frcc->s_rprobe->s_rprobe_prev_start_time_us =
		get_rprobe_time(frcc, current_rprobe_start_time_us);
	frcc->s_rprobe->s_rprobe_start_time_us = 0;
	frcc->s_rprobe->s_rprobe_init_end_time_us = 0;
	frcc->s_rprobe->s_rprobe_end_initiated = false;
	frcc->s_rprobe->s_rprobe_prev_cwnd_pkts = 0;
}

static void frcc_init(struct sock *sk)
{
	struct frcc_data *frcc = inet_csk_ca(sk);
	struct tcp_sock *tsk = tcp_sk(sk);
	u64 now_us = tsk->tcp_mstamp;

	frcc->s_probe = kzalloc(sizeof(struct probe_data), GFP_KERNEL);
	frcc->s_rprobe = kzalloc(sizeof(struct rprobe_data), GFP_KERNEL);
	frcc->s_round = kzalloc(sizeof(struct round_data), GFP_KERNEL);
	frcc->p_params = kzalloc(sizeof(struct param_data), GFP_KERNEL);

	// Convention, the order in struct is same as order of initialization
	// so that we ensure everything is initialized and in the right order.

	// param initialization should be first as these are used in other
	// initializations, for others, the order does not matter much.
	init_params(sk, frcc, tsk, now_us);

	++id;
	frcc->id = id;
	frcc->last_log_time_us = 0;
	// frcc->log_level = static_log_level;

	// TODO: we should reset this at some time to accommodate path changes.
	frcc->s_min_rtprop_us = U32_MAX;

	frcc->s_ss_done = false;
	frcc->s_ss_end_initiated = false;
	frcc->s_ss_last_seq = 0;

	reset_round_state(frcc);
	start_new_slot(frcc, now_us);
	reset_probe_state(frcc);
	reset_rprobe_state(frcc, now_us);

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}

static u32 frcc_get_mss(struct tcp_sock *tsk)
{
	// TODO: Figure out if mss_cache is the one to use
	return tsk->mss_cache;
}

/* was the frcc struct fully inited */
static bool frcc_valid(struct frcc_data *frcc)
{
	return (frcc);
}

static bool part_of_probe(struct frcc_data *frcc, struct tcp_sock *tsk)
{
	// Because last_rcv_seq is the next seq we expect to receive, i.e.,
	// unacked seq, the current convention here is that first seq - 1 is
	// included in the acks part of probe and last - 1 is the last included
	// sequence. We really do want last to be excluded as that is sent
	// after the cwnd update.
	u64 last_rcv_seq = get_last_rcv_seq(tsk);
	if (frcc->s_probe->s_probe_first_seq > 0) {
		if (frcc->s_probe->s_probe_last_seq > 0) {
			return !before(last_rcv_seq,
				       frcc->s_probe->s_probe_first_seq) &&
			       !after(last_rcv_seq,
				      frcc->s_probe->s_probe_last_seq);
		} else {
			return !before(last_rcv_seq,
				       frcc->s_probe->s_probe_first_seq);
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

static void update_pacing_rate(struct sock *sk, struct frcc_data *frcc,
			       struct tcp_sock *tsk, u32 rtt_us,
			       bool probe_gain)
{
	u64 next_rate_bps =
		2 * tsk->snd_cwnd * frcc_get_mss(tsk) * USEC_PER_SEC;
	do_div(next_rate_bps, frcc->s_min_rtprop_us);
	if (probe_gain) {
		// Just after cwnd increase for probe, set pacing rate to new
		// (probing) cwnd / old RTT, so that the new inflight builds up
		// slowly over an RTT in an attempt to avoid self induced
		// oscillations.
		next_rate_bps =
			tsk->snd_cwnd * frcc_get_mss(tsk) * USEC_PER_SEC;
		do_div(next_rate_bps, rtt_us);
	}
	sk->sk_pacing_rate = next_rate_bps;
}

static void update_estimates(struct frcc_data *frcc, struct tcp_sock *tsk,
			     const struct rate_sample *rs, u32 rtt_us)
{
	u32 this_qdel;
	u32 init_rtt_us = get_initial_rtt(tsk);
	// TODO: Should we use the rs->delivered instead of snd_cwnd?
	u64 this_rate_pps = tsk->snd_cwnd * USEC_PER_SEC;
	do_div(this_rate_pps, rtt_us);

	frcc->s_min_rtprop_us = min_t(u32, frcc->s_min_rtprop_us, init_rtt_us);
	frcc->s_min_rtprop_us = min_t(u32, frcc->s_min_rtprop_us, rtt_us);

	frcc->s_round->s_round_min_rtt_us =
		min_t(u32, frcc->s_round->s_round_min_rtt_us, rtt_us);
	this_qdel = rtt_us - frcc->s_min_rtprop_us;

	if (frcc->s_probe->s_probe_ongoing && part_of_probe(frcc, tsk)) {
		u32 this_excess_delay_us =
			rtt_us - frcc->s_probe->s_probe_min_rtt_before_us;
		frcc->s_probe->s_probe_min_excess_delay_us =
			min_t(u32, frcc->s_probe->s_probe_min_excess_delay_us,
			      this_excess_delay_us);
		frcc->s_probe->s_probe_min_rtt_us =
			min_t(u32, frcc->s_probe->s_probe_min_rtt_us, rtt_us);
	} else if (!frcc->s_probe->s_probe_ongoing) {
		frcc->s_round->s_round_max_rate_pps =
			max_t(u64, frcc->s_round->s_round_max_rate_pps,
			      this_rate_pps);
	}
	frcc->s_slot_max_qdel_us =
		max_t(u32, frcc->s_slot_max_qdel_us, this_qdel);
	frcc->s_slot_max_rate_pps =
		max_t(u64, frcc->s_slot_max_rate_pps, this_rate_pps);
	frcc->s_slot_max_rtt_us = max_t(u32, frcc->s_slot_max_rtt_us, rtt_us);
	frcc->s_slot_min_rtt_us = min_t(u32, frcc->s_slot_min_rtt_us, rtt_us);
}

static bool probe_ended(struct frcc_data *frcc, struct tcp_sock *tsk)
{
	// part of probe is first -1 and last -1, so here, we are checking if
	// una is >= last so that last -1 is definitely acked.
	u64 last_rcv_seq = get_last_rcv_seq(tsk);
	return frcc->s_probe->s_probe_last_seq > 0 &&
	       !before(last_rcv_seq, frcc->s_probe->s_probe_last_seq);
}

static bool cruise_ended(struct frcc_data *frcc, u64 now_us)
{
	struct param_data *p = frcc->p_params;
	u32 max_rtprop_us, max_rtt_us, probe_duration_us, drain_duration_us,
		slot_duration_us;
	u64 slot_end_us;

	max_rtprop_us = p->p_ub_rtprop_us;
	if (p->f_slot_greater_than_rtprop) {
		max_rtprop_us =
			max_t(u32, frcc->s_min_rtprop_us, p->p_ub_rtprop_us);
	}
	if (p->f_slot_exactly_rtprop) {
		max_rtprop_us = frcc->s_min_rtprop_us;
	}

	max_rtt_us = max_rtprop_us + frcc->s_slot_max_qdel_us;

	probe_duration_us = p->p_probe_duration_us;
	if (p->f_probe_duration_max_rtt) {
		probe_duration_us = max_rtt_us;
	}

	drain_duration_us = frcc->s_slot_max_qdel_us;
	if (p->f_drain_over_rtt) {
		drain_duration_us = max_rtt_us;
	}

	slot_duration_us = max_rtt_us + probe_duration_us + drain_duration_us;
	if (p->f_wait_rtt_after_probe) {
		slot_duration_us += max_rtt_us;
	}
	if (p->f_probe_wait_in_max_rtts) {
		slot_duration_us =
			max_t(u32, slot_duration_us,
			      max_rtt_us * p->p_probe_wait_rtts +
				      probe_duration_us + drain_duration_us);
	}

	slot_end_us = frcc->s_slot_start_time_us + slot_duration_us;
	return time_after64(now_us, slot_end_us);
}

static bool should_init_probe_end(struct frcc_data *frcc, struct tcp_sock *tsk)
{
	// since last-1 is the last seq part of probe, we are chekcing whether
	// next_snd is >= last, this means last-1 has been sent.
	u32 last_snd_seq = get_last_snd_seq(tsk);
	return frcc->s_probe->s_probe_last_seq > 0 &&
	       !before(last_snd_seq, frcc->s_probe->s_probe_last_seq) &&
	       !frcc->s_probe->s_probe_end_initiated;
}

static bool round_ended(struct frcc_data *frcc)
{
	return frcc->s_round->s_round_slots_till_now >=
	       get_slots_per_round(frcc);
}

static bool should_probe(struct frcc_data *frcc)
{
	return frcc->s_round->s_round_slots_till_now >=
	       frcc->s_round->s_round_probe_slot_idx;
}

static u32 get_probe_excess(struct frcc_data *frcc)
{
	struct param_data *p = frcc->p_params;
	u32 target_flow_count_unit;
	u64 excess_pkts;

	target_flow_count_unit = get_target_flow_count_unit(frcc);
	excess_pkts = p->p_probe_multiplier_unit;
	excess_pkts *= target_flow_count_unit;
	excess_pkts >>= P_SCALE;
	excess_pkts *= frcc->s_round->s_round_max_rate_pps;
	excess_pkts *= p->p_ub_rtterr_us;
	excess_pkts >>= P_SCALE;
	excess_pkts = DIV_ROUND_UP_ULL(excess_pkts, USEC_PER_SEC);
	excess_pkts = max_t(u64, excess_pkts, 1);

	return excess_pkts;
}

void log_cwnd(enum cwnd_event reason, struct sock *sk, struct frcc_data *frcc,
	      struct tcp_sock *tsk, u32 rtt_us, u64 now_us)
{
#ifdef FRCC_LOG_INFO
	printk(KERN_INFO
	       "frcc cwnd_event reason %u " BASE_FMT ROUND_FMT SLOT_FMT
	       "last_snd_seq %llu last_rcv_seq %llu",
	       reason, BASE_VARS, ROUND_VARS, SLOT_VARS, get_last_snd_seq(tsk),
	       get_last_rcv_seq(tsk));
#endif
}

static void log_probe_start(struct sock *sk, struct frcc_data *frcc,
			    struct tcp_sock *tsk, u32 rtt_us, u64 now_us)
{
#ifdef FRCC_LOG_INFO
	printk(KERN_INFO "frcc probe_start " BASE_FMT PROBE_FMT, BASE_VARS,
	       PROBE_VARS);
#endif
}

static void start_probe(struct sock *sk, struct frcc_data *frcc,
			struct tcp_sock *tsk, u32 rtt_us, u64 now_us,
			u32 s_slot_min_rtt_us)
{
	frcc->s_probe->s_probe_ongoing = true;
	frcc->s_probe->s_probe_min_rtt_before_us = s_slot_min_rtt_us;
	frcc->s_probe->s_probe_min_rtt_us = U32_MAX;
	frcc->s_probe->s_probe_min_excess_delay_us = U32_MAX;
	frcc->s_probe->s_probe_prev_cwnd_pkts = tsk->snd_cwnd;
	frcc->s_probe->s_probe_excess_pkts = get_probe_excess(frcc);
	frcc->s_probe->s_probe_end_initiated = false;
	frcc->s_probe->s_probe_drain_pkts_unit = 0;
	frcc->s_probe->s_probe_drain_pkts_rem_unit = 0;

	frcc->s_probe->s_probe_start_time_us = now_us;
	frcc->s_probe->s_probe_start_seq = get_last_snd_seq(tsk);
	frcc->s_probe->s_probe_inflightmatch_seq = 0;
	frcc->s_probe->s_probe_first_seq = 0;
	frcc->s_probe->s_probe_last_seq = 0;
	frcc->s_probe->s_probe_first_time_us = 0;

	tsk->snd_cwnd = tsk->snd_cwnd + frcc->s_probe->s_probe_excess_pkts;
	update_pacing_rate(sk, frcc, tsk, rtt_us, true);

	log_probe_start(sk, frcc, tsk, rtt_us, now_us);
	log_cwnd(PROBE_GAIN, sk, frcc, tsk, rtt_us, now_us);
}

static void update_cwnd_drain(struct sock *sk, struct frcc_data *frcc,
			      struct tcp_sock *tsk, u32 rtt_us, u64 now_us,
			      const struct rate_sample *rs)
{
	struct param_data *p = frcc->p_params;
	u32 this_drain_pkts;
	if (!p->f_drain_over_rtt) {
		return;
	}

	// TODO: increase precision here as cwnd is larger than P_UNIT. Ideally
	// we want P_UNIT > the denominator = cwnd.
	frcc->s_probe->s_probe_drain_pkts_rem_unit +=
		frcc->s_probe->s_probe_drain_pkts_unit * rs->acked_sacked;
	this_drain_pkts = frcc->s_probe->s_probe_drain_pkts_rem_unit >> P_SCALE;
	frcc->s_probe->s_probe_drain_pkts_rem_unit &= P_UNIT - 1;

	tsk->snd_cwnd = tsk->snd_cwnd - this_drain_pkts;
	update_pacing_rate(sk, frcc, tsk, rtt_us, false);
	log_cwnd(PROBE_DRAIN, sk, frcc, tsk, rtt_us, now_us);
}

static void initiate_probe_end(struct sock *sk, struct frcc_data *frcc,
			       struct tcp_sock *tsk, u32 rtt_us, u64 now_us,
			       const struct rate_sample *rs)
{
	struct param_data *p = frcc->p_params;
	frcc->s_probe->s_probe_end_initiated = true;
	if (!p->f_drain_over_rtt) {
		tsk->snd_cwnd = frcc->s_probe->s_probe_prev_cwnd_pkts;
		update_pacing_rate(sk, frcc, tsk, rtt_us, false);
		log_cwnd(PROBE_DRAIN, sk, frcc, tsk, rtt_us, now_us);
	} else {
		// We are amortizing the decrease over a window, so every ack,
		// we will reduce by drain_pkts pkts.
		frcc->s_probe->s_probe_drain_pkts_unit =
			frcc->s_probe->s_probe_excess_pkts << P_SCALE;
		do_div(frcc->s_probe->s_probe_drain_pkts_unit, tsk->snd_cwnd);
		frcc->s_probe->s_probe_drain_pkts_rem_unit = 0;
		update_cwnd_drain(sk, frcc, tsk, rtt_us, now_us, rs);
	}
}

static void update_probe_state(struct sock *sk, struct frcc_data *frcc,
			       struct tcp_sock *tsk,
			       const struct rate_sample *rs, u32 rtt_us,
			       u64 now_us)
{
	// TODO: use inflight = cwnd style checks for start and end of probe.
	// The RTT style checks are upper bounds.

	struct param_data *p = frcc->p_params;
	u64 last_rcv_seq = get_last_rcv_seq(tsk);
	u64 last_snd_seq = get_last_snd_seq(tsk);
	u64 end_seq_snd_time;

	u32 max_rtprop_us =
		max_t(u32, p->p_ub_rtprop_us, frcc->s_min_rtprop_us);
	// Note, in cruise ended, we check if we are using
	// f_slot_greater_than_rtprop, but here for our own flow we definitely
	// want the probe to be bigger.
	if (p->f_slot_exactly_rtprop) {
		max_rtprop_us = frcc->s_min_rtprop_us;
	}
	u32 max_rtt_us = max_rtprop_us + frcc->s_slot_max_qdel_us;

	u32 wait_time_us = max_rtt_us * p->p_probe_wait_rtts;
	u64 wait_until_us = frcc->s_probe->s_probe_start_time_us + wait_time_us;

	u32 probe_duration_us = p->p_probe_duration_us;
	if (p->f_probe_duration_max_rtt) {
		probe_duration_us = max_rtt_us;
	}

#ifdef FRCC_LOG_TRACE
	printk(KERN_INFO "frcc probe_state " BASE_FMT PROBE_DEBUG_FMT SEQ_FMT,
	       BASE_VARS, PROBE_DEBUG_VARS, SEQ_VARS);
#endif

	// last_snd_seq is what we hope to snd next. Checking una > seq is as
	// good as checking acked >= seq, which is what we want.
	if (frcc->s_probe->s_probe_inflightmatch_seq == 0) {
		// The inflight match will happen after half pre-probe-RTT (old
		// RTT) under our pacing rate = 2 * new cwnd / old_rtt, i.e.,
		// last packet of new cwnd sent at time old_rtt/2.
		// Conservatively, we wait a full (packet timed) new RTT.
		// Alternatively, we can just check inflight = cwnd.
		if (after(last_rcv_seq, frcc->s_probe->s_probe_start_seq)) {
			update_pacing_rate(sk, frcc, tsk, rtt_us, false);
			frcc->s_probe->s_probe_inflightmatch_seq = last_snd_seq;
			if (!p->f_wait_rtt_after_probe) {
				frcc->s_probe->s_probe_first_seq = last_snd_seq;
				frcc->s_probe->s_probe_first_time_us = now_us;
			}
#ifdef FRCC_LOG_DEBUG
			printk(KERN_INFO
			       "frcc probe_inflightmatch flow %u "
			       "probe_inflightmatch_seq %llu probe_first_seq %llu "
			       "last_snd_seq %llu last_rcv_seq %llu ",
			       frcc->id,
			       frcc->s_probe->s_probe_inflightmatch_seq,
			       frcc->s_probe->s_probe_first_seq, last_snd_seq,
			       last_rcv_seq);
#endif
		}
	} else if (frcc->s_probe->s_probe_first_seq == 0) {
		if (after(last_rcv_seq,
			  frcc->s_probe->s_probe_inflightmatch_seq)) {
			if (!p->f_probe_wait_in_max_rtts ||
			    now_us >= wait_until_us) {
				frcc->s_probe->s_probe_first_seq = last_snd_seq;
				frcc->s_probe->s_probe_first_time_us = now_us;
#ifdef FRCC_LOG_DEBUG
				printk(KERN_INFO
				       "frcc probe_first_seq flow %u probe_first_seq %llu "
				       "last_snd_seq %llu last_rcv_seq %llu now %llu ",
				       frcc->id,
				       frcc->s_probe->s_probe_first_seq,
				       last_snd_seq, last_rcv_seq, now_us);
#endif
			}
		}
	} else if (frcc->s_probe->s_probe_last_seq == 0) {
		end_seq_snd_time = frcc->s_probe->s_probe_first_time_us +
				   probe_duration_us;
		if (time_after64(now_us, end_seq_snd_time)) {
			frcc->s_probe->s_probe_last_seq = last_snd_seq;
#ifdef FRCC_LOG_DEBUG
			printk(KERN_INFO
			       "frcc probe_last_seq flow %u probe_last_seq %llu "
			       "last_snd_seq %llu last_rcv_seq %llu now %llu ",
			       frcc->id, frcc->s_probe->s_probe_last_seq,
			       last_snd_seq, last_rcv_seq, now_us);
#endif
		}
	}
}

static void log_cwnd_update(struct sock *sk, struct frcc_data *frcc,
			    struct tcp_sock *tsk, u32 rtt_us,
			    u64 bw_estimate_pps, u64 flow_count_belief_unit,
			    u64 target_flow_count_unit, u64 target_cwnd_unit,
			    u64 next_cwnd_unit, u64 now_us)
{
#ifdef FRCC_LOG_INFO
	printk(KERN_INFO
	       "frcc cwnd_update " BASE_FMT ROUND_FMT SLOT_FMT PROBE_FMT
	       "bw_estimate_pps %llu "
	       "target_flow_count_unit %llu flow_count_belief_unit %llu "
	       "target_cwnd_unit %llu next_cwnd_unit %llu ",
	       BASE_VARS, ROUND_VARS, SLOT_VARS, PROBE_VARS, bw_estimate_pps,
	       target_flow_count_unit, flow_count_belief_unit, target_cwnd_unit,
	       next_cwnd_unit);
#endif
}

static void log_round_reset(struct sock *sk, struct frcc_data *frcc,
			    struct tcp_sock *tsk, u32 rtt_us, u64 now_us)
{
#ifdef FRCC_LOG_INFO
	printk(KERN_INFO "frcc round_reset " BASE_FMT ROUND_FMT, BASE_VARS,
	       ROUND_VARS);
#endif
}

static void log_slot_end(struct sock *sk, struct frcc_data *frcc,
			 struct tcp_sock *tsk, u32 rtt_us, u64 now_us)
{
#ifdef FRCC_LOG_INFO
	u32 slot_duration_us =
		tcp_stamp_us_delta(now_us, frcc->s_slot_start_time_us);
	printk(KERN_INFO "frcc slot_end " BASE_FMT ROUND_FMT SLOT_FMT
			 "slot_duration_us %u ",
	       BASE_VARS, ROUND_VARS, SLOT_VARS, slot_duration_us);
#endif
}

static void update_cwnd(struct sock *sk, struct frcc_data *frcc,
			struct tcp_sock *tsk, u32 rtt_us, u64 now_us)
{
	struct param_data *p = frcc->p_params;
	u32 prev_cwnd = frcc->s_probe->s_probe_prev_cwnd_pkts; // tsk->snd_cwnd;
	u64 bw_estimate_pps;
	u64 flow_count_belief_unit;
	u64 target_flow_count_unit;
	u64 target_cwnd_unit;
	u64 next_cwnd_unit;
	u32 next_cwnd;
	u64 tcwnd_hi_clamp_unit = prev_cwnd * p->p_cwnd_clamp_hi_unit;
	u64 tcwnd_lo_clamp_unit = prev_cwnd * p->p_cwnd_clamp_lo_unit;
	u64 tcwnd_num;
	u64 tcwnd_den;

	bw_estimate_pps = U64_MAX;
	if (frcc->s_probe->s_probe_min_excess_delay_us > 0) {
		bw_estimate_pps = frcc->s_probe->s_probe_excess_pkts;
		bw_estimate_pps *= USEC_PER_SEC;
		do_div(bw_estimate_pps,
		       frcc->s_probe->s_probe_min_excess_delay_us);
	}

	flow_count_belief_unit = p->p_ub_flow_count << P_SCALE;
	// ^^ this can be anything as this will never be read.
	if (frcc->s_round->s_round_max_rate_pps > 0) {
		flow_count_belief_unit = P_UNIT;
		flow_count_belief_unit *= bw_estimate_pps;
		do_div(flow_count_belief_unit,
		       frcc->s_round->s_round_max_rate_pps);
	}
	flow_count_belief_unit = max_t(u64, flow_count_belief_unit, P_UNIT);

	target_flow_count_unit = get_target_flow_count_unit(frcc);

	// Even though in the proof we apply the clamps on Ni, we implement
	// clamps on target_cwnd because of integer arithmetic
	// (target_flow_count_unit might be small, so clamps times this might
	// be same as target_flow_count_unit). We expect cwnd to be large so
	// that the clamp times cwnd is a different value.
	if (target_flow_count_unit == 0 ||
	    frcc->s_round->s_round_max_rate_pps == 0) {
		target_cwnd_unit = prev_cwnd * p->p_cwnd_clamp_hi_unit;
	} else {
		if (p->f_use_stable_cwnd_update) {
			target_cwnd_unit = prev_cwnd << P_SCALE;
			tcwnd_num = (frcc->s_min_rtprop_us << P_SCALE) +
				    p->p_contract_min_qdel_us *
					    flow_count_belief_unit;
			tcwnd_den = (frcc->s_min_rtprop_us << P_SCALE) +
				    p->p_contract_min_qdel_us *
					    target_flow_count_unit;
			target_cwnd_unit *= tcwnd_num;
			do_div(target_cwnd_unit, tcwnd_den);
			// TODO: should we convert to unit after, given there
			// is already scaling due to num, and den being in us?
			// Will unit^2 overflow?
			// target_cwnd_unit = target_cwnd_unit << P_SCALE;
		} else {
			target_cwnd_unit = prev_cwnd << P_SCALE;
			target_cwnd_unit *= flow_count_belief_unit;
			do_div(target_cwnd_unit, target_flow_count_unit);
		}
	}
	target_cwnd_unit = max_t(u64, target_cwnd_unit, tcwnd_lo_clamp_unit);
	target_cwnd_unit = min_t(u64, target_cwnd_unit, tcwnd_hi_clamp_unit);

	next_cwnd_unit =
		p->p_inv_cwnd_averaging_factor_unit * prev_cwnd +
		((p->p_cwnd_averaging_factor_unit * target_cwnd_unit) >>
		 P_SCALE);

#ifdef FRCC_LOG_DEBUG
	printk(KERN_INFO
	       "frcc cwnd_update_debug flow %u alpha %u 1-alpha %u cwnd %u "
	       "target_cwnd %llu next_cwnd %llu ",
	       frcc->id, p->p_cwnd_averaging_factor_unit,
	       p->p_inv_cwnd_averaging_factor_unit, prev_cwnd target_cwnd_unit,
	       next_cwnd_unit);
#endif

	next_cwnd = DIV_ROUND_UP_ULL(next_cwnd_unit, P_UNIT);
	next_cwnd = max_t(u32, next_cwnd, p->p_lb_cwnd_pkts);
	tsk->snd_cwnd = next_cwnd;
	update_pacing_rate(sk, frcc, tsk, rtt_us, false);

	log_cwnd_update(sk, frcc, tsk, rtt_us, bw_estimate_pps,
			flow_count_belief_unit, target_flow_count_unit,
			target_cwnd_unit, next_cwnd_unit, now_us);
	log_cwnd(PROBE_UPDATE, sk, frcc, tsk, rtt_us, now_us);
}

static void log_periodic(struct sock *sk, struct frcc_data *frcc,
			 struct tcp_sock *tsk, u32 rtt_us, u64 now_us)
{
	if (time_after64(frcc->last_log_time_us + frcc->s_min_rtprop_us,
			 now_us)) {
		return;
	}
	frcc->last_log_time_us = now_us;
#ifdef FRCC_LOG_INFO
	printk(KERN_INFO
	       "frcc periodic " BASE_FMT ROUND_FMT SLOT_FMT PROBE_FMT SEQ_FMT,
	       BASE_VARS, ROUND_VARS, SLOT_VARS, PROBE_VARS, SEQ_VARS);
#endif
}

static void slow_start(struct sock *sk, struct tcp_sock *tsk,
		       struct frcc_data *frcc, u64 now_us, u32 rtt_us)
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

	struct param_data *p = frcc->p_params;
	u64 last_recv_seq = get_last_rcv_seq(tsk);
	u64 last_snd_seq = get_last_snd_seq(tsk);
	bool should_init_ss_end =
		rtt_us > (frcc->s_min_rtprop_us + p->p_contract_min_qdel_us +
			  p->p_ub_rtterr_us);
	// TODO: contract_const subsumes rtt_err, so should we really add that
	// here?

	// checking after for snd_una is same as checking last_acked >= seq.
	bool ss_ended = frcc->s_ss_last_seq > 0 &&
			after(last_recv_seq, frcc->s_ss_last_seq);

	if (!frcc->s_ss_end_initiated) {
		if (!should_init_ss_end) {
			tsk->snd_cwnd = tsk->snd_cwnd + 1;
			update_pacing_rate(sk, frcc, tsk, rtt_us, false);
			log_cwnd(SLOW_START, sk, frcc, tsk, rtt_us, now_us);
		} else {
			// The ACK that showed high delay used a cwnd that is
			// half of waht it is now, so we revert back to that
			// cwnd.
			tsk->snd_cwnd = tsk->snd_cwnd / 2;
			tsk->snd_cwnd =
				max_t(u32, tsk->snd_cwnd, p->p_lb_cwnd_pkts);
			update_pacing_rate(sk, frcc, tsk, rtt_us, false);
			log_cwnd(SLOW_START_END, sk, frcc, tsk, rtt_us, now_us);
			frcc->s_ss_end_initiated = true;
			frcc->s_ss_last_seq = last_snd_seq;
		}
	} else {
		if (ss_ended) {
			frcc->s_ss_done = true;
			reset_round_state(frcc);
			start_new_slot(frcc, now_us);
		} else {
			// ss end initiated but not yet ended. do nothing.
		}
	}
}

static bool should_rprobe(struct frcc_data *frcc, u64 now_us)
{
	struct param_data *p = frcc->p_params;
	return (tcp_stamp_us_delta(
		       now_us, frcc->s_rprobe->s_rprobe_prev_start_time_us)) >
	       p->p_rprobe_interval_us;
}

static void rprobe(struct sock *sk, struct frcc_data *frcc,
		   struct tcp_sock *tsk, u32 rtt_us, u64 now_us)
{
	// Note, these values only make sense when the boolean conditions they
	// are used in are met.
	struct param_data *p = frcc->p_params;
	u64 rprobe_duration_us = frcc->s_slot_max_qdel_us + p->p_ub_rtprop_us;
	u64 init_rprobe_end_us =
		frcc->s_rprobe->s_rprobe_start_time_us + rprobe_duration_us;
	bool should_init_rprobe_end = time_after64(now_us, init_rprobe_end_us);
	u64 rprobe_end_us = frcc->s_rprobe->s_rprobe_init_end_time_us +
			    2 * rprobe_duration_us;
	// Above, we wait two RTTs becuase it takes one RTT to fill the
	// inflight and then one more RTT to get the ACK of the last packet of
	// the filled inflight.
	bool rprobe_ended = frcc->s_rprobe->s_rprobe_init_end_time_us > 0 &&
			    time_after64(now_us, rprobe_end_us);

	if (!frcc->s_rprobe->s_rprobe_ongoing) {
		frcc->s_rprobe->s_rprobe_ongoing = true;
		frcc->s_rprobe->s_rprobe_prev_start_time_us =
			get_rprobe_time(frcc, now_us);
		frcc->s_rprobe->s_rprobe_start_time_us = now_us;
		frcc->s_rprobe->s_rprobe_init_end_time_us = 0;
		frcc->s_rprobe->s_rprobe_prev_cwnd_pkts = tsk->snd_cwnd;
		if (frcc->s_probe->s_probe_ongoing) {
			// if a capacity probe was ongoing, we need to reset to
			// the cwnd before the probe.
			frcc->s_rprobe->s_rprobe_prev_cwnd_pkts =
				frcc->s_probe->s_probe_prev_cwnd_pkts;
		}
		frcc->s_rprobe->s_rprobe_end_initiated = false;

		tsk->snd_cwnd = p->p_lb_cwnd_pkts;
		// update_pacing_rate(sk, frcc, tsk, rtt_us);
		// ^^ do not update pacing rate here, as linux takes time to
		// increase rate after decrease.
		log_cwnd(RPROBE_DRAIN, sk, frcc, tsk, rtt_us, now_us);
		return;
	}

	// rprobe ongoing
	if (!frcc->s_rprobe->s_rprobe_end_initiated) {
		if (should_init_rprobe_end) {
			frcc->s_rprobe->s_rprobe_end_initiated = true;
			frcc->s_rprobe->s_rprobe_init_end_time_us = now_us;
			tsk->snd_cwnd = frcc->s_rprobe->s_rprobe_prev_cwnd_pkts;
			update_pacing_rate(sk, frcc, tsk, rtt_us, false);
			log_cwnd(RPROBE_REFILL, sk, frcc, tsk, rtt_us, now_us);
		}
	} else {
		if (rprobe_ended) {
			reset_rprobe_state(
				frcc, frcc->s_rprobe->s_rprobe_start_time_us);

			// slow start may also be ongoing, in that
			// case, we do not touch slow start state. If
			// if ss end had been initiated then rprobe end
			// does the same thing, if end was not
			// initiated, we go back to slow start, now
			// with a better rtprop estimate.
			reset_probe_state(frcc);
			reset_round_state(frcc);
			log_round_reset(sk, frcc, tsk, rtt_us, now_us);
			start_new_slot(frcc, now_us);
		}
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
static void on_ack(struct sock *sk, u32 ack, int flag,
		   const struct rate_sample *rs)
#else
static void on_ack(struct sock *sk, const struct rate_sample *rs)
#endif
{
	struct frcc_data *frcc = inet_csk_ca(sk);
	struct tcp_sock *tsk = tcp_sk(sk);
	struct param_data *p = frcc->p_params;
	u32 rtt_us;
	u64 now_us = tsk->tcp_mstamp;
	u32 s_slot_min_rtt_us = frcc->s_slot_min_rtt_us;
	// u32 latest_inflight_segments = rs->prior_in_flight;

	// Is struct valid? Is rate sample valid? Is RTT valid?
	if (!frcc_valid(frcc) || rs->delivered < 0 || rs->interval_us < 0 ||
	    rs->rtt_us <= 0)
		return;

	rtt_us = rs->rtt_us;
	update_estimates(frcc, tsk, rs, rtt_us);

	if (frcc->s_probe->s_probe_ongoing) {
		update_probe_state(sk, frcc, tsk, rs, rtt_us, now_us);
	}

	log_periodic(sk, frcc, tsk, rtt_us, now_us);

	if (p->f_use_rtprop_probe &&
	    (should_rprobe(frcc, now_us) || frcc->s_rprobe->s_rprobe_ongoing)) {
		rprobe(sk, frcc, tsk, rtt_us, now_us);
		return;
	}

	if (!frcc->s_ss_done) {
		slow_start(sk, tsk, frcc, now_us, rtt_us);
		return;
	}

	if (frcc->s_probe->s_probe_ongoing) {
		if (should_init_probe_end(frcc, tsk)) {
			initiate_probe_end(sk, frcc, tsk, rtt_us, now_us, rs);
		} else if (frcc->s_probe->s_probe_end_initiated) {
			update_cwnd_drain(sk, frcc, tsk, rtt_us, now_us, rs);
		}
	}

	if ((!frcc->s_probe->s_probe_ongoing && cruise_ended(frcc, now_us)) ||
	    (frcc->s_probe->s_probe_ongoing && probe_ended(frcc, tsk))) {
		log_slot_end(sk, frcc, tsk, rtt_us, now_us);

		// probe ended
		if (frcc->s_probe->s_probe_ongoing) {
			update_cwnd(sk, frcc, tsk, rtt_us, now_us);
			reset_probe_state(frcc);
		}

		if (round_ended(frcc)) {
			reset_round_state(frcc);
			log_round_reset(sk, frcc, tsk, rtt_us, now_us);
		}

		if (frcc->s_round->s_round_slots_till_now >= 1 &&
		    !frcc->s_round->s_round_probed && should_probe(frcc)) {
			frcc->s_round->s_round_probed = true;
			start_probe(sk, frcc, tsk, rtt_us, now_us,
				    s_slot_min_rtt_us);
		}
		start_new_slot(frcc, now_us);
		frcc->s_round->s_round_slots_till_now++;
	}
}

static void frcc_release(struct sock *sk)
{
	struct frcc_data *frcc = inet_csk_ca(sk);
	kfree(frcc->s_probe);
	kfree(frcc->s_rprobe);
	kfree(frcc->s_round);
	kfree(frcc->p_params);
}

static u32 frcc_ssthresh(struct sock *sk)
{
	return TCP_INFINITE_SSTHRESH;
}

static void frcc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
}

static struct tcp_congestion_ops tcp_frcc_cong_ops __read_mostly = {
	.flags = TCP_CONG_NON_RESTRICTED,
	.name = "frcc",
	.owner = THIS_MODULE,
	.init = frcc_init,
	.release = frcc_release,
	.cong_control = on_ack,
	// Since FRCC does reduce cwnd on loss. We use reno's undo method.
	.undo_cwnd = tcp_reno_undo_cwnd,
	// Slow start threshold will not exist
	.ssthresh = frcc_ssthresh,
	.cong_avoid = frcc_cong_avoid,
};

static int __init frcc_register(void)
{
	BUILD_BUG_ON(sizeof(struct frcc_data) > ICSK_CA_PRIV_SIZE);
#ifdef FRCC_LOG_INFO
	printk(KERN_INFO "frcc module_install ");
#endif
	return tcp_register_congestion_control(&tcp_frcc_cong_ops);
}

static void __exit frcc_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_frcc_cong_ops);
}

module_init(frcc_register);
module_exit(frcc_unregister);

MODULE_AUTHOR("Anup Agarwal <108anup@gmail.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP FRCC (Provably fair and robust CC)");
MODULE_VERSION("0.1");
