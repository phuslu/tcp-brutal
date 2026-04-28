//go:build ignore

#include "vmlinux.h"
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define TCP_BRUTAL_PARAMS 23301

struct brutal_params {
    __u64 rate;
    __u32 cwnd_gain;
} __attribute__((packed));

#define INIT_PACING_RATE 125000ULL
#define INIT_CWND_GAIN 20U

#define MIN_PACING_RATE 62500ULL
#define MIN_CWND_GAIN 5U
#define MAX_CWND_GAIN 80U
#define MIN_CWND 4U

#define USEC_PER_SEC 1000000ULL
#define USEC_PER_MSEC 1000U
#define MSEC_PER_SEC 1000ULL

#define TCP_CA_NAME_MAX 16
#define TCP_CONG_NON_RESTRICTED (1U << 0)
#define MIN_PKT_INFO_SAMPLES 50U
#define MIN_ACK_RATE_PERCENT 80U

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0)
#error "tcp-brutal requires Linux 6.10 or newer"
#endif

#define BRUTAL_CA_PRIV_SIZE sizeof(((struct inet_connection_sock *)0)->icsk_ca_priv)
#define BRUTAL_CA_HEADER_SIZE (2 * sizeof(__u64) + 2 * sizeof(__u32))
#define BRUTAL_RAW_PKT_INFO_SLOTS \
    ((BRUTAL_CA_PRIV_SIZE - BRUTAL_CA_HEADER_SIZE) / sizeof(struct brutal_pkt_info))
#define BRUTAL_PKT_INFO_SLOTS \
    (BRUTAL_RAW_PKT_INFO_SLOTS < 3 ? 3 : \
        (BRUTAL_RAW_PKT_INFO_SLOTS > 5 ? 5 : BRUTAL_RAW_PKT_INFO_SLOTS))

struct brutal_pkt_info {
    __u64 sec;
    __u32 acked;
    __u32 losses;
};

struct brutal {
    __u64 rate;
    __u64 next_param_check_sec;
    __u32 cwnd_gain;
    __u32 param_generation;
    struct brutal_pkt_info slots[BRUTAL_PKT_INFO_SLOTS];
};

struct brutal_param_storage {
    __u64 rate;
    __u32 cwnd_gain;
    __u32 generation;
};

_Static_assert(sizeof(struct brutal) <= BRUTAL_CA_PRIV_SIZE,
               "struct brutal is too large for inet_connection_sock ca_priv");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct brutal_param_storage);
} brutal_sk_storage SEC(".maps");

static __always_inline struct tcp_sock *brutal_tcp_sk(const struct sock *sk)
{
    return (struct tcp_sock *)sk;
}

static __always_inline struct brutal *brutal_ca(const struct sock *sk)
{
    return (struct brutal *)brutal_tcp_sk(sk)->inet_conn.icsk_ca_priv;
}

static __always_inline void brutal_init_params(struct brutal_param_storage *storage)
{
    __builtin_memset(storage, 0, sizeof(*storage));
    storage->rate = INIT_PACING_RATE;
    storage->cwnd_gain = INIT_CWND_GAIN;
}

static __always_inline bool brutal_valid_params(__u64 rate, __u32 cwnd_gain)
{
    return rate >= MIN_PACING_RATE &&
           cwnd_gain >= MIN_CWND_GAIN &&
           cwnd_gain <= MAX_CWND_GAIN;
}

static __always_inline void brutal_apply_params(struct brutal *brutal, __u64 rate,
                                                __u32 cwnd_gain, __u32 generation)
{
    brutal->rate = rate;
    brutal->cwnd_gain = cwnd_gain;
    brutal->param_generation = generation;
}

static __always_inline __u64 brutal_tcp_sock_get_sec(const struct tcp_sock *tp)
{
    return tp->tcp_mstamp / USEC_PER_SEC;
}

static __always_inline void brutal_tcp_snd_cwnd_set(struct tcp_sock *tp, __u32 val)
{
    if (val > 0)
        tp->snd_cwnd = val;
}

static __always_inline __u64 brutal_min_u64(__u64 a, __u64 b)
{
    return a < b ? a : b;
}

static __always_inline void brutal_init_ca(struct brutal *brutal)
{
    __builtin_memset(brutal, 0, sizeof(*brutal));
    brutal->rate = INIT_PACING_RATE;
    brutal->cwnd_gain = INIT_CWND_GAIN;
}

static __always_inline void brutal_try_apply_stored_params(struct sock *sk,
                                                           struct brutal *brutal,
                                                           __u64 sec)
{
    struct brutal_param_storage *params;

    if (sec < brutal->next_param_check_sec)
        return;

    brutal->next_param_check_sec = sec + 1;
    params = bpf_sk_storage_get(&brutal_sk_storage, sk, NULL, 0);
    if (!params || !params->generation ||
        params->generation == brutal->param_generation)
        return;

    if (brutal_valid_params(params->rate, params->cwnd_gain))
        brutal_apply_params(brutal, params->rate, params->cwnd_gain,
                            params->generation);
}

static __always_inline struct brutal_pkt_info *brutal_get_slot(struct brutal *brutal,
                                                               __u64 slot)
{
    switch (slot) {
    case 0:
        return &brutal->slots[0];
    case 1:
        return &brutal->slots[1];
    case 2:
        return &brutal->slots[2];
    case 3:
        if (BRUTAL_PKT_INFO_SLOTS > 3)
            return &brutal->slots[3];
        __builtin_unreachable();
    case 4:
        if (BRUTAL_PKT_INFO_SLOTS > 4)
            return &brutal->slots[4];
        __builtin_unreachable();
    default:
        __builtin_unreachable();
    }
}

static __always_inline __u64 brutal_effective_rate(const struct sock *sk, __u64 rate)
{
    return brutal_min_u64(rate, sk->sk_max_pacing_rate);
}

static __always_inline __u32 brutal_target_cwnd(const struct sock *sk, __u64 rate)
{
    const struct tcp_sock *tp = brutal_tcp_sk(sk);
    const struct brutal *brutal = brutal_ca(sk);
    __u32 mss = tp->mss_cache ? tp->mss_cache : 1;
    __u32 rtt_ms = (tp->srtt_us >> 3) / USEC_PER_MSEC;
    __u32 gain = brutal->cwnd_gain ? brutal->cwnd_gain : INIT_CWND_GAIN;
    __u64 cwnd;

    if (!rtt_ms)
        rtt_ms = 1;

    cwnd = rate / MSEC_PER_SEC;
    cwnd *= rtt_ms;
    cwnd /= mss;
    cwnd *= gain;
    cwnd /= 10;
    if (cwnd < MIN_CWND)
        cwnd = MIN_CWND;

    return (__u32)brutal_min_u64(cwnd, tp->snd_cwnd_clamp);
}

static __always_inline void brutal_update_rate(struct sock *sk, struct brutal *brutal,
                                               __u64 sec)
{
    struct tcp_sock *tp = brutal_tcp_sk(sk);
    __u64 min_sec = 0;
    __u32 acked = 0;
    __u32 losses = 0;
    __u32 ack_rate;
    __u64 rate = brutal->rate;
    __u64 effective_rate;
    __u8 ca_state;

    if (sec > BRUTAL_PKT_INFO_SLOTS - 1)
        min_sec = sec - (BRUTAL_PKT_INFO_SLOTS - 1);

#pragma unroll
    for (int i = 0; i < BRUTAL_PKT_INFO_SLOTS; i++) {
        if (brutal->slots[i].sec >= min_sec) {
            acked += brutal->slots[i].acked;
            losses += brutal->slots[i].losses;
        }
    }

    if (acked + losses < MIN_PKT_INFO_SAMPLES) {
        ack_rate = 100;
    } else {
        ack_rate = acked * 100 / (acked + losses);
        if (ack_rate < MIN_ACK_RATE_PERCENT)
            ack_rate = MIN_ACK_RATE_PERCENT;
    }

    rate = rate * 100 / ack_rate;

    ca_state = BPF_CORE_READ_BITFIELD_PROBED((struct inet_connection_sock *)sk, icsk_ca_state);
    if (ca_state >= TCP_CA_Recovery)
        rate = rate * 3 / 4;

    effective_rate = brutal_effective_rate(sk, rate);

    brutal_tcp_snd_cwnd_set(tp, brutal_target_cwnd(sk, effective_rate));
    sk->sk_pacing_rate = effective_rate;
}

SEC("cgroup/setsockopt")
int brutal_setsockopt(struct bpf_sockopt *ctx)
{
    struct brutal_param_storage initial;
    struct brutal_param_storage *stored;
    struct brutal_params params;
    void *optval = ctx->optval;
    void *optval_end = ctx->optval_end;

    if (ctx->level != IPPROTO_TCP || ctx->optname != TCP_BRUTAL_PARAMS)
        return 1;

    if (!ctx->sk || ctx->optlen < (int)sizeof(params) ||
        (char *)optval + sizeof(params) > (char *)optval_end)
        return 0;

    __builtin_memcpy(&params, optval, sizeof(params));

    if (!brutal_valid_params(params.rate, params.cwnd_gain))
        return 0;

    brutal_init_params(&initial);
    stored = bpf_sk_storage_get(&brutal_sk_storage, ctx->sk, &initial,
                                BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!stored)
        return 0;

    stored->rate = params.rate;
    stored->cwnd_gain = params.cwnd_gain;
    stored->generation++;
    if (!stored->generation)
        stored->generation = 1;
    ctx->optlen = -1;

    return 1;
}

SEC("struct_ops")
void BPF_PROG(brutal_init, struct sock *sk)
{
    struct brutal *brutal = brutal_ca(sk);
    struct brutal_param_storage *params;

    brutal_init_ca(brutal);

    params = bpf_sk_storage_get(&brutal_sk_storage, sk, NULL, 0);
    if (params && params->generation &&
        brutal_valid_params(params->rate, params->cwnd_gain))
        brutal_apply_params(brutal, params->rate, params->cwnd_gain,
                            params->generation);

    if (sk->sk_pacing_status == SK_PACING_NONE)
        sk->sk_pacing_status = SK_PACING_NEEDED;
}

SEC("struct_ops")
void BPF_PROG(brutal_cong_control, struct sock *sk, __u32 ack, int flag,
              const struct rate_sample *rs)
{
    struct tcp_sock *tp = brutal_tcp_sk(sk);
    struct brutal *brutal = brutal_ca(sk);
    struct brutal_pkt_info *slot_info;
    __u64 sec;
    __u64 slot;

    (void)ack;
    (void)flag;

    sec = brutal_tcp_sock_get_sec(tp);
    brutal_try_apply_stored_params(sk, brutal, sec);

    if (rs->delivered >= 0 && rs->interval_us > 0) {
        slot = sec % BRUTAL_PKT_INFO_SLOTS;
        slot_info = brutal_get_slot(brutal, slot);

        __u32 acked = rs->acked_sacked > 0 ? (__u32)rs->acked_sacked : 0;
        __u32 losses = rs->losses > 0 ? (__u32)rs->losses : 0;

        if (slot_info->sec == sec) {
            slot_info->acked += acked;
            slot_info->losses += losses;
        } else {
            slot_info->sec = sec;
            slot_info->acked = acked;
            slot_info->losses = losses;
        }
    }

    brutal_update_rate(sk, brutal, sec);
}

SEC("struct_ops")
__u32 BPF_PROG(brutal_undo_cwnd, struct sock *sk)
{
    struct tcp_sock *tp = brutal_tcp_sk(sk);
    struct brutal *brutal = brutal_ca(sk);

    /* Use raw rate (no ack_rate boost, no recovery halving) — undo recovers
     * cwnd to the steady-state target as if the spurious event hadn't happened. */
    __u32 target = brutal_target_cwnd(sk, brutal_effective_rate(sk, brutal->rate));

    return target > tp->snd_cwnd ? target : tp->snd_cwnd;
}

SEC("struct_ops")
__u32 BPF_PROG(brutal_ssthresh, struct sock *sk)
{
    struct brutal *brutal = brutal_ca(sk);

    return brutal_target_cwnd(sk, brutal_effective_rate(sk, brutal->rate));
}

SEC("struct_ops")
void BPF_PROG(brutal_release, struct sock *sk)
{
    bpf_sk_storage_delete(&brutal_sk_storage, sk);
}

SEC(".struct_ops.link")
struct tcp_congestion_ops brutal = {
    .flags = TCP_CONG_NON_RESTRICTED,
    .name = "brutal",
    .init = (void *)brutal_init,
    .cong_control = (void *)brutal_cong_control,
    .undo_cwnd = (void *)brutal_undo_cwnd,
    .ssthresh = (void *)brutal_ssthresh,
    .release = (void *)brutal_release,
};

char LICENSE[] SEC("license") = "GPL";
