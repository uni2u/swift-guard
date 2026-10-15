// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 맵 값 구조체·ACTION_*·TCP_FLAG_*·MAX_*·IPPROTO_ANY의 유일한 원천.
 * __u8..__u64는 <linux/bpf.h> → <linux/types.h>에서 온다(stdint.h 사용 금지:
 * -target bpf + glibc gnu/stubs-32.h 문제). */
#include "swift_guard.h"

/* 패킷 헤더 정의.
 * 비트필드는 쓰지 않는다(비트 배치가 엔디안에 종속). version/IHL은 첫 바이트를 마스킹하고,
 * TCP 플래그는 TCP 헤더 byte 13을 직접 읽는다. */
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __u16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8 ver_ihl;      /* 상위 4비트 version, 하위 4비트 IHL(32비트 워드 수) */
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;    /* 네트워크 오더: flags(3비트) + fragment offset(13비트, 8바이트 단위) */
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
} __attribute__((packed));

/* TCP/UDP 공통 앞 4바이트(포트). TCP는 이 뒤에 seq/ack가 오고 byte 13이 플래그다. */
struct l4ports {
    __u16 source;
    __u16 dest;
} __attribute__((packed));

#define TCP_HDR_MIN_LEN   20   /* doff=5, 옵션 없음 */
#define UDP_HDR_LEN        8
#define TCP_FLAGS_OFFSET  13   /* 하위 6비트 = FIN SYN RST PSH ACK URG = TCP_FLAG_* 와 같은 비트 */
#define TCP_FLAGS_MASK    0x3F

#define IP_MF      0x2000      /* More Fragments (호스트 오더 frag_off 기준) */
#define IP_OFFMASK 0x1FFF      /* fragment offset (8바이트 단위) */

/* 프로토콜 번호 */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

/* 이더넷 프로토콜 */
#define ETH_P_IP 0x0800

/* XDP_PASS/XDP_DROP/XDP_ABORTED는 <linux/bpf.h>의 enum xdp_action을 사용한다. */

/* 맵 정의 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct prefix_key);
    __type(value, struct filter_rule);
    __uint(max_entries, MAX_FILTER_RULES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} filter_rules SEC(".maps");

/* 목적지 IP prefix 룰. 키 addr = iph->daddr(네트워크 바이트 오더), 값 형식은
 * filter_rules와 같은 struct filter_rule(88B). src 룰이 매치하지 않을 때만 평가된다. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct prefix_key);
    __type(value, struct filter_rule);
    __uint(max_entries, MAX_FILTER_RULES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} dst_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct if_redirect);
    __uint(max_entries, MAX_REDIRECT_IFS);
} redirect_map SEC(".maps");

/* 전역 룰 매치 통계(key 0). 룰에 매치한 패킷만 센다(의미 불변). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct filter_stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

/* XDP가 본 전체 패킷(SG_STAT_RX)과 결과별 카운터. key = SG_STAT_* (swift_guard.h).
 * 패킷마다 RX 1회 + 결과 슬롯 정확히 1회 증가한다. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct sg_counter);
    __uint(max_entries, SG_STAT_MAX);
} xdp_stats_map SEC(".maps");

/* 헬퍼 함수 */
/* xdp_stats_map[idx] += (1, bytes). PERCPU 슬롯이라 경합이 없어 일반 덧셈을 쓴다. */
static __always_inline void count_slot(__u32 idx, __u64 bytes)
{
    struct sg_counter *c = bpf_map_lookup_elem(&xdp_stats_map, &idx);

    if (c) {
        c->packets += 1;
        c->bytes += bytes;
    }
}

/* rule 값(LPM 맵 값 안의 stats)과 전역 stats_map(key 0)을 함께 갱신한다.
 * stats는 bpf_map_lookup_elem 결과(NULL 검사 완료)인 맵 값 포인터여야 한다. */
static __always_inline void update_stats(struct filter_stats *stats, __u64 bytes)
{
    __u32 key = 0;
    struct filter_stats *value;

    /* per-rule 통계 (P-M2). 여러 CPU가 같은 rule을 동시에 갱신하므로 atomic add. */
    __sync_fetch_and_add(&stats->packets, 1);
    __sync_fetch_and_add(&stats->bytes, bytes);
    stats->last_matched = bpf_ktime_get_ns();

    /* 전역 통계 (PERCPU 배열 — CPU별 슬롯이라 경합은 없지만 기존 동작 유지) */
    value = bpf_map_lookup_elem(&stats_map, &key);
    if (value) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, bytes);
    }
}

/* 룰의 세부 조건이 맞으면 1. rule은 NULL 검사가 끝난 맵 값 포인터여야 한다.
 * - protocol: IPPROTO_ANY 또는 일치.
 * - 포트 조건: (0, 65535)가 "조건 없음". 조건이 있으면 L4 헤더를 읽은 패킷(l4_known)에만 매치한다
 *   (ICMP, 후속 조각, 잘린 패킷은 포트 룰과 매치하지 않는다).
 * - TCP 플래그: TCP 패킷이고 rule->tcp_flags != 0 일 때만 본다. l4_known이 아니면 미매치.
 *   TCP가 아닌 패킷에서는 기존처럼 무시한다. */
static __always_inline int rule_matches(const struct filter_rule *r, __u8 proto, int l4_known,
                                        __u16 sport, __u16 dport, __u8 flags)
{
    int has_port;

    if (r->protocol != IPPROTO_ANY && r->protocol != proto)
        return 0;

    has_port = !(r->src_port_min == 0 && r->src_port_max == 65535) ||
               !(r->dst_port_min == 0 && r->dst_port_max == 65535);
    if (has_port) {
        if (!l4_known)
            return 0;
        if (!(r->src_port_min <= sport && sport <= r->src_port_max))
            return 0;
        if (!(r->dst_port_min <= dport && dport <= r->dst_port_max))
            return 0;
    }

    if (proto == IPPROTO_TCP && r->tcp_flags != 0) {
        if (!l4_known)
            return 0;
        if ((r->tcp_flags & flags) != r->tcp_flags)
            return 0;
    }

    return 1;
}

/* 매치된 룰의 액션을 수행하고 XDP 액션을 반환한다. *slot에 결과 카운터 슬롯을 기록한다.
 * redirect 실패(redirect_map에 없음)와 알 수 없는 action은 룰 통계 없이 XDP_PASS(ACTION_ERR).
 * rule은 NULL 검사가 끝난 맵 값 포인터. */
static __always_inline int apply_rule(struct filter_rule *rule, __u64 bytes, __u32 *slot)
{
    switch (rule->action) {
    case ACTION_DROP:
        update_stats(&rule->stats, bytes);
        *slot = SG_STAT_DROP;
        return XDP_DROP;

    case ACTION_REDIRECT:
        {
            __u32 ifindex = rule->redirect_ifindex;
            struct if_redirect *redirect;

            redirect = bpf_map_lookup_elem(&redirect_map, &ifindex);
            if (redirect && redirect->ifindex > 0) {
                update_stats(&rule->stats, bytes);
                *slot = SG_STAT_REDIRECT;
                return bpf_redirect(redirect->ifindex, 0);
            }
        }
        *slot = SG_STAT_ACTION_ERR;
        return XDP_PASS;

    case ACTION_PASS:
        update_stats(&rule->stats, bytes);
        *slot = SG_STAT_PASS;
        return XDP_PASS;

    case ACTION_COUNT:
        /* 통계만 집계하고 통과 (P-m1) */
        update_stats(&rule->stats, bytes);
        *slot = SG_STAT_COUNT;
        return XDP_PASS;

    default:
        *slot = SG_STAT_ACTION_ERR;
        return XDP_PASS;
    }
}

/* IPv4 패킷 처리. 이더넷 헤더는 호출자가 경계 검사를 마쳤다. *slot에 결과 슬롯을 기록한다.
 * 정책(계획 C2):
 *   - IPv4 헤더 20B 미만, version≠4, IHL<5, IHL*4 > 패킷 → INVALID DROP
 *   - tot_len < IHL*4, tot_len > 실제 L3 길이(data_end - iph) → INVALID DROP (커널 ip_rcv도 버린다)
 *   - L4는 iph + IHL*4 에서 읽는다(IP 옵션 건너뜀)
 *   - L4 길이 = tot_len - IHL*4. data_end가 아니라 이 값으로 L4 완전성을 판정한다.
 *     NIC가 60B 미만 프레임에 붙이는 이더넷 패딩(data_end에 포함됨)을 L4로 읽지 않기 위해서다.
 *   - 첫 조각/비조각: L4 길이 ≥ TCP 20B·UDP 8B 이면 포트·플래그를 읽는다(l4_known=1).
 *     헤더가 불완전하면 MF=1(tiny fragment, RFC 1858) → INVALID DROP, MF=0(잘린 패킷) → l4_known=0
 *   - 후속 조각: TCP이고 offset=1 → INVALID DROP(RFC 1858), 그 외 l4_known=0
 *   - INVALID 판정은 룰 조회보다 먼저다(pass 룰로 예외 처리 불가). */
static __always_inline int handle_ipv4(void *data_end, struct iphdr *iph, __u64 bytes,
                                       __u32 *slot)
{
    if ((void *)(iph + 1) > data_end) {
        *slot = SG_STAT_INVALID;
        return XDP_DROP;
    }

    __u8 vihl = iph->ver_ihl;
    __u32 ihl = vihl & 0x0f;            /* 0..15: verifier가 오프셋 상한(60)을 증명한다 */
    if ((vihl >> 4) != 4 || ihl < 5) {
        *slot = SG_STAT_INVALID;
        return XDP_DROP;
    }

    void *l4 = (void *)iph + ihl * 4;
    if (l4 > data_end) {                /* 옵션이 패킷보다 길다 */
        *slot = SG_STAT_INVALID;
        return XDP_DROP;
    }

    /* tot_len 검증. L4 길이는 data_end(패딩 포함)가 아니라 tot_len으로 정한다. */
    __u32 tot_len = bpf_ntohs(iph->tot_len);
    __u32 l3_avail = (__u32)(data_end - (void *)iph);
    if (tot_len < ihl * 4 || tot_len > l3_avail) {
        *slot = SG_STAT_INVALID;
        return XDP_DROP;
    }
    __u32 l4_len = tot_len - ihl * 4;

    __u32 ip_src = iph->saddr;
    __u32 ip_dst = iph->daddr;
    __u8 protocol = iph->protocol;
    __u16 frag = bpf_ntohs(iph->frag_off);
    __u16 frag_offset = frag & IP_OFFMASK;
    int more_frags = (frag & IP_MF) != 0;

    int l4_known = 0;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 tcp_flags = 0;

    if (frag_offset == 0) {
        /* 비조각 또는 첫 조각 */
        if (protocol == IPPROTO_TCP) {
            /* l4_len 조건이 의미 판정, data_end 조건은 verifier용(tot_len ≤ l3_avail이라 함께 참) */
            if (l4_len >= TCP_HDR_MIN_LEN && l4 + TCP_HDR_MIN_LEN <= data_end) {
                struct l4ports *p = l4;
                src_port = bpf_ntohs(p->source);
                dst_port = bpf_ntohs(p->dest);
                tcp_flags = ((__u8 *)l4)[TCP_FLAGS_OFFSET] & TCP_FLAGS_MASK;
                l4_known = 1;
            } else if (more_frags) {
                *slot = SG_STAT_INVALID;    /* tiny fragment */
                return XDP_DROP;
            }
        } else if (protocol == IPPROTO_UDP) {
            if (l4_len >= UDP_HDR_LEN && l4 + UDP_HDR_LEN <= data_end) {
                struct l4ports *p = l4;
                src_port = bpf_ntohs(p->source);
                dst_port = bpf_ntohs(p->dest);
                l4_known = 1;
            } else if (more_frags) {
                *slot = SG_STAT_INVALID;    /* tiny fragment */
                return XDP_DROP;
            }
        }
        /* 그 외 프로토콜(ICMP 등): l4_known = 0 */
    } else if (protocol == IPPROTO_TCP && frag_offset == 1) {
        /* 후속 조각이 TCP 헤더(플래그 포함)를 덮어쓸 수 있다 (RFC 1858) */
        *slot = SG_STAT_INVALID;
        return XDP_DROP;
    }
    /* 그 외 후속 조각: L4 헤더 없음 → l4_known = 0 */

    /* 필터 룰 확인: (a) 출발지 룰 → (b) 목적지 룰 → (c) PASS(NO_MATCH).
     * 출발지 룰이 매치하면 그 결과(redirect 실패로 인한 PASS 포함)로 끝나고 목적지 맵은 보지 않는다.
     * apply_rule 호출은 한 곳에만 둔다(인라인 사본 1개). */
    struct prefix_key key = {0};
    struct filter_rule *rule;

    key.prefix_len = 32; // 정확한 IP 매치 (LPM: 최장 prefix 룰 1개)
    key.addr = ip_src;
    rule = bpf_map_lookup_elem(&filter_rules, &key);
    if (!rule || !rule_matches(rule, protocol, l4_known, src_port, dst_port, tcp_flags)) {
        key.prefix_len = 32;
        key.addr = ip_dst;
        rule = bpf_map_lookup_elem(&dst_rules, &key);
        if (!rule || !rule_matches(rule, protocol, l4_known, src_port, dst_port, tcp_flags)) {
            *slot = SG_STAT_NO_MATCH;
            return XDP_PASS;
        }
    }

    return apply_rule(rule, bytes, slot);
}

SEC("xdp")
int xdp_filter_func(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 bytes = (__u64)(data_end - data);
    __u32 slot = SG_STAT_NON_IPV4;
    int ret = XDP_PASS;

    /* XDP 진입 전체. 파싱 전에 무조건 센다. */
    count_slot(SG_STAT_RX, bytes);

    /* 이더넷 헤더 미만 또는 IPv4가 아닌 프레임(IPv6/ARP/802.1Q 등)은 검사 없이 통과 */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) <= data_end && eth->h_proto == bpf_htons(ETH_P_IP))
        ret = handle_ipv4(data_end, (void *)(eth + 1), bytes, &slot);

    /* 결과 슬롯은 모든 경로에서 정확히 1회 */
    count_slot(slot, bytes);
    return ret;
}

char _license[] SEC("license") = "GPL";
