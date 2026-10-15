/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SWIFT_GUARD_H
#define __SWIFT_GUARD_H

/* __u8..__u64 정의. 이 헤더가 단독으로 컴파일되도록 직접 include한다.
 * BPF 프로그램(src/bpf/xdp_filter.c)과 공유하는 유일한 구조체/상수 원천(SSOT)이다.
 * 맵 값 레이아웃(filter_rule 88B 등)은 Rust src/common/bpf_layout.rs의 offset 상수와 짝을 이룬다. */
#include <linux/types.h>

/* 상수 정의 */
#define MAX_FILTER_RULES   10240
#define MAX_REDIRECT_IFS   64
#define MAX_RULE_LABEL_LEN 32

/* 프로토콜 정의 */
#define IPPROTO_ANY 255

/* 액션 정의 */
#define ACTION_PASS     1
#define ACTION_DROP     2
#define ACTION_REDIRECT 3
#define ACTION_COUNT    4

/* TCP 플래그 정의 */
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

/* 구조체 정의 */
struct prefix_key {
    __u32 prefix_len;  /* LPM 트라이의 프리픽스 길이 */
    __u32 addr;        /* IPv4 주소, 네트워크 바이트 오더.
                        * filter_rules: addr = 출발지, dst_rules: addr = 목적지 */
};

struct filter_stats {
    __u64 packets;      /* 처리된 패킷 수 */
    __u64 bytes;        /* 처리된 바이트 수 */
    __u64 last_matched; /* 마지막 매치 타임스탬프 */
};

struct filter_rule {
    __u32 priority;          /* 룰 우선순위 */
    __u8 action;             /* 액션 (통과, 드롭, 리디렉션) */
    __u8 protocol;           /* 프로토콜 (TCP, UDP, ICMP, ANY) */
    __u16 src_port_min;      /* 소스 포트 범위 최소값 */
    __u16 src_port_max;      /* 소스 포트 범위 최대값 */
    __u16 dst_port_min;      /* 대상 포트 범위 최소값 */
    __u16 dst_port_max;      /* 대상 포트 범위 최대값 */
    __u8 tcp_flags;          /* TCP 플래그 (SYN, ACK, FIN 등) */
    __u32 redirect_ifindex;  /* 리디렉션 인터페이스 인덱스 */
    __u32 rate_limit;        /* 초당 패킷 수 레이트 리밋 */
    __u32 expire;            /* 룰 만료 시간 (초) */
    char label[MAX_RULE_LABEL_LEN]; /* 룰 레이블 */
    struct filter_stats stats; /* 통계 */
};

struct if_redirect {
    __u32 ifindex;           /* 인터페이스 인덱스 */
    char ifname[16];         /* 인터페이스 이름 */
};

/* xdp_stats_map(PERCPU_ARRAY, key = __u32 슬롯 인덱스, value = struct sg_counter,
 * max_entries = SG_STAT_MAX) 슬롯 인덱스.
 * 패킷 1개는 SG_STAT_RX 1회 + 결과 슬롯(1..8) 중 정확히 1회 증가한다.
 * Rust 짝: src/common/bpf_layout.rs 의 xdp_stat::* (값이 같아야 한다). */
#define SG_STAT_RX          0  /* XDP 진입 전체 (모든 프레임, 파싱 전) */
#define SG_STAT_DROP        1  /* 룰 action=drop 으로 XDP_DROP */
#define SG_STAT_PASS        2  /* 룰 action=pass 로 XDP_PASS */
#define SG_STAT_REDIRECT    3  /* 룰 action=redirect, bpf_redirect 반환 (전송 성공 보장 아님) */
#define SG_STAT_COUNT       4  /* 룰 action=count 로 XDP_PASS */
#define SG_STAT_NO_MATCH    5  /* 정상 IPv4, 매치 룰 없음 → XDP_PASS */
#define SG_STAT_INVALID     6  /* 파서 정책으로 XDP_DROP (비정상 IPv4 헤더, tiny fragment, TCP off=1 조각) */
#define SG_STAT_NON_IPV4    7  /* 이더넷 헤더 미만 또는 EtherType≠IPv4(IPv6/ARP/VLAN 등) → 검사 없이 XDP_PASS */
#define SG_STAT_ACTION_ERR  8  /* 룰은 매치했지만 실행 불가(redirect 대상 없음, 알 수 없는 action) → XDP_PASS */
#define SG_STAT_MAX         9

/* xdp_stats_map 값. 16B, align 8, 패딩 없음. 호스트 엔디안.
 * Rust 짝: bpf_layout::SG_COUNTER_SIZE (= 16), decode_counter. */
struct sg_counter {
    __u64 packets;
    __u64 bytes;    /* data_end - data (XDP가 본 L2 프레임 길이, FCS 제외) */
};

#endif /* __SWIFT_GUARD_H */
