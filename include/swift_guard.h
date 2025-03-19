/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SWIFT_GUARD_H
#define __SWIFT_GUARD_H

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
    __u32 addr;        /* IPv4 주소 */
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

#endif /* __SWIFT_GUARD_H */
