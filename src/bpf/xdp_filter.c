// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* 패킷 헤더 정의 */
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    uint16_t h_proto;
} __attribute__((packed));

struct iphdr {
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t res1:4;
    uint8_t doff:4;
    uint8_t fin:1;
    uint8_t syn:1;
    uint8_t rst:1;
    uint8_t psh:1;
    uint8_t ack:1;
    uint8_t urg:1;
    uint8_t res2:2;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} __attribute__((packed));

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} __attribute__((packed));

/* 프로토콜 번호 */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define IPPROTO_ANY 255

/* 이더넷 프로토콜 */
#define ETH_P_IP 0x0800

/* XDP 액션 */
#define XDP_PASS 2
#define XDP_DROP 1
#define XDP_ABORTED 0

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

/* 맵 상수 */
#define MAX_FILTER_RULES 10240
#define MAX_REDIRECT_IFS 64
#define MAX_RULE_LABEL_LEN 32

/* 구조체 정의 */
struct prefix_key {
    uint32_t prefix_len;  /* LPM 트라이의 프리픽스 길이 */
    uint32_t addr;        /* IPv4 주소 */
};

struct filter_stats {
    uint64_t packets;      /* 처리된 패킷 수 */
    uint64_t bytes;        /* 처리된 바이트 수 */
    uint64_t last_matched; /* 마지막 매치 타임스탬프 */
};

struct filter_rule {
    uint32_t priority;          /* 룰 우선순위 */
    uint8_t action;             /* 액션 (통과, 드롭, 리디렉션) */
    uint8_t protocol;           /* 프로토콜 (TCP, UDP, ICMP, ANY) */
    uint16_t src_port_min;      /* 소스 포트 범위 최소값 */
    uint16_t src_port_max;      /* 소스 포트 범위 최대값 */
    uint16_t dst_port_min;      /* 대상 포트 범위 최소값 */
    uint16_t dst_port_max;      /* 대상 포트 범위 최대값 */
    uint8_t tcp_flags;          /* TCP 플래그 (SYN, ACK, FIN 등) */
    uint32_t redirect_ifindex;  /* 리디렉션 인터페이스 인덱스 */
    uint32_t rate_limit;        /* 초당 패킷 수 레이트 리밋 */
    uint32_t expire;            /* 룰 만료 시간 (초) */
    char label[MAX_RULE_LABEL_LEN]; /* 룰 레이블 */
    struct filter_stats stats; /* 통계 */
};

struct if_redirect {
    uint32_t ifindex;           /* 인터페이스 인덱스 */
    char ifname[16];         /* 인터페이스 이름 */
};

/* 맵 정의 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct prefix_key);
    __type(value, struct filter_rule);
    __uint(max_entries, MAX_FILTER_RULES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} filter_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, struct if_redirect);
    __uint(max_entries, MAX_REDIRECT_IFS);
} redirect_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, uint32_t);
    __type(value, struct filter_stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

/* 헬퍼 함수 */
static __always_inline void update_stats(struct filter_stats *stats, uint32_t packets, uint32_t bytes)
{
    uint32_t key = 0;
    struct filter_stats *value;
    
    value = bpf_map_lookup_elem(&stats_map, &key);
    if (value) {
        __sync_fetch_and_add(&value->packets, packets);
        __sync_fetch_and_add(&value->bytes, bytes);
    }
}

static __always_inline int handle_ipv4(struct xdp_md *ctx, void *data, void *data_end)
{
    /* 이더넷 헤더 추출 */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
        
    /* IP 헤더 추출 */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
        
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint8_t protocol = iph->protocol;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t tcp_flags = 0;
    
    /* 5-tuple 정보 추출 */
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)(iph + 1);
        
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;
            
        src_port = bpf_ntohs(tcph->source);
        dst_port = bpf_ntohs(tcph->dest);
        tcp_flags = (tcph->fin) | (tcph->syn << 1) | (tcph->rst << 2) | 
                    (tcph->psh << 3) | (tcph->ack << 4) | (tcph->urg << 5);
                    
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)(iph + 1);
        
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;
            
        src_port = bpf_ntohs(udph->source);
        dst_port = bpf_ntohs(udph->dest);
    }
    
    /* 필터 룰 확인 */
    struct prefix_key key = {0};
    struct filter_rule *rule;
    
    key.prefix_len = 32; // 정확한 IP 매치
    key.addr = ip_src;
    
    rule = bpf_map_lookup_elem(&filter_rules, &key);
    if (rule) {
        /* 포트 및 프로토콜 매치 확인 */
        if ((rule->protocol == IPPROTO_ANY || rule->protocol == protocol) &&
            (rule->src_port_min <= src_port && src_port <= rule->src_port_max) &&
            (rule->dst_port_min <= dst_port && dst_port <= rule->dst_port_max) &&
            ((protocol != IPPROTO_TCP) || ((rule->tcp_flags & tcp_flags) == rule->tcp_flags))) {
            
            /* 룰에 따른 액션 수행 */
            switch (rule->action) {
            case ACTION_DROP:
                update_stats(&rule->stats, 1, ctx->data_end - ctx->data);
                return XDP_DROP;
                
            case ACTION_REDIRECT:
                {
                    uint32_t ifindex = rule->redirect_ifindex;
                    struct if_redirect *redirect;
                    
                    redirect = bpf_map_lookup_elem(&redirect_map, &ifindex);
                    if (redirect && redirect->ifindex > 0) {
                        update_stats(&rule->stats, 1, ctx->data_end - ctx->data);
                        return bpf_redirect(redirect->ifindex, 0);
                    }
                }
                break;
                
            case ACTION_PASS:
                update_stats(&rule->stats, 1, ctx->data_end - ctx->data);
                return XDP_PASS;
                
            default:
                break;
            }
        }
    }
    
    /* 기본적으로 패킷 통과 */
    return XDP_PASS;
}

SEC("xdp")
int xdp_filter_func(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    /* 이더넷 헤더 파싱 */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
        
    /* IP 헤더 파싱 */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        return handle_ipv4(ctx, data, data_end);
    }
    
    /* 지원되지 않는 패킷은 통과 */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
