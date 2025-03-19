/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "swift_guard.h"

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
    __type(key, __u32);
    __type(value, struct if_redirect);
    __uint(max_entries, MAX_REDIRECT_IFS);
} redirect_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct filter_stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

/* 헬퍼 함수 */
static __always_inline void update_stats(struct filter_stats *stats, __u32 packets, __u32 bytes)
{
    __u32 key = 0;
    struct filter_stats *value;
    
    value = bpf_map_lookup_elem(&stats_map, &key);
    if (value) {
        __sync_fetch_and_add(&value->packets, packets);
        __sync_fetch_and_add(&value->bytes, bytes);
    }
}

static __always_inline int handle_ipv4(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph)
{
    void *data_end = (void *)(long)ctx->data_end;
    __u32 ip_src = iph->saddr;
    __u32 ip_dst = iph->daddr;
    __u8 protocol = iph->protocol;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 tcp_flags = 0;
    
    /* 5-tuple 정보 추출 */
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(*iph);
        
        if ((void *)tcph + sizeof(struct tcphdr) > data_end)
            return XDP_PASS;
            
        src_port = bpf_ntohs(tcph->source);
        dst_port = bpf_ntohs(tcph->dest);
        tcp_flags = (tcph->fin) | (tcph->syn << 1) | (tcph->rst << 2) | 
                    (tcph->psh << 3) | (tcph->ack << 4) | (tcph->urg << 5);
                    
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + sizeof(*iph);
        
        if ((void *)udph + sizeof(struct udphdr) > data_end)
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
                    __u32 ifindex = rule->redirect_ifindex;
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
    struct ethhdr *eth;
    
    /* 이더넷 헤더 파싱 */
    eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
        
    /* IP 헤더 파싱 */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)eth + sizeof(*eth);
        
        if ((void *)iph + sizeof(*iph) > data_end)
            return XDP_PASS;
            
        return handle_ipv4(ctx, eth, iph);
    }
    
    /* 지원되지 않는 패킷은 통과 */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
