// xdp_filter.bpf.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 확장된 필터 키 구조체 (5-튜플+)
struct filter_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  tcp_flags;
    __u16 pkt_length;
    __u8  pad[4]; // 정렬을 위한 패딩
} __attribute__((packed));

// 필터링 액션 및 메타데이터
struct filter_value {
    __u32 action;
    __u32 redirect_ifindex;
    __u32 priority;
    __u32 rate_limit;
    __u64 timestamp;
    __u32 expire_seconds;
    __u64 packet_count;
    __u64 byte_count;
} __attribute__((packed));

// 필터 맵: 트래픽 분류 및 액션 저장
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(key_size, sizeof(struct filter_key));
    __uint(value_size, sizeof(struct filter_value));
    __uint(map_flags, BPF_F_NO_PREALLOC);
} filter_map SEC(".maps");

// 통계 맵: 성능 데이터 추적
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

SEC("xdp")
int xdp_filter_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // L2 헤더 파싱 및 유효성 검사
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
        
    // IPv4 패킷만 처리
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;
    
    // L3 헤더 파싱
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // 기본 필터 키 구성
    struct filter_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .protocol = ip->protocol,
        .pkt_length = data_end - data,
    };
    
    // L4 헤더 파싱 및 프로토콜별 처리
    __u8 tcp_flags = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
            
        key.src_port = bpf_ntohs(tcp->source);
        key.dst_port = bpf_ntohs(tcp->dest);
        
        // TCP 플래그 추출
        tcp_flags = (tcp->syn << 5) | (tcp->ack << 4) | 
                   (tcp->fin << 3) | (tcp->rst << 2) | 
                   (tcp->psh << 1) | tcp->urg;
        key.tcp_flags = tcp_flags;
        
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
            
        key.src_port = bpf_ntohs(udp->source);
        key.dst_port = bpf_ntohs(udp->dest);
    }
    
    // 필터 맵에서 룰 조회
    struct filter_value *value = bpf_map_lookup_elem(&filter_map, &key);
    if (value) {
        // 타임스탬프 및 카운터 업데이트
        __u64 now = bpf_ktime_get_ns();
        value->timestamp = now;
        __sync_fetch_and_add(&value->packet_count, 1);
        __sync_fetch_and_add(&value->byte_count, key.pkt_length);
        
        // 만료 검사
        if (value->expire_seconds > 0) {
            __u64 age_ns = now - value->timestamp;
            __u64 expire_ns = (__u64)value->expire_seconds * 1000000000ULL;
            if (age_ns > expire_ns) {
                // 만료된 규칙은 무시
                return XDP_PASS;
            }
        }
        
        // 속도 제한 적용
        if (value->rate_limit > 0) {
            // 실제 구현에서는 토큰 버킷 알고리즘 적용
            // 간소화를 위해 생략
        }
        
        // 액션 적용
        switch (value->action) {
            case 1: // DROP
                return XDP_DROP;
                
            case 2: // REDIRECT
                return bpf_redirect(value->redirect_ifindex, 0);
                
            case 3: // COUNT (통계만 수집)
                return XDP_PASS;
                
            default: // PASS
                return XDP_PASS;
        }
    }
    
    // 기본적으로 패킷 통과
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
