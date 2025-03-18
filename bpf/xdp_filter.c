/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "headers/common.h"

// 필터 맵 키 구조체
struct filter_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  flags;
    __u16 pad;
} __attribute__((packed));

// 필터 맵 값 구조체
struct filter_value {
    __u32 action;         // 0: PASS, 1: DROP, 2: REDIRECT
    __u32 redirect_ifindex;
    __u32 priority;
    __u64 packet_count;
    __u64 byte_count;
    __u64 last_seen
