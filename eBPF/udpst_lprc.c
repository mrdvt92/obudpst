/*
 * Copyright (c) 2026, Len Ciavattone
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * UDP Speed Test - udpst_lprc.c (eBPF)
 *
 * This file contains an eBPF/XDP program to perform Load PDU Receive
 * Coalescing (LPRC) as a performance boost for received udpst traffic.
 *
 * Author                  Date          Comments
 * --------------------    ----------    ----------------------------------
 * Len Ciavattone          07/25/2026    Created
 * Len Ciavattone          08/25/2026    Add version constant
 *
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "../udpst_protocol.h"

//
// Standard Ethernet and IP values that need to be reproduced locally
// --------------------------------------------------------------------------------------------------
//
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1FFF
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif

//
// Local constants
// --------------------------------------------------------------------------------------------------
const char version[] = "v1.0.0"; // Read from BPF map named .rodata (via bpftool)
//
#define FLOW_COUNT 8192
//
#define LOADHDR_SIZE   sizeof(struct loadHdr)
#define LOADHDR_WINDOW 64 // Must be power of 2
#define LOADHDR_MASK   (LOADHDR_WINDOW - 1)
//
#define LPRC_MTU      1500
#define LPRC_FRAME    (LPRC_MTU + sizeof(struct ethhdr))
#define FLUSH_THRESH1 ((LPRC_MTU - sizeof(struct ipv6hdr) - sizeof(struct udphdr)) / LPRC_RXEVENT_SIZE)
#define FLUSH_THRESH2 ((LOADHDR_WINDOW * 3) / 4)
//
#define IPG_THRESH  45                     // Interpacket gap threshold (ms)
#define MAXIMUM_IPG (IPG_THRESH * 1000000) // Maximum IPG in nanoseconds
//
#define IPV4_UDP_CSUM false // Insert UDP checksum with IPv4, see README (true|false)
#define IPV6_UDP_CSUM false // Insert UDP checksum with IPv6, see README (true|false)

//
// Required data structures
// --------------------------------------------------------------------------------------------------
//
// Unified 4-tuple key for IPv4 and IPv6 UDP flows
//
struct flow_key {
        __be32 src_ip[4]; // 16 bytes: Fits IPv6, or IPv4 in index 0
        __be32 dst_ip[4];
        __be16 src_port;
        __be16 dst_port;
};
//
// Define the Load PDU buffer structures
//
struct load_pdu {
        __u64 timestamp_ns;
        __u32 tos_tc;
        __u8 hdr[LOADHDR_SIZE];
};
struct flow_buffer {
        __u32 start_index;
        __u32 next_index;
        __u32 flush_thresh;
        __u32 max_payload;
        __u64 last_arrival_ns;
        struct load_pdu window[LOADHDR_WINDOW];
};
//
// LRU Hash Map for tracking active UDP flows
//
struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, FLOW_COUNT);
        __type(key, struct flow_key);
        __type(value, struct flow_buffer);
} flow_map SEC(".maps");
//
// Scratchpad map to safely bypass the 512-byte eBPF stack limit
//
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, struct flow_buffer);
} scratchpad_map SEC(".maps");
//
// Consolidation structure for all required data fields
//
struct data_fields {
        // Buffer
        void *data;
        void *data_end;

        // Ethernet
        struct ethhdr *eth;

        // IP
        struct iphdr *ip;
        struct ipv6hdr *ipv6;
        __u32 tos_tc;

        // UDP
        struct udphdr *udp;

        // Payload
        void *payload;
        __u32 payload_len;

        // Flow key
        struct flow_key key;
};

//
// Support functions
// --------------------------------------------------------------------------------------------------
//
// Replace/update existing checksum when only a 16-bit value has changed
//
static __always_inline void csum_replace(__be16 *sum, __be16 old, __be16 new) {
        //
        // Accumulate 1s complement
        //
        __u32 new_sum = ~*sum & 0xFFFF;
        new_sum += ~old & 0xFFFF;
        new_sum += new;

        //
        // Fold the 32-bit value down to 16-bits
        //
        new_sum = (new_sum & 0xFFFF) + (new_sum >> 16);
        new_sum = (new_sum & 0xFFFF) + (new_sum >> 16);

        //
        // Negate back to checksum form
        //
        *sum = (__be16) ~new_sum;
}
//
// Calculate a full checksum when the bulk of the data has changed
//
static __always_inline __u16 csum_fold(__u32 csum) {

        csum = (csum & 0xffff) + (csum >> 16);
        csum = (csum & 0xffff) + (csum >> 16);

        return (__u16) ~csum;
}
static __always_inline __u16 update_udp_csum(struct data_fields *df) {
        //
        // Clear checksum field to start
        //
        df->udp->check = 0;

        //
        // Process pseudo header
        //
        __wsum csum = 0;
        if (df->ip) {
                csum = bpf_csum_diff(NULL, 0, &df->ip->saddr, sizeof(df->ip->saddr) + sizeof(df->ip->daddr), csum);
        } else if (df->ipv6) {
                csum = bpf_csum_diff(NULL, 0, (__be32 *) &df->ipv6->saddr, sizeof(df->ipv6->saddr) + sizeof(df->ipv6->daddr), csum);
        } else {
                return 0;
        }
        __u32 tmp = bpf_htonl(IPPROTO_UDP);
        csum      = bpf_csum_diff(NULL, 0, &tmp, sizeof(tmp), csum);
        tmp       = (__u32) df->udp->len;
        csum      = bpf_csum_diff(NULL, 0, &tmp, sizeof(tmp), csum);

        //
        // Process UDP datagram in largest chunks possible (512 max, 4 min, and multiple of 4)
        // ...several chunk sizes are optimized for common udpst datagrams of 1480, 1460, 1230, and 1210 bytes
        //
        __u8 *ptr       = (__u8 *) df->udp;
        __u32 remaining = (__u32) bpf_ntohs(df->udp->len);
        if (remaining > LPRC_MTU - sizeof(struct iphdr)) // Largest possible size
                return 0;
        __u32 chunk[]   = {512, 456, 436, 204, 184, 128, 64, 32, 16, 8, 4};
        __u32 chunk_cnt = sizeof(chunk) / sizeof(__u32);
        for (__u32 i = 0; i < chunk_cnt; i++) {
                while (remaining >= chunk[i]) {
                        if ((void *) ptr + chunk[i] > df->data_end)
                                return 0;
                        csum = bpf_csum_diff(NULL, 0, (__be32 *) ptr, chunk[i], csum);

                        ptr += chunk[i];
                        remaining -= chunk[i];
                }
                if (remaining == 0)
                        break;
        }
        //
        // Process final (1-3) bytes
        //
        if (remaining > 0) {
                __u8 final[4] = {0, 0, 0, 0};
                for (__u32 i = 0; i < 3; i++) {
                        if ((void *) ptr < df->data_end)
                                final[i] = *ptr++;
                        remaining--;
                }
                csum = bpf_csum_diff(NULL, 0, (__be32 *) final, sizeof(final), csum);
        }

        //
        // Fold checksum and return
        //
        __u16 final_csum = csum_fold(csum);
        if (final_csum == 0)
                final_csum = 0xffff;
        return final_csum;
}
//
// Process network data buffer into respective data fields
//
static __always_inline __s32 process_data(struct xdp_md *ctx, struct data_fields *df, bool init_key, __s32 size_delta) {
        df->data     = (void *) (long) ctx->data;
        df->data_end = (void *) (long) ctx->data_end;

        //
        // Obtain Ethernet header
        //
        df->eth = df->data;
        if ((void *) (df->eth + 1) > df->data_end)
                return -1;

        //
        // Initialize data fields
        //
        df->ip          = NULL;
        df->ipv6        = NULL;
        df->tos_tc      = 0;
        df->udp         = NULL;
        df->payload     = NULL;
        df->payload_len = 0;

        //
        // Validate and parse IP header for ToS/Traffic Class, addresses, and UDP header
        //
        if (df->eth->h_proto == bpf_htons(ETH_P_IP)) {
                df->ip = (void *) (df->eth + 1);
                if ((void *) (df->ip + 1) > df->data_end)
                        return -1;
                if (df->ip->frag_off & bpf_htons(IP_MF | IP_OFFMASK))
                        return -1; // Blindly pass all packet fragments
                if (df->ip->protocol != IPPROTO_UDP)
                        return -1; // Blindly pass all non-UDP protocols

                //
                // Parse IPv4 header
                //
                df->tos_tc = df->ip->tos;
                if (init_key) {
                        df->key.src_ip[0] = df->ip->saddr;
                        df->key.src_ip[1] = 0;
                        df->key.src_ip[2] = 0;
                        df->key.src_ip[3] = 0;
                        df->key.dst_ip[0] = df->ip->daddr;
                        df->key.dst_ip[1] = 0;
                        df->key.dst_ip[2] = 0;
                        df->key.dst_ip[3] = 0;
                }
                if (size_delta > 0) {
                        //
                        // Update IPv4 total length and IP checksum if needed
                        //
                        __u16 old_ip_len = df->ip->tot_len;
                        __u16 new_ip_len = bpf_htons(bpf_ntohs(old_ip_len) - size_delta);
                        df->ip->tot_len  = new_ip_len;
                        csum_replace(&df->ip->check, old_ip_len, new_ip_len);
                }
                df->udp = (void *) df->ip + (df->ip->ihl * 4);

        } else if (df->eth->h_proto == bpf_htons(ETH_P_IPV6)) {
                df->ipv6 = (void *) (df->eth + 1);
                if ((void *) (df->ipv6 + 1) > df->data_end)
                        return -1;
                if (df->ipv6->nexthdr == IPPROTO_FRAGMENT)
                        return -1; // Blindly pass all packet fragments
                if (df->ipv6->nexthdr != IPPROTO_UDP)
                        return -1; // Blindly pass all non-UDP protocols

                //
                // Parse IPv6 header
                //
                df->tos_tc = (bpf_ntohl(*(__be32 *) df->ipv6) >> 20) & 0xFF;
                if (init_key) {
                        __builtin_memcpy(df->key.src_ip, &df->ipv6->saddr, 16);
                        __builtin_memcpy(df->key.dst_ip, &df->ipv6->daddr, 16);
                }
                if (size_delta > 0) {
                        //
                        // Update IPv6 payload length if needed
                        //
                        __u16 old_payload_len = df->ipv6->payload_len;
                        __u16 new_payload_len = bpf_htons(bpf_ntohs(old_payload_len) - size_delta);
                        df->ipv6->payload_len = new_payload_len;
                }
                df->udp = (void *) (df->ipv6 + 1);

        } else {
                return -1;
        }

        //
        // Obtain UDP payload and port numbers
        //
        if ((void *) (df->udp + 1) > df->data_end)
                return -1;
        if (size_delta > 0) {
                //
                // Update UDP length if needed
                //
                __u16 old_udp_len = df->udp->len;
                __u16 new_udp_len = bpf_htons(bpf_ntohs(old_udp_len) - size_delta);
                df->udp->len      = new_udp_len;
        }
        df->payload     = (void *) (df->udp + 1);
        df->payload_len = (__u32) bpf_ntohs(df->udp->len) - sizeof(struct udphdr);
        if (init_key) {
                df->key.src_port = df->udp->source;
                df->key.dst_port = df->udp->dest;
        }

        return 0;
}

//
// XDP ENTRY POINT
// --------------------------------------------------------------------------------------------------
// NOTE: SEC("xdp.frags") allows for jumbo frames that span multiple memory pages (i.e., complete
// jumbo frames). This does not involve or impact IP fragmented packets which would normally
// not require multiple memory pages. However, IP fragmentation is NOT supported with LPRC. And
// because all fragmented IP packets are blindly passed up the protocol stack, any received by
// udpst with LPRC active will result in test termination.
//
SEC("xdp.frags")
int udpst_lprc(struct xdp_md *ctx) {
        struct data_fields df;

        //
        // Process header data
        //
        if (process_data(ctx, &df, true, 0))
                return XDP_PASS;
        if (df.payload + LOADHDR_SIZE > df.data_end) // Absolute minimum size (covers Test Act. and Load PDU)
                return XDP_PASS;

        //
        // If Test Activation PDU, signal functionality via specialized PDU ID
        //
        if (df.payload_len == CHTA_SIZE_MVER || df.payload_len == CHTA_SIZE_CVER) {
                struct controlHdrTA *cHdrTA = (struct controlHdrTA *) df.payload;
                if (cHdrTA->pduId == bpf_htons(CHTA_ID)) {
                        //
                        // Only valid for receiving Load PDUs
                        //
                        if ((cHdrTA->cmdRequest == CHTA_CREQ_TESTACTUS && cHdrTA->cmdResponse == CHTA_CRSP_NONE) ||
                            (cHdrTA->cmdRequest == CHTA_CREQ_TESTACTDS && cHdrTA->cmdResponse == CHTA_CRSP_ACKOK)) {
                                //
                                // Modify ID to signal Load PDU Receive Coalescing (update UDP checksum)
                                //
                                __be16 new_id = bpf_htons(CHTA_ID_LPRC);
                                if (df.udp->check != 0) {
                                        csum_replace(&df.udp->check, (__be16) cHdrTA->pduId, new_id);
                                }
                                cHdrTA->pduId = new_id;
                        }
                        return XDP_PASS;
                }
        }

        //
        // Only process Load PDUs after this point
        //
        struct loadHdr *lHdr = (struct loadHdr *) df.payload;
        if (lHdr->pduId != bpf_htons(LOAD_ID))
                return XDP_PASS;

        //
        // Obtain current time (now) and init interpacket gap
        //
        __u64 now_ns = bpf_ktime_get_boot_ns(), ipg_ns = 0;

        //
        // Obtain (or initialize) flow buffer for this UDP flow
        //
        __u32 idx;
        bool update_flow_map    = false;
        struct flow_buffer *buf = bpf_map_lookup_elem(&flow_map, &df.key);
        if (buf) {
                ipg_ns = now_ns - buf->last_arrival_ns;
                //
                // FLOW EXISTS: Atomically grab (and increment) index and mask to appropriate size
                //
                idx = __sync_fetch_and_add(&buf->next_index, 1) & LOADHDR_MASK;
        } else {
                ipg_ns = 0;
                //
                // NEW FLOW: Build the initial buffer in the scratchpad and initialize index values
                //
                idx               = 0;
                __u32 scratch_key = 0;
                buf               = bpf_map_lookup_elem(&scratchpad_map, &scratch_key);
                if (!buf)
                        return XDP_PASS;
                buf->start_index  = 0;
                buf->next_index   = 1;
                buf->flush_thresh = 1; // Start flush threshold at minimum
                buf->max_payload  = 0;
                update_flow_map   = true; // Flow map requires updating
        }
        // NOTE: Flow map may require updating after this, use "proc_complete" exit point for completion
        // --------------------------------------------------------------------------------------------------
        // Drop Load PDU by default (unless used to pass up receive events)
        bool drop_pdu = true;

        //
        // Insert this Load PDU data in flow buffer window
        //
        buf->window[idx].timestamp_ns = now_ns;
        buf->window[idx].tos_tc       = df.tos_tc;
        __builtin_memcpy(buf->window[idx].hdr, df.payload, LOADHDR_SIZE);
        buf->last_arrival_ns = now_ns;

        //
        // Check if space available in this datagram for at least one receive event
        //
        if (df.payload_len < LPRC_RXEVENT_SIZE)
                goto proc_complete;

        //
        // Check if interpacket gap, count, and size limits support reuse of this Load PDU datagram for receive events
        //
        __u32 buf_size = buf->next_index - buf->start_index;
        if (ipg_ns < MAXIMUM_IPG) {
                //
                // Check if current flush threshold reached
                //
                if (buf_size < buf->flush_thresh) {
                        goto proc_complete;
                } else if (buf->flush_thresh < FLUSH_THRESH1) {
                        buf->flush_thresh *= 2; // Double flush threshold
                        if (buf->flush_thresh > FLUSH_THRESH1)
                                buf->flush_thresh = FLUSH_THRESH1; // Cap the maximum
                }

                //
                // Check if using maximum payload size so far (allow growth to second threshold)
                //
                if (df.payload_len < buf->max_payload && buf_size < FLUSH_THRESH2) {
                        goto proc_complete;
                }
        }

        //
        // Receive events can/should be passed up the protocol stack using this datagram
        // --------------------------------------------------------------------------------------------------
        // First, shrink frame/packet/datagram if larger than "traditional" MTU size (i.e., if jumbo frame)
        //
        // ...original Load PDU header retains actual payload size received
        //
        __s32 frame_len = bpf_xdp_get_buff_len(ctx);
        if (frame_len > (__s32) LPRC_FRAME) {
                __s32 size_delta = (__s32) LPRC_FRAME - frame_len;

                //
                // IMPORTANT: Calling bpf_xdp_adjust_tail() when using xdpdrv (native/driver mode) with veth
                // interfaces may cause system crashes. In these cases, using xdpgeneric works as expected.
                //
                if (bpf_xdp_adjust_tail(ctx, size_delta))
                        goto proc_complete;
                size_delta *= -1; // Convert to positive value

                //
                // Reprocess data fields and update headers
                //
                if (process_data(ctx, &df, false, size_delta))
                        goto proc_complete;
        }
        //
        // Update maximum payload size threshold if needed (done after possible shrink)
        //
        if (df.payload_len > buf->max_payload) {
                buf->max_payload = df.payload_len;
        }

        //
        // Second, insert as many receive events as will fit in this datagram payload (overwriting Load PDU)
        //
        __u32 payload_len       = df.payload_len;
        __u32 rx_event_count    = 0; // Used as sanity check for verifier
        struct lprcRxEvent *lRE = (struct lprcRxEvent *) df.payload;
        while (buf->start_index < buf->next_index && payload_len >= LPRC_RXEVENT_SIZE && rx_event_count++ < LOADHDR_WINDOW) {
                //
                // Obtain starting index of window
                //
                __u32 idx = __sync_fetch_and_add(&buf->start_index, 1) & LOADHDR_MASK;

                //
                // Insert event
                //
                if ((void *) (lRE + 1) > df.data_end)
                        break;
                lRE->pduId     = LPRC_ID;
                lRE->dscpEcn   = (__u8) buf->window[idx].tos_tc;
                lRE->statusVal = LPRC_STATUS_OK;
                lRE->lpduAge   = (__u32) (now_ns - buf->window[idx].timestamp_ns) & 0xFFFFFFFF;
                __builtin_memcpy((void *) &lRE->lHdr, buf->window[idx].hdr, LOADHDR_SIZE);

                //
                // Adjust remaining payload length and step to location of next receive event
                //
                payload_len -= LPRC_RXEVENT_SIZE;
                lRE++;
        }
        //
        // If there is room, clear trailing PDU ID bytes to mark the end
        //
        __u8 *ptr = (__u8 *) lRE;
        for (__u32 i = 0; i < 2; i++) {
                if ((void *) ptr < df.data_end)
                        *ptr++ = 0x00;
        }

        //
        // Third, if needed insert UDP checksum to cover new contents
        //
        __u16 csum;
        if (df.ip && !IPV4_UDP_CSUM) {
                df.udp->check = 0; // Indicate not in use (disabled)
                drop_pdu      = false;

        } else if (df.ipv6 && !IPV6_UDP_CSUM) {
                df.udp->check = 0xFFFF; // Must be non-zero even if CHECKSUM_UNNECESSARY
                drop_pdu      = false;

        } else if ((csum = update_udp_csum(&df)) != 0) {
                df.udp->check = csum; // Insert calculated checksum
                drop_pdu      = false;
        }
        // --------------------------------------------------------------------------------------------------

proc_complete:
        //
        // Update flow map if needed
        //
        if (update_flow_map) {
                bpf_map_update_elem(&flow_map, &df.key, buf, BPF_ANY);
        }

        //
        // Final determination for this datagram
        //
        if (drop_pdu) {
                return XDP_DROP;
        } else {
                return XDP_PASS;
        }
}
char _license[] SEC("license") = "GPL";
