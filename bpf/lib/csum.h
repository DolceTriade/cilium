/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_CSUM_H_
#define __LIB_CSUM_H_

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include <linux/sctp.h>
#include "crc32c.h"

#define TCP_CSUM_OFF (offsetof(struct tcphdr, check))
#define UDP_CSUM_OFF (offsetof(struct udphdr, check))
#define SCTP_CSUM_OFF 8

struct csum_offset {
	__u16 offset;
	__u16 flags;
	__u8 proto;
};

/**
 * Determins the L4 checksum field offset and required flags
 * @arg nexthdr	L3 nextheader field
 * @arg off	Pointer to uninitialied struct csum_offset struct
 *
 * Sets off.offset to offset from start of L4 header to L4 checksum field
 * and off.flags to the required flags, namely BPF_F_MARK_MANGLED_0 for UDP.
 * For unknown L4 protocols or L4 protocols which do not have a checksum
 * field, off is initialied to 0.
 */
static __always_inline void csum_l4_offset_and_flags(__u8 nexthdr,
						     struct csum_offset *off)
{
	switch (nexthdr) {
	case IPPROTO_TCP:
		off->offset = TCP_CSUM_OFF;
		off->proto = IPPROTO_TCP;
		break;

	case IPPROTO_UDP:
		off->offset = UDP_CSUM_OFF;
		off->flags = BPF_F_MARK_MANGLED_0;
		off->proto = IPPROTO_UDP;
		break;

	case IPPROTO_SCTP:
		off->offset = SCTP_CSUM_OFF;
		off->proto = IPPROTO_SCTP;
		break;

	case IPPROTO_ICMPV6:
		off->offset = offsetof(struct icmp6hdr, icmp6_cksum);
		off->proto = IPPROTO_ICMPV6;
		break;

	case IPPROTO_ICMP:
		off->proto = IPPROTO_ICMP;
		break;
	}
}

/**
 * Helper to change L4 checksum
 * @arg ctx	Packet
 * @arg l4_off	Offset to L4 header
 * @arg csum	Pointer to csum_offset as extracted by csum_l4_offset_and_flags()
 * @arg from	From value or 0 if to contains csum diff
 * @arg to	To value or a csum diff
 * @arg flags	Additional flags to be passed to l4_csum_replace()
 */
static __always_inline int csum_l4_replace(struct __ctx_buff *ctx, __u64 l4_off,
					   const struct csum_offset *csum,
					   __be32 from, __be32 to, int flags)
{
	__u32 sctp_csum = 0;
	__u32 size = 0;
	__u8* data = NULL;
	__u8* data_end = NULL;
	if (csum->proto != IPPROTO_SCTP) {
		return l4_csum_replace(ctx, l4_off + csum->offset, from, to, flags | csum->flags);
	}
	if (l4_off > 0xff) return 0;
	data = (__u8*)(ctx_data(ctx));
	data_end = (__u8*)ctx_data_end(ctx);
	size = data_end - data;
	if (size < sizeof(struct sctphdr) || size > 9000) return 0;
	data += l4_off;
	if (data > data_end) return 0;
	sctp_csum = crc32c(data, ctx_data_end(ctx));
	return ctx_store_bytes(ctx, l4_off + csum->offset, &sctp_csum, sizeof(sctp_csum), 0);
 }

#endif /* __LB_H_ */
