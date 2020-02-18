/*
 *  Copyright (C) 2016-2020 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __LIB_IPV4__
#define __LIB_IPV4__

#include <linux/ip.h>

#include "dbg.h"

#if defined IPV4_FRAGMENTS && defined HAVE_LRU_MAP_TYPE
struct ipv4_frag_id {
	__be32	daddr;
	__be32	saddr;
	__be16	id;		/* L4 datagram identifier */
	__u8	proto;
} __attribute__((packed));

struct ipv4_frag_l4ports {
	__be16	dport;
	__be16	sport;
} __attribute__((packed));

struct bpf_elf_map __section_maps IPV4_FRAG_DATAGRAMS_MAP = {
	.type           = BPF_MAP_TYPE_LRU_HASH,
	.size_key	= sizeof(struct ipv4_frag_id),
	.size_value	= sizeof(struct ipv4_frag_l4ports),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES,
	.flags		= CONDITIONAL_PREALLOC,
};
#endif

static inline int ipv4_load_daddr(struct __ctx_buff *ctx, int off, __u32 *dst)
{
	return ctx_load_bytes(ctx, off + offsetof(struct iphdr, daddr), dst, 4);
}

static inline int ipv4_dec_ttl(struct __ctx_buff *ctx, int off, struct iphdr *ip4)
{
	__u8 new_ttl, ttl = ip4->ttl;

	if (ttl <= 1)
		return 1;

	new_ttl = ttl - 1;
	/* l3_csum_replace() takes at min 2 bytes, zero extended. */
	l3_csum_replace(ctx, off + offsetof(struct iphdr, check), ttl, new_ttl, 2);
	ctx_store_bytes(ctx, off + offsetof(struct iphdr, ttl), &new_ttl, sizeof(new_ttl), 0);

	return 0;
}

static inline int ipv4_hdrlen(struct iphdr *ip4)
{
	return ip4->ihl * 4;
}

static inline bool ipv4_is_fragment(struct iphdr *ip4)
{
	// The frag_off portion of the header consists of:
	//
	// +----+----+----+----------------------------------+
	// | RS | DF | MF | ...13 bits of fragment offset... |
	// +----+----+----+----------------------------------+
	//
	// If "More fragments" or the offset is nonzero, then this is an IP
	// fragment. The evil bit must be set to 0 (RFC791, RFC3514).
	return ip4->frag_off & bpf_htons(0xBFFF);
}

#if defined IPV4_FRAGMENTS && defined HAVE_LRU_MAP_TYPE
static inline bool ipv4_is_not_first_fragment(const struct iphdr *ip4)
{
	/* Ignore "More fragments" bit to catch all fragments but the first */
	return ip4->frag_off & bpf_htons(0x9FFF);
}

static inline int ipv4_frag_get_l4ports(const struct ipv4_frag_id *frag_id,
					struct ipv4_frag_l4ports *ports)
{
	struct ipv4_frag_l4ports *tmp;

	tmp = map_lookup_elem(&IPV4_FRAG_DATAGRAMS_MAP, &frag_id);
	if (!tmp)
		return -1;

	/* Do not make ports a pointer to map data, copy from map */
	memcpy(ports, tmp, sizeof(*ports));
	return 0;
}

static inline int ipv4_frag_register_datagram(struct __ctx_buff *ctx,
					      int l4_off,
					      const struct ipv4_frag_id *frag_id,
					      struct ipv4_frag_l4ports *ports)
{
	int ret;

	ret = ctx_load_bytes(ctx, l4_off, ports, 4);
	if (ret < 0)
		return ret;

	map_update_elem(&IPV4_FRAG_DATAGRAMS_MAP, frag_id, ports, BPF_ANY);
	/* Do not return an error if map update failed, as nothing prevents us
	 * to process the current packet normally */
	return 0;
}

static inline int ipv4_handle_fragment(struct __ctx_buff *ctx,
				       const struct iphdr *ip4, int l4_off,
				       struct ipv4_frag_l4ports *ports)
{
	struct ipv4_frag_id frag_id = {
		.daddr = ip4->daddr,
		.saddr = ip4->saddr,
		.id = ip4->id,
		.proto = ip4->protocol,
	};

	if (likely(ipv4_is_not_first_fragment(ip4)))
		return ipv4_frag_get_l4ports(&frag_id, ports);
	else
		/* First logical fragment for this datagram (not necessarily the
		 * first we receive). Fragment has L4 header, we can retrieve L4
		 * ports and create an entry in datagrams map. */
		return ipv4_frag_register_datagram(ctx, l4_off, &frag_id,
						   ports);
}
#endif

#endif /* __LIB_IPV4__ */
