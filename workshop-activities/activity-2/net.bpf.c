#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// This struct defined by XDP holds information about the packet
//
// struct xdp_md {
//   __u32 data;
//   __u32 data_end;
//   __u32 data_meta;
//   /* Below access go through struct xdp_rxq_info */ __u32
//       ingress_ifindex;  /* rxq->dev->ifindex */
//   __u32 rx_queue_index; /* rxq->queue_index */
//   __u32 egress_ifindex; /* txq->dev->ifindex */
// };
//
//
//
//
//
// This struct defined by the kernel stores the Ethernet header
//
// struct ethhdr {
// unsigned char h_dest[ETH_ALEN];   /* destination eth addr	*/
// unsigned char h_source[ETH_ALEN]; /* source ether addr	*/
// __be16 h_proto;                   /* packet type ID field	*/
// }
// __attribute__((packed));
//
// Here, 'be' refers to the Big-endian byte order
//
//
//
//
// This struct defined by the kernel stores the IP header
//
// struct iphdr {
//
// #if defined(__LITTLE_ENDIAN_BITFIELD)
// __u8 ihl : 4, version : 4;
//
// #elif defined(__BIG_ENDIAN_BITFIELD)
// __u8 version : 4, ihl : 4;
//
// #else
// #error "Please fix <asm/byteorder.h>"
// #endif
//
// __u8 tos;
// __be16 tot_len;
// __be16 id;
// __be16 frag_off;
// __u8 ttl;
// __u8 protocol;
// __sum16 check;
//
// __struct_group(/* no tag */, addrs, /* no attrs */,
//                __be32 saddr;
//                __be32 daddr;);
// /*The options start here. */
// };
//

// 0x0800 indicates that the packet is an IPv4 packet
#define ETH_P_IP 0x0800

// Converting the IP Address to the unsigned int format to filter out Lima VM
// network packets
#define IP_ADDRESS(x) (unsigned int)(192 + (168 << 8) + (5 << 16) + (x << 24))

SEC("xdp")
int trace_net(struct xdp_md *ctx) {
  // The casting to long before void* is done to ensure
  // compatibility between 32 and 64-bit systems
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth_hdr = data;
  // This check to verify that the ethernet header is contained within the
  // network packet is necessary to pass the eBPF verifier
  if (data + sizeof(struct ethhdr) > data_end)
    return XDP_PASS;

  // bpf_ntohs converts the network packet's byte order type to
  // the host byte order type
  if (bpf_ntohs(eth_hdr->h_proto) == ETH_P_IP) {

    // This check to verify that the IP header is contained within the
    // network packet is necessary to pass the eBPF verifier
    struct iphdr *ip_hdr = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
      return XDP_PASS;

    // Packet protocol values
    // 1 = ICMP
    // 6 = TCP
    // 17 = UDP

    // 192.168.5.2 is the loopback address of the host set by Lima VM
    // The packets from the host to the VM clutter the trace log, hence we do
    // not print them
    if (ip_hdr->saddr != IP_ADDRESS(2)) {

      // printk format specifier for IP addresses:
      // https://www.kernel.org/doc/html/v4.20/core-api/printk-formats.html
      bpf_printk("Src: %pI4, Dst: %pI4, Proto: %d", &ip_hdr->saddr,
                 &ip_hdr->daddr, ip_hdr->protocol);
    }
  }

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
