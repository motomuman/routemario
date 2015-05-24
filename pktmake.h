#ifndef PKTMAKE_H
#define PKTMAKE_H

#include <rte_ether.h>
#include <stdint.h>
#include<rte_arp.h>
#include<rte_icmp.h>
#include<rte_ip.h>

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
//type
//#define IP_ICMP_ECHO_REPLY   0
//#define IP_ICMP_ECHO_REQUEST 8
#define IP_ICMP_DESTINATION_UNREACHABLE 3
#define IP_ICMP_TIME_EXCEEDED 11
//code
#define IP_ICMP_NETWORK_UNREACHABLE 0
#define IP_ICMP_HOST_UNREACHABLE 1

#define IP_NEXT_PROT_ICMP 1


struct icmp_ttl_data {
	struct ipv4_hdr icmp_ipv4; /* ICMP packet sequence number. */
	uint8_t icmp_data_8b; /* ICMP packet sequence number. */
} __attribute__((__packed__));

struct icmp_unreachable {
	uint8_t  icmp_type;   /* ICMP packet type. */
	uint8_t  icmp_code;   /* ICMP packet code. */
	uint16_t icmp_cksum;  /* ICMP packet checksum. */
	uint8_t  icmp_unuse;   /* ICMP packet code. */
	uint8_t icmp_len;  /* ICMP packet identifier. */
	uint16_t icmp_next_mtu; /* ICMP packet sequence number. */
} __attribute__((__packed__));


void set_eth_header(struct ether_hdr *eth_hdr, struct ether_addr *src_mac, struct ether_addr *dst_mac, uint16_t ether_type, unsigned broadcast);
void set_arp_header(struct arp_hdr *arp_hdr, struct ether_addr *src_mac, struct ether_addr *dst_mac, uint32_t src_ip, uint32_t dst_ip, uint32_t opcode);
void set_icmp_header(struct icmp_hdr *icmp_hdr, uint8_t icmp_type, uint8_t icmp_code,  uint16_t icmp_ident, uint16_t icmp_seq_nb);
void set_ipv4_header(struct ipv4_hdr *ip_hdr, uint32_t src_addr, uint32_t dst_addr, uint16_t next_proto_id, uint16_t pkt_len);
#endif
