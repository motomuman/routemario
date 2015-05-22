
#include"pktmake.h"

void set_eth_header(struct ether_hdr *eth_hdr, struct ether_addr *src_mac, struct ether_addr *dst_mac, uint16_t ether_type, unsigned broadcast) {
  if(broadcast){
    eth_hdr->d_addr.addr_bytes[0] = 0xff;
    eth_hdr->d_addr.addr_bytes[1] = 0xff;
    eth_hdr->d_addr.addr_bytes[2] = 0xff;
    eth_hdr->d_addr.addr_bytes[3] = 0xff;
    eth_hdr->d_addr.addr_bytes[4] = 0xff;
    eth_hdr->d_addr.addr_bytes[5] = 0xff;
  }else{
  ether_addr_copy(dst_mac, &eth_hdr->d_addr);
  }
  ether_addr_copy(src_mac, &eth_hdr->s_addr);
  eth_hdr->ether_type = rte_cpu_to_be_16(ether_type);
}



void set_arp_header(struct arp_hdr *arp_hdr, struct ether_addr *src_mac, struct ether_addr *dst_mac, uint32_t src_ip, uint32_t dst_ip, uint32_t opcode) {
  printf("debug10\n");
  printf("arp_hdr %d\n", ARP_HRD_ETHER);
  arp_hdr->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
  arp_hdr->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
  arp_hdr->arp_hln = ETHER_ADDR_LEN;
  arp_hdr->arp_pln = sizeof(uint32_t);
  arp_hdr->arp_op = rte_cpu_to_be_16(opcode);
  ether_addr_copy(src_mac, &arp_hdr->arp_data.arp_sha);
  arp_hdr->arp_data.arp_sip = src_ip;
  printf("debughoge\n");
  if(opcode == ARP_OP_REQUEST){
    arp_hdr->arp_data.arp_tha.addr_bytes[0] = 0xff;
    arp_hdr->arp_data.arp_tha.addr_bytes[1] = 0xff;
    arp_hdr->arp_data.arp_tha.addr_bytes[2] = 0xff;
    arp_hdr->arp_data.arp_tha.addr_bytes[3] = 0xff;
    arp_hdr->arp_data.arp_tha.addr_bytes[4] = 0xff;
    arp_hdr->arp_data.arp_tha.addr_bytes[5] = 0xff;
  }else{
  ether_addr_copy(dst_mac, &arp_hdr->arp_data.arp_tha);
  }
  printf("debugfuga\n");
  arp_hdr->arp_data.arp_tip = dst_ip;
}


void set_icmp_header(struct icmp_hdr *icmp_hdr, uint8_t icmp_type, uint8_t icmp_code, 
uint16_t icmp_cksum, uint16_t icmp_ident, uint16_t icmp_seq_nb){
icmp_hdr->icmp_type = icmp_type;
icmp_hdr->icmp_code = icmp_code; 
icmp_hdr->icmp_cksum = icmp_cksum; 
icmp_hdr->icmp_ident = icmp_ident; 
icmp_hdr->icmp_seq_nb = icmp_seq_nb;
}

void set_icmp_unreachable(struct icmp_unreachable *icmp_hdr, uint8_t icmp_type, uint8_t icmp_code, 
uint16_t icmp_cksum, uint8_t icmp_len, uint16_t icmp_next_mtu){
icmp_hdr->icmp_type = icmp_type;
icmp_hdr->icmp_code = icmp_code; 
icmp_hdr->icmp_cksum = icmp_cksum; 
icmp_hdr->icmp_len = icmp_len; 
icmp_hdr->icmp_next_mtu = icmp_next_mtu;
}

void set_ipv4_header(struct ipv4_hdr *ip_hdr, uint32_t src_addr, uint32_t dst_addr, uint16_t next_proto_id, uint16_t pkt_len)
{
	uint16_t *ptr16;
	uint32_t ip_cksum;

	/*
	 * Initialize IP header.
	 */
	//pkt_len = (uint16_t) (sizeof(struct icmp_hdr) +sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));

	ip_hdr->version_ihl   = IP_VHL_DEF;
	ip_hdr->type_of_service   = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live   = IP_DEFTTL;
	ip_hdr->next_proto_id = next_proto_id;
	ip_hdr->packet_id = 0;
	ip_hdr->total_length   = rte_cpu_to_be_16(pkt_len);
	ip_hdr->src_addr = rte_cpu_to_be_32(src_addr);
	ip_hdr->dst_addr = rte_cpu_to_be_32(dst_addr);

	/*
	 * Compute IP header checksum.
	 */
	ptr16 = (uint16_t *)ip_hdr;
	ip_cksum = 0;
	ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
	ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
	ip_cksum += ptr16[4];
	ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
	ip_cksum += ptr16[8]; ip_cksum += ptr16[9];

	/*
	 * Reduce 32 bit checksum to 16 bits and complement it.
	 */
	ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
		(ip_cksum & 0x0000FFFF);
	ip_cksum %= 65536;
	ip_cksum = (~ip_cksum) & 0x0000FFFF;
	if (ip_cksum == 0)
		ip_cksum = 0xFFFF;
	ip_hdr->hdr_checksum = (uint16_t) ip_cksum;
}
