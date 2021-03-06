#include"pktmake.h"
#include"env.h"

void set_eth_header(struct ether_hdr *eth_hdr, struct ether_addr *src_mac, struct ether_addr *dst_mac, uint16_t ether_type, unsigned broadcast) {
  if(broadcast){
    memset(&eth_hdr->d_addr, 0xff, 6);
  }else{
    ether_addr_copy(dst_mac, &eth_hdr->d_addr);
  }
  ether_addr_copy(src_mac, &eth_hdr->s_addr);
  eth_hdr->ether_type = rte_cpu_to_be_16(ether_type);
}

void set_arp_header(struct arp_hdr *arp_hdr, struct ether_addr *src_mac, struct ether_addr *dst_mac, uint32_t src_ip, uint32_t dst_ip, uint32_t opcode) {
  arp_hdr->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
  arp_hdr->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
  arp_hdr->arp_hln = ETHER_ADDR_LEN;
  arp_hdr->arp_pln = sizeof(uint32_t);
  arp_hdr->arp_op = rte_cpu_to_be_16(opcode);
  ether_addr_copy(src_mac, &arp_hdr->arp_data.arp_sha);
  arp_hdr->arp_data.arp_sip = src_ip;
  if(opcode == ARP_OP_REQUEST){
    memset(&arp_hdr->arp_data.arp_tha, 0xff, 6);
  }else{
    ether_addr_copy(dst_mac, &arp_hdr->arp_data.arp_tha);
  }
  arp_hdr->arp_data.arp_tip = dst_ip;
}

void set_icmp_header(struct icmp_hdr *icmp_hdr, uint8_t icmp_type, uint8_t icmp_code, 
    uint16_t icmp_ident, uint16_t icmp_seq_nb){
  icmp_hdr->icmp_type = icmp_type;
  icmp_hdr->icmp_code = icmp_code; 
  icmp_hdr->icmp_cksum = 0; 
  icmp_hdr->icmp_ident = icmp_ident; 
  icmp_hdr->icmp_seq_nb = icmp_seq_nb;
}

void set_icmp_unreachable(struct icmp_unreachable *icmp_hdr, uint8_t icmp_type, uint8_t icmp_code, 
     uint8_t icmp_len, uint16_t icmp_next_mtu){
  icmp_hdr->icmp_type = icmp_type;
  icmp_hdr->icmp_code = icmp_code; 
  icmp_hdr->icmp_len = icmp_len; 
  icmp_hdr->icmp_next_mtu = icmp_next_mtu;
  icmp_hdr->icmp_cksum = cksum(icmp_hdr, icmp_len, 0);
}

void set_ipv4_header(struct ipv4_hdr *ip_hdr, uint32_t src_addr, uint32_t dst_addr, uint16_t next_proto_id, uint16_t pkt_len)
{
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

  ip_hdr->hdr_checksum = 0;
  ip_hdr->hdr_checksum = cksum(ip_hdr,sizeof(struct ipv4_hdr), 0);
}


void make_ttl_expkt(struct rte_mbuf *m, struct rte_mbuf *pkt, uint32_t myip){
          struct ether_hdr *eth_org;
          struct ipv4_hdr *ip_org;
          eth_org = rte_pktmbuf_mtod(m, struct ether_hdr *);
          ip_org = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr));
          
          struct ether_hdr *eth_pkt;
          struct ipv4_hdr *ip_pkt;
          struct icmp_hdr *icmp_pkt;
          eth_pkt = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
          ip_pkt = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr));
          icmp_pkt = (struct icmp_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr));

          set_eth_header(eth_pkt,  &eth_org->d_addr, &eth_org->s_addr, ETHER_TYPE_IPv4, 0);
          set_ipv4_header(ip_pkt, rte_bswap32(myip), rte_bswap32(ip_org->src_addr), IP_NEXT_PROT_ICMP, 2*(int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr)+8); 
          set_icmp_header(icmp_pkt, IP_ICMP_TIME_EXCEEDED, 0, 0, 0);
          
          struct ipv4_hdr *icmp_ip_header;
          icmp_ip_header = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr) + sizeof(struct icmp_hdr));
          *icmp_ip_header = *ip_org;
          
          uint64_t *icmp_data;
          uint64_t *icmp_data_tmp;
          icmp_data_tmp = (uint64_t *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr));
          icmp_data = (uint64_t *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr)+ 2*sizeof(struct ipv4_hdr) + sizeof(struct icmp_hdr));
          *icmp_data = *icmp_data_tmp;
          
          (pkt)->pkt_len = (int)sizeof(struct ether_hdr) + 2*(int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr)+8;
          (pkt)->data_len = (int)sizeof(struct ether_hdr) + 2*(int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr)+8;
          
          uint16_t tlen;
          tlen  = pkt->pkt_len - (sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
          icmp_pkt->icmp_cksum = cksum(icmp_pkt, tlen, 0);
}


void *make_unreach_pkt(struct rte_mbuf *m, struct rte_mbuf *pkt, uint32_t myip){
  struct ether_hdr *eth_org;
  struct ipv4_hdr *ip_org;
  eth_org = rte_pktmbuf_mtod(m, struct ether_hdr *);
  ip_org = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr));

  struct ether_hdr *eth_pkt;
  struct ipv4_hdr *ip_pkt;
  struct icmp_unreachable *icmp_pkt;
  eth_pkt = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
  ip_pkt = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr));
  icmp_pkt = (struct icmp_unreachable *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr));
  set_eth_header(eth_pkt, &eth_org->d_addr, &eth_org->s_addr, ETHER_TYPE_IPv4, 0);
  set_ipv4_header(ip_pkt, rte_bswap32(myip), rte_bswap32(ip_org->src_addr), IP_NEXT_PROT_ICMP,
      2*(int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr)+8); 

  struct ipv4_hdr *icmp_ip_header;
  icmp_ip_header = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr) + sizeof(struct icmp_hdr));
  * icmp_ip_header = * ip_org;
  uint64_t *icmp_data;
  uint64_t *icmp_data_tmp;
  icmp_data_tmp = (uint64_t *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr));
  icmp_data = (uint64_t *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr)+ 2*sizeof(struct ipv4_hdr) + sizeof(struct icmp_hdr));
  *icmp_data = *icmp_data_tmp;

  (pkt)->pkt_len = (int)sizeof(struct ether_hdr) + 2*(int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr)+8;
  (pkt)->data_len = (int)sizeof(struct ether_hdr) + 2*(int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr)+8;
  uint16_t tlen;
  tlen  = pkt->pkt_len - (sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
  set_icmp_unreachable(icmp_pkt, IP_ICMP_DESTINATION_UNREACHABLE, IP_ICMP_NETWORK_UNREACHABLE,  tlen, 777);
}

