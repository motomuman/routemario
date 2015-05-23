#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include<rte_ip.h>
#include<rte_hash.h>
#include<rte_icmp.h>
#include<rte_arp.h>

#include"arp_table.h"
#include"radix_tree.h"
#include"pktmake.h"
#include"tool.h"
#include"env.h"

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF   8192

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

//#define 32BIT_MASK        0xffffffff

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];



/* list of enabled ports */
//static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

static unsigned int l2fwd_rx_queue_per_lcore = 1;

uint8_t nb_lcores;
uint8_t node_id;

int find_port_fip(uint32_t ip){
  int i;
    for(i = 0; i <nb_ports; i++){
      if(ip==port_to_ip[i]){
        return i;
      }
    }
    return -1;
}


/*message buffer*/
struct mbuf_table {
	unsigned len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static const struct rte_eth_conf prt_conf = {
	.rxmode = {
    .mq_mode = ETH_MQ_RX_RSS,
    .max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
    .hw_vlan_filter = 0, /**< VLAN filtering disabled */
    .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
    .hw_strip_crc   = 0, /**< CRC stripped by hardware */
  },
  .rx_adv_conf = {
    .rss_conf = {
      .rss_key=NULL,
      .rss_hf = ETH_RSS_IP,
    },
  },
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

#define MAX_NB_CORE 128
struct rte_mempool * l2fwd_pktmbuf_pool[MAX_NB_CORE];

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx[MAX_NB_CORE];
	uint64_t rx[MAX_NB_CORE];
	uint64_t dropped[MAX_NB_CORE];
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

/* A tsc-based timer responsible for triggering statistics printout */
#define TIMER_MILLISECOND 2000000ULL /* around 1ms at 2 Ghz */
#define MAX_TIMER_PERIOD 86400 /* 1 day max */
static int64_t timer_period = 10 * TIMER_MILLISECOND * 1000; /* default period is 10 seconds */



uint32_t cksumUpdate( void * pBuf, int32_t size, uint32_t cksum )
{
    uint32_t       nWords;
    uint16_t     * pWd = (uint16_t *)pBuf;
    
    for( nWords = (size >> 5); nWords > 0; nWords-- )
    {
        cksum += *pWd++; cksum += *pWd++; cksum += *pWd++; cksum += *pWd++;
        cksum += *pWd++; cksum += *pWd++; cksum += *pWd++; cksum += *pWd++;
        cksum += *pWd++; cksum += *pWd++; cksum += *pWd++; cksum += *pWd++;
        cksum += *pWd++; cksum += *pWd++; cksum += *pWd++; cksum += *pWd++;
    }
    
    /* handle the odd number size */
    for(nWords = (size & 0x1f) >> 1; nWords > 0; nWords-- )
        cksum   += *pWd++;
        
    /* Handle the odd byte length */
    if (size & 1)
        cksum   += *pWd & htons(0xFF00);
        
    return cksum;
}





uint16_t cksumDone( uint32_t cksum )
{
    /* Fold at most twice */
    cksum = (cksum & 0xFFFF) + (cksum >> 16);
    cksum = (cksum & 0xFFFF) + (cksum >> 16);
    
    return ~((uint16_t)cksum);
}

uint16_t cksum( void * pBuf, int32_t size, uint32_t cksum )
{
    return cksumDone( cksumUpdate( pBuf, size, cksum) );
}


/* Print out statistics on packets dropped */
static void print_stats(void) {
  /*
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;
	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;
  int i;

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < nb_ports; portid++) {
    for(i = 0; i < nb_lcores; i++){
		printf("\nStatistics for port %u core %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
         i,
			   port_statistics[portid].tx[i],
			   port_statistics[portid].rx[i],
			   port_statistics[portid].dropped[i]);

		total_packets_dropped += port_statistics[portid].dropped[i];
		total_packets_tx += port_statistics[portid].tx[i];
		total_packets_rx += port_statistics[portid].rx[i];
    }
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");
  */
}





/* Send the burst of packets on an output interface */
static int l2fwd_send_burst(struct lcore_queue_conf *qconf, unsigned n, uint8_t port, unsigned lcore_id) {
	struct rte_mbuf **m_table;
	unsigned ret;
	unsigned queue_id = lcore_id;

	m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;
	ret = rte_eth_tx_burst(port, (uint16_t) queue_id, m_table, (uint16_t) n);
  port_statistics[port].tx[lcore_id] += ret;
  if (unlikely(ret < n)) {
    port_statistics[port].dropped[lcore_id] += (n - ret);
    do {
      rte_pktmbuf_free(m_table[ret]);
    } while (++ret < n);
  }
	return 0;
}

/* Enqueue packets for TX and prepare them to be sent */
static int TX_enqueue(struct rte_mbuf *m, uint8_t port) {
  unsigned lcore_id, len;
  struct lcore_queue_conf *qconf;
  lcore_id = rte_lcore_id();

  qconf = &lcore_queue_conf[lcore_id];
  len = qconf->tx_mbufs[port].len;
  qconf->tx_mbufs[port].m_table[len] = m;
  len++;

  /* enough pkts to be sent */
  if (unlikely(len == MAX_PKT_BURST)) {
    l2fwd_send_burst(qconf, MAX_PKT_BURST, port, lcore_id);
    len = 0;
  }

  qconf->tx_mbufs[port].len = len;
  return 0;
}


static void arp_handle_external(struct rte_mbuf *m, unsigned portid, struct ether_hdr *eth){
  struct arp_hdr *arp;
  arp = (struct arp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr));
  printf("ARP packet!!\n");
  if(rte_bswap16(arp->arp_op)== ARP_OP_REPLY){
    uint32_t newkey;
    unsigned ret;
    newkey = arp->arp_data.arp_sip;
    //
    printf("from arp add new key " );
    show_ip(newkey);
    printf("\n");
    //
    ret = rte_hash_add_key(mac_table_hash[portid],(void *) &newkey);
    mac_table[portid][ret] = arp->arp_data.arp_sha;;
    int i;
    for(i = 0; i < nb_ports; i++){
      if( i == node_id){
        continue;
      } 
      struct rte_mbuf *clonem= rte_pktmbuf_clone(m, m->pool); 
      TX_enqueue(clonem, i);
    }
    rte_pktmbuf_free(m);
    return;
  }else if(rte_bswap16(arp->arp_op) == ARP_OP_REQUEST){
    int ret = find_port_fip(arp->arp_data.arp_tip);
    if(ret >= 0){
      printf("To me arp REQUEST(i = %d)!!\n", ret);
      struct arp_hdr *arp_pkt;
      arp_pkt = (struct arp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) 
      + sizeof(struct ether_hdr));
      set_eth_header(eth, &l2fwd_ports_eth_addr[portid], &eth->s_addr, ETHER_TYPE_ARP, 0);
      set_arp_header(arp_pkt, &l2fwd_ports_eth_addr[portid], &eth->d_addr, port_to_ip[ret], arp->arp_data.arp_sip, ARP_OP_REPLY);
      printf("i = %d\n", ret );
      printf("IPIP \n");
      show_ip(port_to_ip[ret]);
      TX_enqueue(m, (uint8_t) portid);
    }else{
      rte_pktmbuf_free(m);
      return;
    }
  }else{
    printf("invalid arp op\n");
    rte_pktmbuf_free(m);
    return;
  }
}

static uint8_t is_broadcast(struct ether_addr ad){
  return ad.addr_bytes[0] == 0xff && ad.addr_bytes[1] == 0xff && ad.addr_bytes[2] == 0xff &&
    ad.addr_bytes[3] == 0xff && ad.addr_bytes[4] == 0xff && ad.addr_bytes[5] == 0xff;
}
static uint8_t is_same_addr(struct ether_addr ad1, struct ether_addr ad2){
  return ad1.addr_bytes[0] == ad2.addr_bytes[0] && 
         ad1.addr_bytes[1] == ad2.addr_bytes[1] && 
         ad1.addr_bytes[2] == ad2.addr_bytes[2] && 
         ad1.addr_bytes[3] == ad2.addr_bytes[3] && 
         ad1.addr_bytes[4] == ad2.addr_bytes[4] && 
         ad1.addr_bytes[5] == ad2.addr_bytes[5];
}

static void packet_handle_external(struct rte_mbuf *m, unsigned portid){
  printf("external\n");
  struct ether_hdr *eth;
  eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
  if(is_same_addr(eth->d_addr, l2fwd_ports_eth_addr[portid] ) == 0 && is_broadcast(eth->d_addr) == 0){
    printf("not to my eth so dwomp\n");
    rte_pktmbuf_free(m);
  }else{
    if(rte_bswap16(eth->ether_type) == ETHER_TYPE_ARP){
      arp_handle_external(m, portid, eth);
    }else{
      printf("PACKET IS IP\n");
      struct ipv4_hdr *ip_hdr;
      ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr));
      uint32_t newkey;
      int ret;
      newkey = ip_hdr->src_addr;
      printf("from  ");
      show_ip(newkey);
      printf("I ADDED this!!\n");
      printf("portid = %d\n", portid);
      ret = rte_hash_add_key(mac_table_hash[portid],(void *) &newkey);
      printf("debug1\n");
      mac_table[portid][ret] = eth->s_addr;                             //200
      int outport;
      for(outport = 0; outport <nb_ports; outport++){
        if(ip_hdr->dst_addr==port_to_ip[outport]){
          break;
        }
      }
      if(outport != nb_ports){
        printf("This packet is for ME(i = %d)\n", outport);
        if(ip_hdr->next_proto_id == IP_NEXT_PROT_ICMP){
          printf("This packet is to me ICMP\n");
          struct icmp_hdr *icmp_hdr;
          icmp_hdr = (struct icmp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr));
          if(icmp_hdr->icmp_type == IP_ICMP_ECHO_REQUEST){
            printf("This packet is ICMP REQUEST\n");
            //ICMP REQUEST
            set_eth_header(eth, &l2fwd_ports_eth_addr[portid], &eth->s_addr, ETHER_TYPE_IPv4, 0);
            set_icmp_header(icmp_hdr, IP_ICMP_ECHO_REPLY, icmp_hdr->icmp_code, icmp_hdr->icmp_cksum, icmp_hdr->icmp_ident, icmp_hdr->icmp_seq_nb);
            uint32_t tmp = ip_hdr->dst_addr;
            ip_hdr->dst_addr = ip_hdr->src_addr;
            ip_hdr->src_addr = tmp;
            TX_enqueue(m, (uint8_t) portid);
          }else{
            //other ICMP
          }
        }else{
          // not ICMP
        }
      }else{
        ip_hdr->time_to_live--;
        if(ip_hdr->time_to_live == 0){
          printf("TTL 0 TIME EXCEEDED\n");
          struct rte_mbuf *pkt;
          struct ether_hdr *eth_pkt;
          struct ipv4_hdr *ip_pkt;
          struct icmp_hdr *icmp_pkt;
          pkt = rte_pktmbuf_alloc(l2fwd_pktmbuf_pool[rte_lcore_id()]);
          eth_pkt = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
          ip_pkt = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr));
          icmp_pkt = (struct icmp_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr));

          //icmp_ttl = (struct icmp_ttl_data *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr) + sizeof(struct icmp_hdr));

          set_eth_header(eth_pkt, &l2fwd_ports_eth_addr[portid], &eth->s_addr, ETHER_TYPE_IPv4, 0);
          set_ipv4_header(ip_pkt, rte_bswap32(port_to_ip[portid]), rte_bswap32(ip_hdr->src_addr), IP_NEXT_PROT_ICMP,
          2*(int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr)+8); 
          //set_icmp_header(icmp_pkt, IP_ICMP_TIME_EXCEEDED, 0, icmp_hdr->icmp_cksum, icmp_hdr->icmp_ident, icmp_hdr->icmp_seq_nb);
          set_icmp_header(icmp_pkt, IP_ICMP_TIME_EXCEEDED, 0, 0, 0, 0);

          struct ipv4_hdr *icmp_ip_header;
          //struct icmp_ttl_data *icmp_ttl;
          uint64_t *icmp_data;
          uint64_t *icmp_data_tmp;
          icmp_ip_header = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr) + sizeof(struct icmp_hdr));
	        icmp_ip_header->version_ihl = ip_hdr->version_ihl;		
	        icmp_ip_header->type_of_service = ip_hdr->type_of_service;
	        icmp_ip_header->total_length = ip_hdr->total_length;		
	        icmp_ip_header->packet_id = ip_hdr->packet_id;	
	        icmp_ip_header->fragment_offset = ip_hdr->fragment_offset;
	        icmp_ip_header->time_to_live = ip_hdr->time_to_live+1;		
	        icmp_ip_header->next_proto_id = ip_hdr->next_proto_id;	
	        icmp_ip_header->hdr_checksum = ip_hdr->hdr_checksum;		
	        icmp_ip_header->src_addr = ip_hdr->src_addr;		
	        icmp_ip_header->dst_addr = ip_hdr->dst_addr;		

          icmp_data_tmp = (uint64_t *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr));
          printf("icmp_data= %"PRIu64, *icmp_data_tmp);
          icmp_data = (uint64_t *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr)+ 2*sizeof(struct ipv4_hdr) + sizeof(struct icmp_hdr));
          *icmp_data = *icmp_data_tmp;
          printf("icmp_data= %"PRIu64, *icmp_data);
          printf("\n");
          (pkt)->pkt_len = (int)sizeof(struct ether_hdr) + 2*(int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr)+8;
          (pkt)->data_len = (int)sizeof(struct ether_hdr) + 2*(int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr)+8;
          uint16_t tlen;
          tlen  = pkt->pkt_len - (sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
          icmp_pkt->icmp_cksum     = cksum(icmp_pkt, tlen, 0);



          TX_enqueue(pkt, (uint8_t) portid);
        }else{

          //not to me
          struct next_set next_set =  lookup(rte_bswap32(ip_hdr->dst_addr));
          if(next_set.unreachable == 1){
          struct rte_mbuf *pkt;
          struct ether_hdr *eth_pkt;
          struct ipv4_hdr *ip_pkt;
          struct icmp_unreachable *icmp_pkt;
          pkt = rte_pktmbuf_alloc(l2fwd_pktmbuf_pool[rte_lcore_id()]);
          eth_pkt = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
          ip_pkt = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr));
          icmp_pkt = (struct icmp_unreachable *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr));

          set_eth_header(eth_pkt, &l2fwd_ports_eth_addr[portid], &eth->s_addr, ETHER_TYPE_IPv4, 0);
          set_ipv4_header(ip_pkt, rte_bswap32(port_to_ip[portid]), rte_bswap32(ip_hdr->src_addr), IP_NEXT_PROT_ICMP,
          2*(int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr)+8); 
          //set_icmp_header(icmp_pkt, IP_ICMP_TIME_EXCEEDED, 0, icmp_hdr->icmp_cksum, icmp_hdr->icmp_ident, icmp_hdr->icmp_seq_nb);


          struct ipv4_hdr *icmp_ip_header;
          //struct icmp_ttl_data *icmp_ttl;
          uint64_t *icmp_data;
          uint64_t *icmp_data_tmp;
          icmp_ip_header = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr) + sizeof(struct icmp_hdr));
	        icmp_ip_header->version_ihl = ip_hdr->version_ihl;		
	        icmp_ip_header->type_of_service = ip_hdr->type_of_service;
	        icmp_ip_header->total_length = ip_hdr->total_length;		
	        icmp_ip_header->packet_id = ip_hdr->packet_id;	
	        icmp_ip_header->fragment_offset = ip_hdr->fragment_offset;
	        icmp_ip_header->time_to_live = ip_hdr->time_to_live+1;		
	        icmp_ip_header->next_proto_id = ip_hdr->next_proto_id;	
	        icmp_ip_header->hdr_checksum = ip_hdr->hdr_checksum;		
	        icmp_ip_header->src_addr = ip_hdr->src_addr;		
	        icmp_ip_header->dst_addr = ip_hdr->dst_addr;		

          icmp_data_tmp = (uint64_t *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr));
          printf("icmp_data= %"PRIu64, *icmp_data_tmp);
          icmp_data = (uint64_t *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr)+ 2*sizeof(struct ipv4_hdr) + sizeof(struct icmp_hdr));
          *icmp_data = *icmp_data_tmp;
          //*icmp_data = 0xffffffffffffffffff;
          printf("icmp_data= %"PRIu64, *icmp_data);
          printf("\n");
          //*icmp_data = 8;
          //printf("icmp_data_tmp = %u\n", *icmp_data);



          
          (pkt)->pkt_len = (int)sizeof(struct ether_hdr) + 2*(int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr)+8;
          (pkt)->data_len = (int)sizeof(struct ether_hdr) + 2*(int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr)+8;
          //(pkt)->pkt_len = (int)sizeof(struct ether_hdr) + (int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr);
          //(pkt)->data_len = (int)sizeof(struct ether_hdr) + (int)sizeof(struct ipv4_hdr)+ (int)sizeof(struct icmp_hdr);
          uint16_t tlen;
          tlen  = pkt->pkt_len - (sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
          set_icmp_unreachable(icmp_pkt, IP_ICMP_DESTINATION_UNREACHABLE, IP_ICMP_NETWORK_UNREACHABLE, 0, tlen, 777);
          icmp_pkt->icmp_cksum     = cksum(icmp_pkt, tlen, 0);

          TX_enqueue(pkt, (uint8_t) portid);

            printf("UNreachable!!!!\n");
          }else{
          printf("dest ip is ");
          show_ip(ip_hdr->dst_addr);
          printf("= %"PRIu32, ip_hdr->dst_addr);
          printf("nexthop is ");
          show_ip(next_set.nexthop);
          printf("nextport is %d\n",next_set.nextport);
          printf("I will find key ");
          show_ip(next_set.nexthop);
          printf("\n");
          ret = rte_hash_lookup(mac_table_hash[next_set.nextport], (const void *)&next_set.nexthop);
          printf("M lookup ret  = %d\n", ret);
          if(ret >= 0){
            printf("mac lookup!! MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                mac_table[portid][ret].addr_bytes[0],
                mac_table[portid][ret].addr_bytes[1],
                mac_table[portid][ret].addr_bytes[2],
                mac_table[portid][ret].addr_bytes[3],
                mac_table[portid][ret].addr_bytes[4],
                mac_table[portid][ret].addr_bytes[5]);
            ether_addr_copy(&mac_table[next_set.nextport][ret], &eth->s_addr);
            eth->d_addr.addr_bytes[0] = (uint8_t)(0xf) + (next_set.nextport<<4);
            int i;

            uint32_t ip_cksum;
            uint16_t *ptr16;
            ptr16 = (uint16_t *)ip_hdr;
            ip_cksum = 0;
            ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
            ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
            ip_cksum += ptr16[4];
            ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
            ip_cksum += ptr16[8]; ip_cksum += ptr16[9];
            ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
              (ip_cksum & 0x0000FFFF);
            ip_cksum %= 65536;
            ip_cksum = (~ip_cksum) & 0x0000FFFF;
            if (ip_cksum == 0){
              ip_cksum = 0xFFFF;
            }
            printf("before checksum = %"PRIu32, ip_hdr->hdr_checksum);
            ip_hdr->hdr_checksum = (uint16_t)ip_cksum;
            printf("\nafter checksum = %"PRIu32, ip_hdr->hdr_checksum);
            printf("\n");
            TX_enqueue(m, (uint8_t) next_set.nextport);
          }else{
            printf("debughoge0\n");
            struct rte_mbuf *pkt;
            struct ether_hdr *eth_pkt;
            struct arp_hdr *arp_pkt;
            pkt = rte_pktmbuf_alloc(l2fwd_pktmbuf_pool[rte_lcore_id()]);
            eth_pkt = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
            struct ether_addr * dummy;
            set_eth_header(eth_pkt, &l2fwd_ports_eth_addr[next_set.nextport], dummy, ETHER_TYPE_ARP, 1);
            arp_pkt = (struct arp_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr));

            set_arp_header(arp_pkt, &l2fwd_ports_eth_addr[next_set.nextport], dummy, port_to_ip[next_set.nextport], next_set.nexthop, ARP_OP_REQUEST);
            eth_pkt->d_addr.addr_bytes[0] = (uint8_t)(0xf) + (next_set.nextport<<4);
            int i;
            for(i = 1; i <6; i++){
              eth_pkt->d_addr.addr_bytes[i] =0;
            }
            for(i = 0; i <6; i++){
              eth_pkt->s_addr.addr_bytes[i] =0xff;
            }
            printf("arp generate!!\n");
            (pkt)->pkt_len = (int)sizeof(struct ether_hdr) + (int)sizeof(struct arp_hdr);
            (pkt)->data_len = (int)sizeof(struct ether_hdr) + (int)sizeof(struct arp_hdr);
            TX_enqueue(pkt, (uint8_t) next_set.nextport);
            rte_pktmbuf_free(m);
          }
        }
        }
        }
      }
    }


}

static void packet_handle_internal(struct rte_mbuf *m, unsigned portid){
  printf("internal\n");
  struct ether_hdr *eth;
  eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
  if(rte_bswap16(eth->ether_type) == ETHER_TYPE_ARP){
    struct arp_hdr *arp;
    arp = (struct arp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr));
    printf("ARP packet!!\n");
    if(rte_bswap16(arp->arp_op)== ARP_OP_REPLY){
      uint32_t newkey;
      unsigned ret;
      newkey = arp->arp_data.arp_sip;
      //
      printf("from arp add new key " );
      show_ip(newkey);
      printf("\n");
      //
      ret = rte_hash_add_key(mac_table_hash[portid],(void *) &newkey);
      mac_table[portid][ret] = arp->arp_data.arp_sha;;
      rte_pktmbuf_free(m);
      return;
    }else{
      unsigned nextport = rte_lcore_id();
      struct ether_hdr *eth_pkt;
      eth_pkt = rte_pktmbuf_mtod(m, struct ether_hdr *);
      ether_addr_copy(&eth->s_addr, &eth->d_addr);
      ether_addr_copy(&l2fwd_ports_eth_addr[node_id], &eth->s_addr);
      set_arp_header(arp, &l2fwd_ports_eth_addr[node_id], &eth->s_addr, port_to_ip[node_id], arp->arp_data.arp_tip, ARP_OP_REQUEST);
      TX_enqueue(m, (uint8_t) node_id);
    }
  }else{
    unsigned nextport = rte_lcore_id();
    struct ether_hdr *eth_pkt;
    eth_pkt = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ether_addr_copy(&eth->s_addr, &eth->d_addr);
    ether_addr_copy(&l2fwd_ports_eth_addr[node_id], &eth->s_addr);
    TX_enqueue(m, (uint8_t) node_id);
  }
}


static void packet_handle(struct rte_mbuf *m, unsigned portid){
  printf("----------------------------------------------------\n");
  printf("PACKET COME\n");
  printf("portid %u, coreid %u\n", portid, rte_lcore_id());
  struct ether_hdr *eth;
  eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
  if(portid == node_id){
    packet_handle_external(m, portid);
  }else{
    packet_handle_internal(m, portid);
  }
}


/* main processing loop */
static void router_main_loop(void){
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned lcore_id, queue_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();
	queue_id = lcore_id;
	qconf = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {
		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);
	}

	while (1){
		cur_tsc = rte_rdtsc();
		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)){
			for (portid = 0; portid < nb_ports; portid++) {
				if (qconf->tx_mbufs[portid].len == 0){
					continue;
        }
				l2fwd_send_burst(&lcore_queue_conf[lcore_id],
						 qconf->tx_mbufs[portid].len,
						 (uint8_t) portid, lcore_id);
				qconf->tx_mbufs[portid].len = 0;
			}

      //statistics!!!!!
			if (timer_period > 0) {
				timer_tsc += diff_tsc;
				if (unlikely(timer_tsc >= (uint64_t) timer_period)) {
					if (lcore_id == rte_get_master_lcore()) {
						print_stats();
						timer_tsc = 0;
					}
				}
			}
			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
    for (i = 0; i < qconf->n_rx_port; i++) {
      portid = qconf->rx_port_list[i];
      nb_rx = rte_eth_rx_burst((uint8_t) portid, (uint8_t)queue_id, pkts_burst, MAX_PKT_BURST);
      port_statistics[portid].rx[lcore_id] += nb_rx;
      for (j = 0; j < nb_rx; j++) {
        m = pkts_burst[j];
        rte_prefetch0(rte_pktmbuf_mtod(m, void *));
        packet_handle(m, portid);
      }
    }
  }
}

static int router_launch_one_lcore(__attribute__((unused)) void *dummy){
	router_main_loop();
	return 0;
}

/* display usage */
static void l2fwd_usage(const char *prgname){
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
		   "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n",
	       prgname);
}

static  int l2fwd_parse_node_nb(const char *q_arg) {
	char *end = NULL;
	unsigned long n;
	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0')){
		return -1;
  }
	if (n >= MAX_RX_QUEUE_PER_LCORE){
		return -1;
  }
	return n;
}

static unsigned int l2fwd_parse_nqueue(const char *q_arg) {
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0')){
		return 0;
  }
	if (n == 0){
		return 0;
  }
	if (n >= MAX_RX_QUEUE_PER_LCORE){
		return 0;
  }
	return n;
}

static int l2fwd_parse_timer_period(const char *q_arg) {
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0')){
		return -1;
  }
	if (n >= MAX_TIMER_PERIOD){
		return -1;
  }
	return n;
}

/* Parse the argument given in the command line of the application */
static int l2fwd_parse_args(int argc, char **argv) {
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:q:T:w:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {

		case 'w':
      ret =  l2fwd_parse_node_nb(optarg);
			if (ret == -1) {
				printf("invalid node_nb number\n");
				l2fwd_usage(prgname);
				return -1;
			}
      node_id = ret;
      printf("node_nb = %d\n", node_id);
			break;


		/* nqueue */
		case 'q':
			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
			if (l2fwd_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_period = l2fwd_parse_timer_period(optarg) * 1000 * TIMER_MILLISECOND;
			if (timer_period < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* long options */
		case 0:
			l2fwd_usage(prgname);
			return -1;

		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 0; /* reset getopt lib */
	return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

int main(int argc, char **argv){
	struct lcore_queue_conf *qconf;
	int ret;
  int i, j;
	uint8_t portid;
	unsigned lcore_id, rx_lcore_id;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");
	nb_ports = rte_eth_dev_count();
  printf("nb_ports = %d\n",nb_ports); 
	nb_lcores = rte_lcore_count();

  /*set up hash*/
  setup_hash(nb_ports);
  setup_radix_tree();

	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

  if (nb_ports > RTE_MAX_ETHPORTS){
    nb_ports = RTE_MAX_ETHPORTS;
  }

	/* create the mbuf pool */
  char str[10];
  for(i = 0; i < nb_lcores; i++){
    sprintf(str, "hoge%d",i);
    l2fwd_pktmbuf_pool[i] =
      rte_mempool_create(str, NB_MBUF,
          MBUF_SIZE, 32,
          sizeof(struct rte_pktmbuf_pool_private),
          rte_pktmbuf_pool_init, NULL,
          rte_pktmbuf_init, NULL,
          rte_socket_id(), 0);
    if (l2fwd_pktmbuf_pool[i] == NULL){
      rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
    }
  }

	rx_lcore_id = 0;
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */

  l2fwd_rx_queue_per_lcore = nb_lcores;
  for(rx_lcore_id = 0; rx_lcore_id <nb_lcores; rx_lcore_id++){
    for (portid = 0; portid < nb_ports; portid++) {
      if (qconf != &lcore_queue_conf[rx_lcore_id]){
        // Assigned a new logical core in the loop above. 
        qconf = &lcore_queue_conf[rx_lcore_id];
      }
      qconf->rx_port_list[qconf->n_rx_port] = portid;
      qconf->n_rx_port++;
    }
  }

	/* Initialise each port */
	for (portid = 0; portid < nb_ports; portid++) {
		/* init port */
		printf("Initializing port %u... ", (unsigned) portid);
		fflush(stdout);

		ret = rte_eth_dev_configure(portid, nb_lcores, nb_lcores, &prt_conf);

		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, (unsigned) portid);

		//mac addr of portid -> l2fwd_ports_eth_addr[portid]
    rte_eth_macaddr_get(portid,&l2fwd_ports_eth_addr[portid]);

		/* init one RX queue */
    fflush(stdout);
    int i;
    for(i = 0; i < nb_lcores;i++){
      ret = rte_eth_rx_queue_setup(portid, i, nb_rxd, rte_eth_dev_socket_id(portid), NULL, l2fwd_pktmbuf_pool[i]);
      if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
            ret, (unsigned) portid);
    }

		/* init one TX queue on each port */
    for(i = 0; i < nb_lcores;i++){
		fflush(stdout);
		ret = rte_eth_tx_queue_setup(portid, i, nb_txd,
				rte_eth_dev_socket_id(portid),
				NULL);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, (unsigned) portid);
    }

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, (unsigned) portid);


		rte_eth_promiscuous_enable(portid);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				(unsigned) portid,
				l2fwd_ports_eth_addr[portid].addr_bytes[0],
				l2fwd_ports_eth_addr[portid].addr_bytes[1],
				l2fwd_ports_eth_addr[portid].addr_bytes[2],
				l2fwd_ports_eth_addr[portid].addr_bytes[3],
				l2fwd_ports_eth_addr[portid].addr_bytes[4],
				l2fwd_ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (!nb_ports) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}
	check_all_ports_link_status(nb_ports);

  int mac;
  int port;
  for(mac = 0; mac < nb_ports; mac++){
    struct rte_eth_flex_filter filter;
    filter.len = 8;
    filter.bytes[0] = (uint8_t)(0xf) + (mac<<4);
    for(i = 1; i <8; i++){
    filter.bytes[i] = 0;
    }
    filter.mask[0] = (uint8_t)0b10000000;
    filter.priority = 1;
    filter.queue = mac;
    for(port = 0; port < nb_ports; port++){
      if(port == node_id){
        continue;
      }
      printf("mac = %d, port = %d\n", mac, port);
      ret  = rte_eth_dev_filter_ctrl(port, 
          RTE_ETH_FILTER_FLEXIBLE,
          RTE_ETH_FILTER_ADD,
          &filter);
    }
  }


	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(router_launch_one_lcore, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}

