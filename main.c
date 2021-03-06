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
#include"vlb.h"


#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF   8192

#define BURST_TX_DRAIN_US 1000 /* TX drain every ~100us */
/*
 * Configurable number of RX/TX ring descriptors
 */
//#define RTE_TEST_RX_DESC_DEFAULT 512
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 512

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */

uint8_t nb_lcores;

struct rte_mempool * l2fwd_pktmbuf_pool[MAX_NB_CORE];

struct rte_eth_stats oldstat;
struct rte_eth_stats newstat;


/* Print out statistics on packets dropped */
static void print_stats(void) {
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;
	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;
  int i;


  printf("my node id = %d data size = %dbyte\n", node_id, data_len);
	for (portid = 0; portid < nb_ports; portid++) {
  int ret;
  ret = rte_eth_stats_get(portid, &newstat);
    for(i = 0; i < nb_lcores; i++){
      /*
      printf("\n port = %d Q = %d: ipacket:%lu\n", portid, i, newstat.q_ipackets[i]);
      printf("port = %d Q = %d: outpacket:%lu\n", portid, i,  newstat.q_opackets[i]);
      printf("port = %d Q = %d: ibyte:%lu\n", portid, i, newstat.q_ibytes[i]);
      printf("port = %d Q = %d: outbyte:%lu\n", portid, i,  newstat.q_obytes[i]);
      printf("\nStatistics for port %u core %u ------------------------------"
          "\nPackets sent: %24"PRIu64
          "\nPackets received: %20"PRIu64
          "\nPackets dropped: %21"PRIu64,
          portid,
          i,
          port_statistics[portid].tx[i],
          port_statistics[portid].rx[i],
          port_statistics[portid].dropped[i]);
      */
      total_packets_tx += port_statistics[portid].tx[i];
      total_packets_rx += port_statistics[portid].rx[i];
      total_packets_dropped += port_statistics[portid].dropped[i];
      port_statistics[portid].tx[i] = 0;
      port_statistics[portid].rx[i] = 0;
      port_statistics[portid].dropped[i] = 0;
      /*
      if(portid == node_id){
        exter_total_packets_tx += port_statistics[portid].tx[i];
        exter_total_packets_rx += port_statistics[portid].rx[i];
      }else{
        inter_total_packets_tx += port_statistics[portid].tx[i];
        inter_total_packets_rx += port_statistics[portid].rx[i];
      }
      */
    }
    if(node_id == portid){
      printf("out->%d:%lu\n", node_id, newstat.ibytes);
      printf("%d->out:%lu\n", node_id, newstat.obytes);
      //printf(" out-> OUTPUT %lu pps\n",  newstat.opackets);
    }else{
      printf("%d->%d:%lu\n",portid,node_id, newstat.ibytes);
      printf("%d->%d:%lu\n",node_id,portid, newstat.obytes);
      //printf("INTERNAL TO NODE[%d]  %lu pps\n", portid, newstat.opackets);
    }
	fflush(stdout);
/*
    printf("My node id is %d\n", node_id);
    printf("port id %d my stat :in :%lu\n", portid, total_packets_rx);
    printf("port id %d my stat :out:%lu\n",portid, total_packets_tx);
    printf("port id %d my stat :drop:%lu\n",portid, total_packets_dropped);

    printf("port id %d TOTAL STAT:ipacket:%lu\n", portid, newstat.ipackets);
    printf("port id %d TOTAL STAT:outpacket:%lu\n",portid, newstat.opackets);
    */
    /*
     *
    printf("port id %d TOTAL STAT:ierrors:%lu\n",portid, newstat.ierrors);
    printf("port id %d TOTAL STAT:oerrors:%lu\n",portid, newstat.oerrors);
    printf("port id %d TOTAL STAT:imiss:%lu\n",portid, newstat.imissed);
    printf("port id %d TOTAL STAT:rxnombuf:%lu\n",portid, newstat.rx_nombuf);
    */
    total_packets_tx = 0; 
    total_packets_rx = 0; 
    rte_eth_stats_reset(portid);

  }
  /*
 printf("\nAggregate statistics ==============================="
		   "\nextnTotal packets sent: %18"PRIu64
		   "\nenxtnTotal packets received: %14"PRIu64
		   "\nintnTotal packets sent: %18"PRIu64
		   "\nintnTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   exter_total_packets_tx,
		   exter_total_packets_rx,
		   inter_total_packets_tx,
		   inter_total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");
  */
}

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
//#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
//#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
//#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */



//#define IGB_DEFAULT_RX_FREE_THRESH  32
//#define RX_PTHRESH 16 /**< Default values of RX prefetch threshold reg. */
//#define RX_HTHRESH 16 /**< Default values of RX host threshold reg. */
//#define RX_WTHRESH 8 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */

/*
static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
  .rx_free_thresh = IGB_DEFAULT_RX_FREE_THRESH,
  .rx_drop_en = 0
};
*/







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
  if(rte_bswap16(arp->arp_op)== ARP_OP_REPLY){
    uint32_t newkey;
    unsigned ret;
    newkey = arp->arp_data.arp_sip;
    //
    //printf("from arp add new key " );
    //show_ip(newkey);
    //printf("\n");
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
      struct arp_hdr *arp_pkt;
      arp_pkt = (struct arp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) 
      + sizeof(struct ether_hdr));
      set_eth_header(eth, &ports_eth_addr[portid], &eth->s_addr, ETHER_TYPE_ARP, 0);
      set_arp_header(arp_pkt, &ports_eth_addr[portid], &eth->d_addr, port_to_ip[ret], arp->arp_data.arp_sip, ARP_OP_REPLY);
      //show_ip(port_to_ip[ret]);
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

static void packet_handle_external(struct rte_mbuf *m, unsigned portid){
  //printf("external\n");
  struct ether_hdr *eth;
  eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
  if(is_same_addr(eth->d_addr, ports_eth_addr[portid] ) == 0 && is_broadcast(eth->d_addr) == 0){
    rte_pktmbuf_free(m);
  }else{
    if(rte_bswap16(eth->ether_type) == ETHER_TYPE_ARP){
      arp_handle_external(m, portid, eth);
    }else{
      struct ipv4_hdr *ip_hdr;
      ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr));
      int ret;
      int outport;
      outport = find_port_fip(ip_hdr->dst_addr);
      if(outport >= 0){
        if(ip_hdr->next_proto_id == IP_NEXT_PROT_ICMP){
          struct icmp_hdr *icmp_hdr;
          icmp_hdr = (struct icmp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr));
          if(icmp_hdr->icmp_type == IP_ICMP_ECHO_REQUEST){
            //ICMP REQUEST
            set_eth_header(eth, &ports_eth_addr[portid], &eth->s_addr, ETHER_TYPE_IPv4, 0);
            set_icmp_header(icmp_hdr, IP_ICMP_ECHO_REPLY, icmp_hdr->icmp_code, icmp_hdr->icmp_ident, icmp_hdr->icmp_seq_nb);
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
          pkt = rte_pktmbuf_alloc(l2fwd_pktmbuf_pool[rte_lcore_id()]);
          make_ttl_expkt(m, pkt, port_to_ip[portid]);
          TX_enqueue(pkt, (uint8_t) portid);
        }else{
          //not to me
          /*
          struct next_set next_set;
          ret = rte_hash_lookup(nextset_hash, (const void *)&ip_hdr->dst_addr);
          if(ret >= 0){
            next_set = nextset_table[ret]; 
          }else{
            next_set = lookup(rte_bswap32(ip_hdr->dst_addr));
            ret = rte_hash_add_key(nextset_hash,(void *) &ip_hdr->dst_addr);
            nextset_table[ret] = next_set;
          }
          */
          struct next_set next_set;
          next_set = lookup(rte_bswap32(ip_hdr->dst_addr));

          if(next_set.unreachable == 1){
            struct rte_mbuf *pkt;
            pkt = rte_pktmbuf_alloc(l2fwd_pktmbuf_pool[rte_lcore_id()]);
            make_unreach_pkt(m, pkt, port_to_ip[portid]);
            TX_enqueue(pkt, (uint8_t) portid);
            printf("UNreachable!!!!\n");
          }else{
            ret = rte_hash_lookup(mac_table_hash[next_set.nextport], (const void *)&next_set.nexthop);
            if(ret >= 0){
              ether_addr_copy(&mac_table[next_set.nextport][ret], &eth->s_addr);
              eth->d_addr.addr_bytes[0] = (uint8_t)(0xf) + (next_set.nextport<<4);
              ip_hdr->hdr_checksum = 0;
              ip_hdr->hdr_checksum =  cksum(ip_hdr,sizeof(struct ipv4_hdr), 0);
              //printf("\n");
              //TX_enqueue(m, (uint8_t) next_set.nextport);
              int destport;
              destport = forwarding_node_id(m->hash.rss);
              TX_enqueue(m, (uint8_t) destport);
            }else{
              struct rte_mbuf *pkt;
              struct ether_hdr *eth_pkt;
              struct arp_hdr *arp_pkt;
              pkt = rte_pktmbuf_alloc(l2fwd_pktmbuf_pool[rte_lcore_id()]);
              eth_pkt = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
              struct ether_addr * dummy;
              set_eth_header(eth_pkt, &ports_eth_addr[next_set.nextport], dummy, ETHER_TYPE_ARP, 1);
              arp_pkt = (struct arp_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr));
              set_arp_header(arp_pkt, &ports_eth_addr[next_set.nextport], dummy, port_to_ip[next_set.nextport], next_set.nexthop, ARP_OP_REQUEST);
              eth_pkt->d_addr.addr_bytes[0] = (uint8_t)(0xf) + (next_set.nextport<<4);
              int i;
              memset(&eth_pkt->s_addr, 0xff, 6);
              memset(&eth_pkt->d_addr.addr_bytes[1], 0xff, 5);
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
  struct ether_hdr *eth;
  eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
  if(rte_bswap16(eth->ether_type) == ETHER_TYPE_ARP){
    struct arp_hdr *arp;
    arp = (struct arp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr));
    if(rte_bswap16(arp->arp_op)== ARP_OP_REPLY){
      uint32_t newkey;
      unsigned ret;
      newkey = arp->arp_data.arp_sip;
      //show_ip(newkey);
      ret = rte_hash_add_key(mac_table_hash[portid],(void *) &newkey);
      mac_table[portid][ret] = arp->arp_data.arp_sha;;
      rte_pktmbuf_free(m);
      return;
    }else{
      unsigned nextport = rte_lcore_id();
      if(nextport == node_id){
        struct ether_hdr *eth_pkt;
        eth_pkt = rte_pktmbuf_mtod(m, struct ether_hdr *);
        ether_addr_copy(&eth->s_addr, &eth->d_addr);
        ether_addr_copy(&ports_eth_addr[node_id], &eth->s_addr);
        set_arp_header(arp, &ports_eth_addr[node_id], &eth->s_addr, port_to_ip[node_id], arp->arp_data.arp_tip, ARP_OP_REQUEST);
        TX_enqueue(m, (uint8_t) node_id);
      }else{
        TX_enqueue(m, (uint8_t) nextport);
      }
    }
  }else{
    unsigned nextport = rte_lcore_id();
    if(nextport == node_id){
      struct ether_hdr *eth_pkt;
      eth_pkt = rte_pktmbuf_mtod(m, struct ether_hdr *);
      ether_addr_copy(&eth->s_addr, &eth->d_addr);
      ether_addr_copy(&ports_eth_addr[node_id], &eth->s_addr);
      TX_enqueue(m, (uint8_t) node_id);
    }else{
      TX_enqueue(m, (uint8_t) nextport);
    }
  }
}


static void packet_handle(struct rte_mbuf *m, unsigned portid){
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
	unsigned i, portid;
  int j, nb_rx;
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
      if ( (nb_rx = rte_eth_rx_burst((uint8_t) portid, (uint8_t)queue_id, pkts_burst, MAX_PKT_BURST)) == 0 ){
        continue;
      }
      int PREFETCH_OFFSET = (nb_rx>>1);
      port_statistics[portid].rx[lcore_id] += nb_rx;
      /*
      for (j = 0; j < nb_rx; j++) {
        m = pkts_burst[j];
        rte_prefetch0(rte_pktmbuf_mtod(m, void *));
        packet_handle(m, portid);
      }
      */
      /* Prefetch first packets */
      for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));

      /* Prefetch and handle already prefetched packets */
      for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + PREFETCH_OFFSET], void *));
        packet_handle(pkts_burst[j], portid);
      }
      /* Handle remaining prefetched packets */
      for (; j < nb_rx; j++)
        packet_handle(pkts_burst[j], portid);
    }
  }
}

static int router_launch_one_lcore(__attribute__((unused)) void *dummy){
	router_main_loop();
	return 0;
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

	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */

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

		//mac addr of portid -> ports_eth_addr[portid]
    rte_eth_macaddr_get(portid,&ports_eth_addr[portid]);

      
		/* init one RX queue */
    fflush(stdout);
    int i;
    for(i = 0; i < nb_lcores;i++){
      ret = rte_eth_rx_queue_setup(portid, i, nb_rxd, rte_eth_dev_socket_id(portid), NULL , l2fwd_pktmbuf_pool[i]);
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
				ports_eth_addr[portid].addr_bytes[0],
				ports_eth_addr[portid].addr_bytes[1],
				ports_eth_addr[portid].addr_bytes[2],
				ports_eth_addr[portid].addr_bytes[3],
				ports_eth_addr[portid].addr_bytes[4],
				ports_eth_addr[portid].addr_bytes[5]);

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
    filter.bytes[0] = (uint8_t)(0xf) + ((mac)<<4);
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
      //printf("mac = %d, port = %d\n", mac, port);
      ret  = rte_eth_dev_filter_ctrl(port, 
          RTE_ETH_FILTER_FLEXIBLE,
          RTE_ETH_FILTER_ADD,
          &filter);
      if(ret < 0){
        printf("can't set filter\n");
        return 1;
      }
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

