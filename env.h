#ifndef EVV_H
#define ENV_H

#include <rte_ether.h>
#include <rte_ethdev.h>

#define MAX_PKT_BURST 32
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
#define MAX_TIMER_PERIOD 86400 /* 1 day max */
#define TIMER_MILLISECOND 2000000ULL /* around 1ms at 2 Ghz */
static int64_t timer_period = 10 * TIMER_MILLISECOND * 1000; /* default period is 10 seconds */


static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

uint8_t nb_ports;
uint8_t node_id;

/*message buffer*/
struct mbuf_table {
	unsigned len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
uint32_t  port_to_ip[RTE_MAX_ETHPORTS];


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

/* Per-port statistics struct */
#define MAX_NB_CORE 128
struct routemario_statistics {
	uint64_t tx[MAX_NB_CORE];
	uint64_t rx[MAX_NB_CORE];
	uint64_t dropped[MAX_NB_CORE];
} __rte_cache_aligned;
struct routemario_statistics port_statistics[RTE_MAX_ETHPORTS];




#endif
