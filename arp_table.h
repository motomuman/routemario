#ifndef ARP_TABLE_H
#define ARP_TABLE_H
#include<rte_hash.h>
#include <rte_memory.h>
#include <rte_ether.h>

void setup_hash(uint8_t port_num);
struct rte_hash *mac_table_hash[RTE_MAX_ETHPORTS];

#define MAC_TABLE_ENTRIES		1024

struct ether_addr mac_table[RTE_MAX_ETHPORTS][MAC_TABLE_ENTRIES] __rte_cache_aligned;

struct rte_hash *mac_addr_to_portid;
#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif

#endif
