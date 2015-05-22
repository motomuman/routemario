#include"arp_table.h"

void setup_hash(uint8_t port_num) {
  int i;
  for(i = 0; i < port_num; i++){
    char s[10];
    sprintf(s, "%d", i);
    struct rte_hash_parameters mac_table_hash_param = {
        .name = s,
        .entries = MAC_TABLE_ENTRIES,
        .bucket_entries = 4,
        .key_len = sizeof(uint32_t),
        .hash_func = rte_hash_crc,
        .hash_func_init_val = 0,
    };
    mac_table_hash[i] =  rte_hash_create(&mac_table_hash_param);
    if (mac_table_hash[i]== NULL)
      rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on \n");
  }
}


/* HASH END*/

