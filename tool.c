#include"tool.h"


void show_ip(uint32_t ip){
  uint32_t showip = rte_bswap32(ip);
  uint8_t ip1;
  uint8_t ip2;
  uint8_t ip3;
  uint8_t ip4;
  ip1 = ((0xff000000) & showip)>>24;
  ip2 = ((0x00ff0000) & showip)>>16;
  ip3 = ((0x0000ff00) & showip)>>8;
  ip4 = ((0x000000ff) & showip);
  printf("%d.%d.%d.%d\n",ip1, ip2, ip3, ip4);
  return;
}

uint32_t ips_to_normal_order(char* ips[4]){
return IPv4(atoi(ips[0]), atoi(ips[1]), atoi(ips[2]), atoi(ips[3]));
}


uint8_t is_broadcast(struct ether_addr ad){
  return ad.addr_bytes[0] == 0xff && ad.addr_bytes[1] == 0xff && ad.addr_bytes[2] == 0xff &&
    ad.addr_bytes[3] == 0xff && ad.addr_bytes[4] == 0xff && ad.addr_bytes[5] == 0xff;
}
uint8_t is_same_addr(struct ether_addr ad1, struct ether_addr ad2){
  return ad1.addr_bytes[0] == ad2.addr_bytes[0] && 
         ad1.addr_bytes[1] == ad2.addr_bytes[1] && 
         ad1.addr_bytes[2] == ad2.addr_bytes[2] && 
         ad1.addr_bytes[3] == ad2.addr_bytes[3] && 
         ad1.addr_bytes[4] == ad2.addr_bytes[4] && 
         ad1.addr_bytes[5] == ad2.addr_bytes[5];
}

