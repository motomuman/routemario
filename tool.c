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

