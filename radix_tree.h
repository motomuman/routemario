#ifndef RADIX_H
#define RADIX_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include<string.h>
#include"tool.h"

#define PORT_ALL 100

struct radix_node{
  uint32_t nexthop;
  uint32_t nextport;
  unsigned link_local;
  unsigned done;
  struct radix_node *node1;
  struct radix_node *node0;
};

struct pradix_node{
  unsigned nextport;
  unsigned done;
  struct pradix_node *pnode1;
  struct pradix_node *pnode0;
};

struct next_set{
  unsigned nextport;
  uint32_t nexthop;
  unsigned link_local;
  unsigned unreachable;
};


uint32_t  port_to_ip[RTE_MAX_ETHPORTS];
struct radix_node *root;
struct pradix_node *proot;



struct next_set lookup(uint32_t dst_ip);
unsigned port_lookup(uint32_t dst_ip);
void insert(uint32_t ip, uint32_t mask, uint32_t next, unsigned port, unsigned link_local);
void pinsert(uint32_t ip, uint32_t mask, unsigned port);
void setup_radix_tree();
#endif
