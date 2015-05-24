#ifndef TOOL_H
#define TOOL_H
#include <stdint.h>
#include<stdio.h>
#include<rte_ip.h>
#include<rte_ip.h>
#include <rte_ether.h>
void show_ip(uint32_t ip);
uint32_t ips_to_normal_order(char* ips[4]);
uint8_t is_broadcast(struct ether_addr ad);
uint8_t is_same_addr(struct ether_addr ad1, struct ether_addr ad2);
#endif
