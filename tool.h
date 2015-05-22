#ifndef TOOL_H
#define TOOL_H
#include <stdint.h>
#include<stdio.h>
#include<rte_ip.h>
void show_ip(uint32_t ip);
uint32_t ips_to_normal_order(char* ips[4]);
#endif
