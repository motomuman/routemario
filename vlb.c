#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_cycles.h>

#include "vlb.h"
#include "env.h"

#define VLB_SIZE (1 << 20)
#define EXPIRE_TIME (3 << 27) 
#define NODE_SIZE (4)

#define RTE_LOGTYPE_VLB RTE_LOGTYPE_USER1

static uint8_t round_robbin = 0;
static struct vlb_info vlb_tb[VLB_SIZE];

static uint8_t
next_node_id() {
  round_robbin = (++round_robbin) & (NODE_SIZE - 1); 
  if(round_robbin == node_id) 
    round_robbin = (++round_robbin) & (NODE_SIZE - 1); 
  return round_robbin; 
}

uint8_t
forwarding_node_id(uint32_t rss)
{
  uint32_t index = rss & (VLB_SIZE -1);
  struct vlb_info *info = &vlb_tb[index];
  uint64_t now =  rte_get_timer_cycles();
  uint64_t gap =  now - info->expire;
//  if (!info->expire || gap > EXPIRE_TIME) {
    info->node_id = next_node_id();
//  }

  //RTE_LOG(DEBUG, VLB, "gap %lu\n", gap);
  info->expire = now;
  return info->node_id;
}
