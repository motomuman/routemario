#include <rte_ip.h>
#include"radix_tree.h"
#include"tool.h"
#include"env.h"

struct next_set lookup(uint32_t dst_ip){
  int i;
  struct next_set ret;
  ret.unreachable = 1;
  struct radix_node *now = root;
  for(i = 31; i >= 0; i--){
    if(now->done){
      //show_ip(now->nexthop);
      ret.nexthop = now->nexthop;
      ret.nextport = now->nextport;
      ret.link_local = now->link_local;
      ret.unreachable = 0;
    }
    if((dst_ip>>i)&1){
      if(now->node1 == NULL){
        if(now->done){
          ret.nexthop = now->nexthop;
          ret.nextport = now->nextport;
          ret.link_local = now->link_local;
        }
        if(ret.link_local==1){
          ret.nexthop = rte_bswap32(dst_ip);
        }
        return ret;
      }
      now = now->node1;
    }else{
      if(now->node0 == NULL){
        if(now->done){
          ret.nexthop = now->nexthop;
          ret.nextport = now->nextport;
          ret.link_local = now->link_local;
        }
        if(ret.link_local==1){
          ret.nexthop = rte_bswap32(dst_ip);
        }
        return ret;
      }
      now = now->node0;
    }
  }
  if(ret.link_local==1){
          ret.nexthop = dst_ip;
  }
  return ret;
}


unsigned port_lookup(uint32_t dst_ip){
  int i;
  unsigned nextport = PORT_ALL;
  struct pradix_node *now = proot;
  for(i = 31; i >= 0; i--){
    if(now->done){
      nextport = now->nextport;
    }
    if((dst_ip>>i)&1){
      if(now->pnode1 == NULL){
        if(now->done){
          return now->nextport;
        }else{
          return nextport;
        }
      }
      now = now->pnode1;
    }else{
      if(now->pnode0 == NULL){
        if(now->done){
          return now->nextport;
        }else{
          return nextport;
        }
      }
      now = now->pnode0;
    }
  }
  return nextport;
}

void insert(uint32_t ip, uint32_t mask, uint32_t nexthop, unsigned nextport, unsigned link_local){
  nexthop = rte_bswap32(nexthop);
  //show_ip(ip);
  //show_ip(mask);
  int i;
  struct radix_node *now = root;
  for(i = 31; i >= 0; i--){
    if(!((mask>>i)&1)){
      now->nexthop = nexthop;
      now->nextport = nextport;
      now->link_local = link_local;
      now->done = 1;
      break;
    }
    if((ip>>i)&1){
      if(now->node1 == NULL){
        now->node1 =(struct radix_node *)malloc(sizeof(struct radix_node));
        now->node1->done = 0;
        now->node1->node0 = NULL;
        now->node1->node1 = NULL;
      }
      now = now->node1;
    }else{
      if(now->node0 == NULL){
        now->node0 =(struct radix_node *)malloc(sizeof(struct radix_node));
        now->node0->done = 0;
        now->node0->node0 = NULL;
        now->node0->node1 = NULL;
      }
      now = now->node0;
    }
  }
}


void pinsert(uint32_t ip, uint32_t mask, unsigned nextport){
  int i;
  struct pradix_node *now = proot;
  for(i = 31; i >= 0; i--){
    if(!((mask>>i)&1)){
      now->nextport = nextport;
      now->done = 1;
      break;
    }
    if((ip>>i)&1){
      if(now->pnode1 == NULL){
        now->pnode1 =(struct pradix_node *)malloc(sizeof(struct pradix_node));
        now->pnode1->done = 0;
        now->pnode1->pnode0 = NULL;
        now->pnode1->pnode1 = NULL;
      }
      now = now->pnode1;
    }else{
      if(now->pnode0 == NULL){
        now->pnode0 =(struct pradix_node *)malloc(sizeof(struct pradix_node));
        now->pnode0->done = 0;
        now->pnode0->pnode0 = NULL;
        now->pnode0->pnode1 = NULL;
      }
      now = now->pnode0;
    }
  }
}


void split( char *str, const char *delim, char *outlist[]) {
  char    *tk;
  int     cnt = 0;
  tk = strtok( str, delim );
  while( tk != NULL) {
    outlist[cnt++] = tk;
    tk = strtok( NULL, delim );
  }
  return;
}


void setup_port_lookup_table(char s[100]){
  char *interfaces[5];
  int cnt;
  int i;
  split(s, " " , interfaces);
  int port = atoi(interfaces[0]+4);
  char *ips1[4];
  char *ips2[4];
  split(interfaces[1], "." , ips1);
  split(interfaces[2], "." , ips2);
  port_to_ip[port] = rte_bswap32(ips_to_normal_order(ips1));
  pinsert(ips_to_normal_order(ips1),ips_to_normal_order(ips2), port); 
  insert(ips_to_normal_order(ips1), ips_to_normal_order(ips2), 0, port, 1); 

}

void setup_lookup_table(char s[100]){
  char *interfaces[5];
  int cnt;
  int i;
  split(s, " " , interfaces);
  char *ips1[5];
  char *ips2[5];
  char *ips3[5];
  unsigned port;
  split(interfaces[0], "." , ips1);
  split(interfaces[1], "." , ips2);
  split(interfaces[2], "." , ips3);
  port = port_lookup(ips_to_normal_order(ips3));
  insert(ips_to_normal_order(ips1), ips_to_normal_order(ips2), ips_to_normal_order(ips3) , port, 0); 
}

