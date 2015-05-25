#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include"env.h"
#include"arp_table.h"
#include"radix_tree.h"

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16





/* display usage */
static void l2fwd_usage(const char *prgname){
	printf("%s [EAL options] -- \n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
		   "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n",
	       prgname);
}

static  int l2fwd_parse_node_nb(const char *q_arg) {
	char *end = NULL;
	unsigned long n;
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0')){
		return -1;
  }
	if (n >= MAX_RX_QUEUE_PER_LCORE){
		return -1;
  }
	return n;
}

static unsigned int l2fwd_parse_nqueue(const char *q_arg) {
	char *end = NULL;
	unsigned long n;
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0')){
		return 0;
  }
	if (n == 0){
		return 0;
  }
	if (n >= MAX_RX_QUEUE_PER_LCORE){
		return 0;
  }
	return n;
}

static int l2fwd_parse_timer_period(const char *q_arg) {
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0')){
		return -1;
  }
	if (n >= MAX_TIMER_PERIOD){
		return -1;
  }
	return n;
}

/* Parse the argument given in the command line of the application */
 int l2fwd_parse_args(int argc, char **argv) {
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:T:w:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {

		case 'w':
      ret =  l2fwd_parse_node_nb(optarg);
			if (ret == -1) {
				printf("invalid node_nb number\n");
				l2fwd_usage(prgname);
				return -1;
			}
      node_id = ret;
      printf("node_nb = %d\n", node_id);
			break;


		/* nqueue */

		/* timer period */
		case 'T':
			timer_period = l2fwd_parse_timer_period(optarg) * 1000 * TIMER_MILLISECOND;
			if (timer_period < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* long options */
		case 0:
			l2fwd_usage(prgname);
			return -1;

		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 0; /* reset getopt lib */
	return ret;
}



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

  struct rte_hash_parameters ip_to_nextset_hash_param = {
    .name = "next_set",
    .entries = MAC_TABLE_ENTRIES,
    .bucket_entries = 4,
    .key_len = sizeof(uint32_t),
    .hash_func = rte_hash_crc,
    .hash_func_init_val = 0,
  };
  nextset_hash =  rte_hash_create(&ip_to_nextset_hash_param);
  if (nextset_hash== NULL)
    rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on \n");

}

void setup_radix_tree(){
  root = (struct radix_node *)(malloc(sizeof(struct radix_node)));
  root->node0 = NULL;
  root->node1 = NULL;
  root->done = 0;
  proot = (struct pradix_node *)(malloc(sizeof(struct pradix_node)));
  proot->pnode0 = NULL;
  proot->pnode1 = NULL;
  proot->done = 0;
  FILE *fp;
  char s[100];
  fp = fopen("config/interfaces", "r" );
  if( fp == NULL ){
    printf( "can't open interface/n");
  }
  while( fgets( s, 100, fp ) != NULL ){
    setup_port_lookup_table(s);
    printf( "%s", s );
  }
  fclose( fp );
  fp = fopen("config/route", "r" );
  if( fp == NULL ){
    printf( "can't open route/n");
  }
  while( fgets( s, 100, fp ) != NULL ){
    setup_lookup_table(s);
  }
  fclose( fp );
}
