#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include"env.h"
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
