#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stddef.h>

typedef struct status {
  int clsid;
  int chunk_size;
  int chunks_per_page;
  int total_pages;
  int total_chunks;
  int used_chunks;
  int free_chunks;
  int free_chunks_end;
  int mem_requested;
  int get_hits;
  int cmd_set;
  int delete_hits;
  int incr_hits;
  int decr_hits;
  int cas_hits;
  int cas_badval;
  int touch_hits;
}Status;

