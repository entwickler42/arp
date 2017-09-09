#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <error.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <unistd.h>
#include <sys/ioctl.h> 
#include <net/if.h>

typedef int (*daemon_callback)(int s, char* pkg, int len_pkg, struct sockaddr_ll* addr);

struct arp_pkg 
{
	struct ethhdr ether;
	struct ether_arp arp;
};

int apz_create_socket();

int apz_read_socket(int s, daemon_callback callback);

int apz_arp_reply(
		int s, 
		int ifindex,
		struct ether_addr* ha_dst,
		struct ether_addr* ha_src,
		struct in_addr* pa_dst, 
		struct in_addr* pa_src);

int apz_handle_pkg(int s, char* pkg, int len_pkg, struct sockaddr_ll* addr);

void apz_fprint_eth_hdr(FILE* f, struct ethhdr* h);

void apz_fprint_arp_hdr(FILE* f, struct ether_arp* h);

char* arp_op2str(uint16_t op);
