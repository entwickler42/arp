#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

int create_socket()
{
//	int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	return sock;
}

void read_raw_socket(int sock)
{
	char data[8192];
	struct sockaddr_ll from;
	unsigned int fromlen = sizeof(from);

	while(read(sock,data,8192) > 0){
		struct iphdr* ip_hdr = (struct iphdr*) data;
		struct tcphdr* tcp_hdr = (struct tcphdr*) (data + sizeof(struct iphdr));
	
		printf("%15s:%-6u ->",inet_ntoa(*(struct in_addr*)&ip_hdr->saddr), tcp_hdr->source);
		printf("%15s:%-6u\n",inet_ntoa(*(struct in_addr*)&ip_hdr->daddr), tcp_hdr->dest);
	}

/*	
 	while(recvfrom(sock,data,8192,0,(struct sockaddr*)&from,&fromlen) > 0){
		if(from.sll_protocol == htons(ETH_P_IP)){
			struct iphdr* ip_hdr = (struct iphdr*) data;
			struct tcphdr* tcp_hdr = (struct tcphdr*) (data + sizeof(struct iphdr));
		
			printf("%15s:%-6u ->",inet_ntoa(*(struct in_addr*)&ip_hdr->saddr), tcp_hdr->source);
			printf("%15s:%-6u\n",inet_ntoa(*(struct in_addr*)&ip_hdr->daddr), tcp_hdr->dest);
		}
	}
	*/
}

int main(int argc, char* arv[])
{
	int ps = create_socket();
	if(ps == -1){
		perror("create_socket()");
		exit(1);
	}

	/*
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = 0;
	addr.sin_addr.s_addr = INADDR_ANY;
	
	if(bind(ps,(struct sockaddr*)&addr,sizeof(struct sockaddr_in)) == -1){
		perror("bind()");
		exit(1);
	}
	*/

	read_raw_socket(ps);
	close(ps);

	return 0;
}
