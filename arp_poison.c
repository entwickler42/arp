#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h> 
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */

struct ether_addr ether_aton_or_exit(const char* str)
{
	struct ether_addr *eth = ether_aton(str);
	if(eth == NULL){
		error(1,1,"%s is no valid hardware address !\n",str);
	}
	return *eth;
}

struct in_addr inet_aton_or_exit(const char* str)
{
	struct in_addr ip;
	if(inet_aton(str,&ip) == 0){
		error(1,1,"%s is no valid ip address !\n",str);
	}
	return ip;
}

int create_socket_or_exit()
{
	int s= socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if(s == -1){
		error(1,1,"can't create socket !\n");
	}
	return s;
}

int eth_enum_devices()
{
	struct ifreq* req_adr;
	struct ifreq  req_idx;
	struct ifreq  req_mac;
	struct ifconf cfg;
	int s,i,_1st = 0;
	struct ifreq req_buf[256];

	cfg.ifc_ifcu.ifcu_req = req_buf;
	cfg.ifc_len = 256;

	if((s = socket(AF_INET, SOCK_DGRAM, 0))==-1){
		error(1,1, "can't create ioctl socket !\n");
	}
	
	if(ioctl(s, SIOCGIFCONF, &cfg) == -1){
		error(1,1, "can't ioctl !\n");
	}

	for(i=0;i<cfg.ifc_len/sizeof(struct ifreq); i++){
		req_adr = cfg.ifc_req + i;
		strcpy(req_idx.ifr_ifrn.ifrn_name, req_adr->ifr_ifrn.ifrn_name);
		strcpy(req_mac.ifr_ifrn.ifrn_name, req_adr->ifr_ifrn.ifrn_name);
		if(ioctl(s, SIOCGIFINDEX, &req_idx) == -1){
			perror("SIOCGIFINDEX failed !\n");
		}
		if(ioctl(s, SIOCGIFHWADDR, &req_mac) == -1){
			perror("SIOCGIFHWADDR failed !\n");
		}
		printf("%i %20s %10s %15s\n",
				req_idx.ifr_ifindex,
				ether_ntoa((struct ether_addr*)&req_mac.ifr_ifru.ifru_hwaddr.sa_data),
				req_adr->ifr_ifrn.ifrn_name,
				inet_ntoa(((struct sockaddr_in*)&req_adr->ifr_ifru.ifru_addr)->sin_addr)
				);
		if(strncmp(req_idx.ifr_ifrn.ifrn_name,"lo",2) != 0 && _1st == 0){
			_1st = req_idx.ifr_ifindex;
		}
	}

	close(s);
	return _1st;
}

int arp_reply_ipv4(int s,
		const struct ether_addr* d_mac, 
		const struct ether_addr* s_mac,
		const struct in_addr* d_ip,
		const struct in_addr* s_ip)
{
	int err = 0;
	struct _ether_arp{
		struct ethhdr eth_hdr;
		struct ether_arp arp_hdr;
	} pkg;
	// fill ethernet header
	pkg.eth_hdr.h_proto = htons(ETH_P_ARP);
	memcpy(&pkg.eth_hdr.h_dest, d_mac, ETH_ALEN);
	memcpy(&pkg.eth_hdr.h_source, s_mac, ETH_ALEN);
	// fill arp header
	pkg.arp_hdr.ea_hdr.ar_op = htons(ARPOP_REPLY);
	pkg.arp_hdr.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	pkg.arp_hdr.ea_hdr.ar_pro = htons(ETH_P_IP);
	pkg.arp_hdr.ea_hdr.ar_hln = ETH_ALEN;
	pkg.arp_hdr.ea_hdr.ar_pln = sizeof(struct in_addr);
	memcpy(&pkg.arp_hdr.arp_spa,s_ip,sizeof(struct in_addr));
	memcpy(&pkg.arp_hdr.arp_tpa,d_ip,sizeof(struct in_addr));
	memcpy(&pkg.arp_hdr.arp_sha,s_mac,ETH_ALEN);
	memcpy(&pkg.arp_hdr.arp_tha,d_mac,ETH_ALEN);

	struct sockaddr_ll addr_dst;
	socklen_t len_addr_dst = sizeof(struct sockaddr_ll);
	memset(&addr_dst,0,sizeof(struct sockaddr_ll));

	addr_dst.sll_family = PF_PACKET;
	addr_dst.sll_ifindex = 4;
	memcpy(&addr_dst.sll_addr, d_mac, sizeof(struct ether_addr));

	if(bind(s,(struct sockaddr*)&addr_dst,sizeof(struct sockaddr_ll)) == -1){
		perror("bind()");
	}

	if(write(s,&pkg,sizeof(struct _ether_arp)) == -1){
		perror("write(struct ethhdr)");
	}

	/*
	if(sendto(s, arp_hdr, len_pkt, 0, (struct sockaddr*)&addr_dst, len_addr_dst ) == -1){
		perror("sendto()");
	}
	*/

	return err;
}

int main(int argc, char* argv[])
{
	int opt;
	struct ether_addr eth_src;
	struct ether_addr eth_dst;
	struct in_addr ip_addr;

	while((opt = getopt(argc,argv,"lhs:d:i:")) != -1){
		switch(opt){
			case 's':
				eth_src = ether_aton_or_exit(optarg); 
			break;
			case 'd':
				eth_dst = ether_aton_or_exit(optarg); 
			break;
			case 'i':
				ip_addr = inet_aton_or_exit(optarg);
			break;
			case 'l':
				eth_enum_devices();
				exit(0);
			break;
		}
	}

	printf("Destination MAC:%s\n", ether_ntoa(&eth_dst));
	printf("Source MAC:%s\n", ether_ntoa(&eth_src));
	printf("IP to inject:%s\n", inet_ntoa(ip_addr));

	int s = create_socket_or_exit();
	arp_reply_ipv4(s, &eth_dst, &eth_src, &ip_addr, &ip_addr);

	return 0;
}
