#include<stdio.h>
#include<pcap.h>
#include<WinSock2.h>
#include<stdbool.h>


#define SIZE_ETHERNET 14
#define SIZE_IPV6 40
#define ETHER_ADDR_LEN	6

#define	ETHERTYPE_IPV4	0x0800
#define ETHERTYPE_IPV6 0x86dd

#define IPv4_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IPv4_V(ip)		(((ip)->ip_vhl) >> 4)

#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)

#define TLS_HANDSHAKE 0x16
#define TLS_APPL 0x17
#define CLIENT_HELLO 1

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_FINACK 0x011

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};
/* IPv4 header */
struct sniff_ip {
	u_char ip_vhl;		/* version 4 bits | header length 4 bits */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};

/* IPv6 header */
struct sniff_ipv6 {
	u_char ipv6_vcf[4];  /* version 4 bits | traffic class 8 bits | Flow label 20 bits*/
	u_short ipv6_plen;   /* payload length */
	u_char ip_p;		/* next header protocol */
	u_char ipv6_hl;		/* hop limit =ttl */
	struct in6_addr ipv6_src, ipv6_dst;  /* source and dest address */
};

/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	u_char th_flags;	/*CWR|ECE|URG|ACK|PSH|RST|SYN|FIN*/
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};
struct comm_info{
	int ipv;
	struct in_addr address4;
	struct in6_addr address6;
	int fb;				/*0 no conn | 1 connected | 2 conn closed*/
	int nr_of_ports;
	int ports[20];
	char start_time[16];
	char close_time[16];
};
typedef struct node {
	struct comm_info communication;
	struct node* next;
}NODE;

NODE *list = NULL;
int check_if_ipv6_address_is_in_list( struct in6_addr addr);
int check_if_ipv4_address_is_in_list( struct in_addr addr);
NODE* insert_node( struct comm_info* info);
void add_port_to_socket_v4(struct in_addr addr,u_short port);
void add_port_to_socket_v6(struct in6_addr addr, int port);
void handle_port_closing_v4(struct in_addr addr, int port);
void handle_port_closing_v6(struct in6_addr addr, int port);
void print_comm_info(struct comm_info data);
void init(NODE** head);
void print_list();
void print_hex_ascii_line(const u_char *arg, int len, int offset);
int delete_port_from_list(int ports[],int port, int size);

int is_facebook(const char *payload, int payload_length)
{
	if (payload[0] == TLS_HANDSHAKE && payload[5] == CLIENT_HELLO)
	{

		for (int i = 46; i < payload_length - 8; i++)
		{
			if (payload[i] == 'f')
			{
				//memcmp(&payload[i + 1], "acebook", 7) == 0 ||
				if ( memcmp(&payload[i + 1], "bcdn", 4) == 0)
					return 1;
			}
		}
		return 0;
	}
	return 0;
}

void my_packet_handler(u_char args, const struct pcap_pkthdr *header, const u_char *packet)
{
	//NODE * list =l;
	int ip_protocol = 0;
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip = NULL; /* The IP header */
	const struct sniff_ipv6 *ipv6 = NULL;
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;
	int total_headers_size, payload_length;
	char tim[16];
	time_t t;
	struct tm ltime;

	ethernet = (struct sniff_ethernet*)(packet);
	if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV4)
	{
		ip_protocol = 4;
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		size_ip = IPv4_HL(ip) * 4;

		if (size_ip < 20)
		{
			//printf("   * Invalid IPv4 header length: %u bytes\n", size_ip);
			return;
		}
	}
	else if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV6)
	{
		ip_protocol = 6;
		ipv6 = (struct sniff_ipv6*)(packet + SIZE_ETHERNET);
		size_ip = SIZE_IPV6;

	}
	else
	{
		//*Not an IP packet. Skipping... 
		return;
	}
	if ((ip != NULL && ip->ip_p != IPPROTO_TCP) || (ipv6 != NULL && ipv6->ip_p != IPPROTO_TCP))
	{
		//Not a TCP packet. Skipping...
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20)
	{
		//printf("   * Invalid TCP header length: %u bytes\n\n \n", size_tcp);
		return;
	}
	if (ntohs(tcp->th_dport) == 443)
	{
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

		total_headers_size = SIZE_ETHERNET + size_ip + size_tcp;
		payload_length = header->caplen - total_headers_size;

		if (payload_length > 0)
		{
			if (is_facebook(payload, payload_length) == 1)
			{
				if (ip_protocol == 4)
				{
					if (check_if_ipv4_address_is_in_list(ip->ip_src) == 0)
					{
						struct comm_info new_com;
						new_com.fb = 1;
						new_com.ipv = 4;
						new_com.address4 = ip->ip_src;
						new_com.nr_of_ports = 1;
						memset(new_com.ports, 0, sizeof(new_com.ports));
						new_com.ports[0] = ntohs(tcp->th_sport);
						t = header->ts.tv_sec;
						localtime_s(&ltime, &t);
						strftime(tim, sizeof tim, "%H:%M:%S", &ltime);
						memcpy(new_com.start_time, tim, sizeof(tim));
						list = insert_node(&new_com);
					}
					else
					{
						add_port_to_socket_v4(ip->ip_src, ntohs(tcp->th_sport));
						print_list();
					}

				}
				else
				{
					if (check_if_ipv6_address_is_in_list(ipv6->ipv6_src) == 0)
					{
						struct comm_info new_com;
						new_com.fb = 1;
						new_com.ipv = 6;
						new_com.address6 = ipv6->ipv6_src;
						new_com.nr_of_ports = 1;
						memset(new_com.ports, 0, sizeof(new_com.ports));
						new_com.ports[0] = ntohs(tcp->th_sport);
						t = header->ts.tv_sec;
						localtime_s(&ltime, &t);
						strftime(tim, sizeof tim, "%H:%M:%S", &ltime);
						memcpy(new_com.start_time, tim, sizeof(tim));
						list = insert_node(&new_com);
					}
					else
					{
						add_port_to_socket_v6(ipv6->ipv6_src, ntohs(tcp->th_sport));
						print_list();
					}

				}

				//printf("\t Payload: \n");
				//print_hex_ascii_line(payload, payload_length, 0);
				//printf("\n \n \n");	
			}
			return;
		}
		if (tcp->th_flags == TH_FIN || tcp->th_flags == TH_FINACK)
		{
			if (ip_protocol == 4)
			{
				handle_port_closing_v4(ip->ip_src, ntohs(tcp->th_sport));
			}
			else
			{
				handle_port_closing_v6(ipv6->ipv6_src, ntohs(tcp->th_sport));
			}
			print_list();
		}
	}
	return;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		if (i == 7)
			printf(" ");
	}

	if (len < 8)
		printf(" ");


	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}
void print_comm_info(struct comm_info data)
{
	if (data.ipv == 4)
	{
		printf("IPv4 Packet\n ");
		printf("\t Device with IP address: %d.%d.%d.%d \n", data.address4.S_un.S_un_b.s_b1, data.address4.S_un.S_un_b.s_b2,
			data.address4.S_un.S_un_b.s_b3, data.address4.S_un.S_un_b.s_b4);
	}
	else
	{
		printf("IPv6 Packet\n ");
		char *addr = malloc(INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &data.address6, addr, INET6_ADDRSTRLEN);
		printf("\t Device with IP address: %s \n", addr);
	}
	if (data.fb == 1)
	{
		printf("Is using Facebook!\n");
		printf("Time when connection was started: %s\n ",data.start_time);
	}
}
void init(NODE** head)
{
	*head = NULL;
}
NODE* insert_node(struct comm_info* info)
{
	NODE* new_node = (NODE*)malloc(sizeof(NODE));
	new_node->communication = *info;
	new_node->next = list;
	return new_node;
}
void print_list()
{
	NODE *aux;
	aux = list;
	while (aux) 
	{
		if (aux->communication.fb != 0) 
		{
			if (aux->communication.ipv == 4)
			{
				printf("IPv4 Packet\n ");
				printf("\t Device with IP address: %d.%d.%d.%d \n", aux->communication.address4.S_un.S_un_b.s_b1, aux->communication.address4.S_un.S_un_b.s_b2,
					aux->communication.address4.S_un.S_un_b.s_b3, aux->communication.address4.S_un.S_un_b.s_b4);
			}
			else
			{
				printf("IPv6 Packet\n ");
				char *addr = malloc(INET6_ADDRSTRLEN);
				inet_ntop(AF_INET6, &aux->communication.address6, addr, INET6_ADDRSTRLEN);
				printf("\t Device with IP address: %s \n", addr);
			}
			if (aux->communication.fb == 1)
			{
				printf("\tIs using Facebook!\n");
				printf("\tTime when connection was started: %s\n ", aux->communication.start_time);
				printf("\t Communication oppened on %d ports: ", aux->communication.nr_of_ports);
				for (int i = 0; i < aux->communication.nr_of_ports; i++)
				{
					printf("%d   ", aux->communication.ports[i]);
				}
			}
			if (aux->communication.fb == 2)
			{
				printf("\tClosed connection with Facebook!\n");
				printf("\tTime when connection was started: %s\n ", aux->communication.start_time);
				printf("\tTime when connection was closed: %s\n ", aux->communication.close_time);
				aux->communication.fb = 0;
			}
			printf("\n-------\n\n");
		}
		aux = aux->next;
	}
}

int check_if_ipv4_address_is_in_list(struct in_addr addr)
{
	NODE *aux;
	aux = list;
	while (aux)
	{
		if (addr.S_un.S_addr == aux->communication.address4.S_un.S_addr)
			return 1;
		aux = aux->next;
	}
	return 0;
}

int check_if_ipv6_address_is_in_list(struct in6_addr addr)
{
	NODE *aux;
	aux = list;
	while (aux)
	{
		if(memcmp(addr.u.Word,aux->communication.address6.u.Word,sizeof(addr.u.Word))==0)
			return 1;
		aux = aux->next;
	}
	return 0;
}
void add_port_to_socket_v4(struct in_addr addr, u_short port)
{
	NODE *aux;
	aux = list;
	while (aux)
	{
		if (addr.S_un.S_addr == aux->communication.address4.S_un.S_addr)
		{
			if (aux->communication.nr_of_ports >= 20)
			{
				return;
			}
			aux->communication.nr_of_ports++;
			aux->communication.ports[aux->communication.nr_of_ports - 1] = port;
		}
		aux = aux->next;
	}
}
void add_port_to_socket_v6(struct in6_addr addr, int port)
{
	NODE *aux;
	aux = list;
	while (aux)
	{
		if (memcmp(addr.u.Word, aux->communication.address6.u.Word, sizeof(addr.u.Word)) == 0)
		{
			if (aux->communication.nr_of_ports >= 20)
			{
				return;
			}
			aux->communication.nr_of_ports++;
			aux->communication.ports[aux->communication.nr_of_ports - 1] = port;
		}
		aux = aux->next;
	}
}

void handle_port_closing_v4(struct in_addr addr, int port)
{
	NODE *aux;
	aux = list;
	while (aux)
	{
		if (addr.S_un.S_addr == aux->communication.address4.S_un.S_addr)
		{
			if (aux->communication.nr_of_ports > 0)
			{
				aux->communication.nr_of_ports = delete_port_from_list(aux->communication.ports, port, aux->communication.nr_of_ports);
				if (aux->communication.nr_of_ports == 0 && aux->communication.fb == 1)
				{
					struct tm ltime;
					char tim[16];
					time_t t = time(NULL);
					localtime_s(&ltime, &t);
					strftime(tim, sizeof tim, "%H:%M:%S", &ltime);
					memcpy(aux->communication.close_time, tim, sizeof(tim));
					aux->communication.fb = 2;
				}
			}
		}
		aux = aux->next;
	}
}

void handle_port_closing_v6(struct in6_addr addr, int port)
{
	NODE *aux;
	aux = list;
	while (aux)
	{
		if (memcmp(addr.u.Word, aux->communication.address6.u.Word, sizeof(addr.u.Word)) == 0)
		{
			if (aux->communication.nr_of_ports > 0)
			{
				aux->communication.nr_of_ports = delete_port_from_list(&aux->communication.ports, port, aux->communication.nr_of_ports);
				if (aux->communication.nr_of_ports == 0 && aux->communication.fb==1)
				{
					struct tm ltime;
					char tim[16];
					time_t t = time(NULL);
					localtime_s(&ltime,&t);
					strftime(tim, sizeof tim, "%H:%M:%S", &ltime);
					memcpy(aux->communication.close_time, tim, sizeof(tim));
					aux->communication.fb = 2;
				}
			}
		}
		aux = aux->next;
	}
}
int delete_port_from_list(int ports[],int port, int size)
{
	int i;
	for (i = 0; i < size; i++)
		if (ports[i] == port)
			break;
	if (i < size)
	{
		size = size - 1;
		for (int j = i; j < size; j++)
			ports[j] = ports[j + 1];
		ports[size] = 0;
	}
	return size;
}

int main(int argc, char **argv)
{
	pcap_if_t *alldevs, *device;
	char errbuf[PCAP_ERRBUF_SIZE];
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	pcap_t *handle = NULL;
	int snapshot_length = 1024;
	int total_packet_count = -1;//450;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		printf("Error on finding devices to open: %s  \n", errbuf);
	}
	else 
	{
		/*
		select interface to listen to (same order as in wireshark)
		device=alldevs - first interf
		device=alldevs->next  - second interface
		device=alldevs->next->next - third interface and so on
		*/
		device = alldevs->next->next->next->next->next->next;
		handle = pcap_open_live(device->name, snapshot_length, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf);
		if (handle == NULL)
		{
			printf("Eroare la deschiderea adaptorului");
			return;
		}
		pcap_loop(handle, total_packet_count, my_packet_handler, NULL);
		
	}
	pcap_close(handle);
	pcap_freealldevs(alldevs);
	getch();
	return 0;
}