#include<stdio.h>
#include<pcap.h>
#include<WinSock2.h>

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
int ip_protocol = 0;
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


void print_hex_ascii_line(const u_char *arg, int len, int offset);

void my_packet_handler(u_char *pack_count, const struct pcap_pkthdr *header, const u_char *packet)
{
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
			if (payload[0] == TLS_HANDSHAKE && payload[5] == CLIENT_HELLO)
			{

				for (int i = 46; i < payload_length - 5; i++)
				{
					if (payload[i] == 'f') {
						if (memcmp(&payload[i + 1], "acebook", 7) == 0 || memcmp(&payload[i + 1], "bcdn", 4) == 0)
						{
							printf("Conectare la Facebook!");

							t = header->ts.tv_sec;
							localtime_s(&ltime, &t);
							strftime(tim, sizeof tim, "%H:%M:%S", &ltime);
							printf("\t Ora: %s\n", tim);
							if (ip_protocol == 6)
							{
								printf("IPv6 Packet\n ");
								char *dest = malloc(INET6_ADDRSTRLEN);
								char *src = malloc(INET6_ADDRSTRLEN);
								inet_ntop(AF_INET6, &ipv6->ipv6_dst, dest, INET6_ADDRSTRLEN);
								inet_ntop(AF_INET6, &ipv6->ipv6_src, src, INET6_ADDRSTRLEN);
								printf("\t Source IP: %s \n", src);
								printf("\t Destination IP: %s \n", dest);
							}
							else
							{
								printf("IPv4 Packet\n ");
								printf("\t Source IP: %d.%d.%d.%d \n", ip->ip_src.S_un.S_un_b.s_b1, ip->ip_src.S_un.S_un_b.s_b2,
									ip->ip_src.S_un.S_un_b.s_b3, ip->ip_src.S_un.S_un_b.s_b4);
								printf("\t Destination IP: %d.%d.%d.%d \n", ip->ip_dst.S_un.S_un_b.s_b1, ip->ip_dst.S_un.S_un_b.s_b2,
									ip->ip_dst.S_un.S_un_b.s_b3, ip->ip_dst.S_un.S_un_b.s_b4);
							}

							printf("\t Port: %d \n", ntohs(tcp->th_sport));
							printf("\t Payload: \n");
							print_hex_ascii_line(payload, payload_length, 0);
							printf("\n \n \n");
							return;
						}
					}
				}

			}
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
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
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
	else {
		device = alldevs;

		handle = pcap_open_live(device->name, snapshot_length, PCAP_OPENFLAG_PROMISCUOUS, 10000, errbuf);
		pcap_loop(handle, total_packet_count, my_packet_handler, NULL);
	}
	pcap_close(handle);
	pcap_freealldevs(alldevs);
	getch();
	return 0;
}