#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <string.h>

int main(int argc, char* argv[])
{
	//device, ip_destination, mac_destination
	char errbuff[LIBNET_ERRBUF_SIZE]; //0x100

	char ip_spoof[17]; char ip_dest[17];
	u_int32_t ip_network_spoof; u_int32_t ip_network_dest;
	u_int8_t* mac_spoof; u_int8_t* mac_dest;
	char* device = (char*)malloc(64);
	int random_seed;
	memset(device, '\0', 0);

	//Copy device into string;
	strncpy(device, argv[1], strlen(argv[1]));
	printf("Device is %s\n", device);

	//Start libnet 0x01 = LIBNET_RAW4
	libnet_t* lnet = libnet_init(0x01, device, errbuff);

	//build ip_s

	memcpy(ip_dest, argv[2], 17);
	ip_network_dest = libnet_name2addr4(lnet, ip_dest, LIBNET_DONT_RESOLVE);

	if(ip_network_dest == -1)
	{
		perror("Invalid destination IP address");
		exit(1);
	}

	random_seed = libnet_seed_prand(lnet);
	ip_network_spoof = libnet_get_prand(random_seed);

	if(ip_network_spoof == -1)
	{
		perror("Could not create a spoof address");
		exit(1);
	}

	//BUILD IP VARS
	uint16_t packet_length = LIBNET_TCP_H;//LIBNET_IPV4_H + LIBNET_TCP_H;
	uint16_t id = libnet_get_prand(LIBNET_PR16);
	uint16_t frag = 0;
	uint16_t ttl = 10;

	//BUILD TCP VARS
	uint16_t sport = atoi("8554");
	uint16_t dport = atoi("8554");
	unsigned int seq = libnet_get_prand(LIBNET_PR32);
	unsigned int ack = libnet_get_prand(LIBNET_PR32);
	unsigned short control = 0x02;
	uint16_t win = libnet_get_prand(LIBNET_PR16);
	uint16_t urg = 0x00;

	//BUILD TCP
	libnet_ptag_t tcpheader = libnet_build_tcp(sport, dport, seq, ack, control, win, 0, urg, LIBNET_TCP_H, NULL, 0, lnet, 0);
	if(tcpheader == -1)
	{
		perror("Could not create TCP header\n");
		exit(-1);
	}
	else
		printf("TCP header is built\n");

	//BUILD IPV4
        libnet_ptag_t ipv4header = libnet_build_ipv4(packet_length, 0x10, id, frag, ttl, IPPROTO_TCP, 0, ip_network_spoof, ip_network_dest, NULL, 0, lnet, 0);
        if(ipv4header == -1)
        {
                perror("Could not create ipv4 header\n");
                exit(-1);
        }
        else
                printf("IP header built\n");


	int success = libnet_write(lnet);
	if(success == -1)
	{
		perror("Unable to write packet to network\n");
		exit(-1);
	}
	else
		printf("Wrote packet to network!\n");
	libnet_destroy(lnet);
	return 0;
}
