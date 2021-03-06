/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/ether.h>

#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>

#define DEFAULT_IF	"ens5"

#define CKSUM_CARRY(x) \
		(x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

static long
inChecksum(unsigned short *buf, int len)
{
	register long sum = 0;
	while (len > 1) {
		sum += *buf++;
		len -= 2;
	}
	if (len == 1) {
		sum += *(u_int8_t *)buf;
	}
	return sum;
}

static unsigned short
checksum_ip(struct ip *ip)
{
	int sum;
        sum = inChecksum((unsigned short *)ip, ip->ip_hl * 4);
	return CKSUM_CARRY(sum);
}

#define PROTO_TCP  6
#define PROTO_UDP 17

static uint32_t
net_checksum_add(int len, uint8_t *buf)
{
	uint32_t sum = 0;
	int i;
	for (i = 0; i < len; i++) {
		if (i & 1)
			sum += (uint32_t)buf[i];
		else
			sum += (uint32_t)buf[i] << 8;
	}
	return sum;
}

static uint16_t
net_checksum_finish(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return ~sum;
}

static uint16_t
net_checksum_tcpudp(uint16_t length, uint16_t proto, uint8_t *addrs, uint8_t *buf)
{
	uint32_t sum = 0;
	sum += net_checksum_add(length, buf);         // payload
	sum += net_checksum_add(8, addrs);            // src + dst address
	sum += proto + length;                        // protocol & length
	return net_checksum_finish(sum);
}

static uint16_t
checksum_l4(struct ip *iphdr)
{
	int hlen, plen, proto, csum_offset;
	uint16_t csum;
	uint8_t *data = (uint8_t *)iphdr;

	if ((data[0] & 0xf0) != 0x40)
		return 0; /* not IPv4 */
	hlen = (data[0] & 0x0f) * 4;
	plen = (data[2] << 8 | data[3]) - hlen;
	proto = data[9];

	switch (proto) {
	case PROTO_TCP:
		csum_offset = 16;
		break;
	case PROTO_UDP:
		csum_offset = 6;
		break;
	default:
		printf("No checksum\n");
		return 0;
	}

	if (plen < csum_offset+2)
		return 0;

	data[hlen + csum_offset]   = 0;
	data[hlen + csum_offset + 1] = 0;
	csum = net_checksum_tcpudp(plen, proto,
		data + 12, data + hlen);
	data[hlen + csum_offset]   = csum >> 8;
	data[hlen + csum_offset + 1] = csum & 0xff;
	return csum;
}

int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;

	if (argc != 2) {
		printf("Need to pass speed as parameter\n");
		return -1;
	}

	/* Open RAW socket to send on. */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("socket");
	}

	/* Get the index of the interface to send on. */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, DEFAULT_IF, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	/* Get the MAC address of the interface to send on. */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, DEFAULT_IF, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = 0x00;
	socket_address.sll_addr[1] = 0x00;
	socket_address.sll_addr[2] = 0x00;
	socket_address.sll_addr[3] = 0x00;
	socket_address.sll_addr[4] = 0x00;
	socket_address.sll_addr[5] = 0x00;

	char bytes[1093] = {
		0x06, 0xfd, 0x8b, 0xd4, 0xad, 0xda, 0x06, 0xce, 0x68, 0xf2, 0xef, 0x88, 0x08, 0x00,
		0x45, 0x00, 0x04, 0x37, 0x35, 0x59, 0x40, 0x00, 0x40, 0x06, 0xa5, 0x02, 0xac, 0x1f, 0x00, 0x5f, 0xac, 0x1f, 0x03, 0xc8,
		0x8e, 0x79, 0x1f, 0x90, 0x68, 0xc3, 0xe1, 0x9b, 0x10, 0x90, 0x14, 0xac, 0x80, 0x18,
		0x01, 0xeb, 0x60, 0x8f, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xc5, 0xd5, 0xc3, 0x70, 0xe4, 0xae,
		0xcc, 0x3f, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f,
		0x6c, 0x6f, 0x72, 0x20, 0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20, 0x63, 0x6f,
		0x6e, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69, 0x73,
		0x63, 0x69, 0x6e, 0x67, 0x20, 0x65, 0x6c, 0x69, 0x74, 0x2e, 0x20, 0x43, 0x72, 0x61, 0x73, 0x20,
		0x69, 0x6e, 0x20, 0x6d, 0x61, 0x73, 0x73, 0x61, 0x20, 0x62, 0x6c, 0x61, 0x6e, 0x64, 0x69, 0x74,
		0x2c, 0x20, 0x76, 0x69, 0x76, 0x65, 0x72, 0x72, 0x61, 0x20, 0x6d, 0x61, 0x73, 0x73, 0x61, 0x20,
		0x65, 0x67, 0x65, 0x74, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75,
		0x72, 0x20, 0x6d, 0x69, 0x2e, 0x20, 0x46, 0x75, 0x73, 0x63, 0x65, 0x20, 0x76, 0x65, 0x6c, 0x20,
		0x6d, 0x6f, 0x6c, 0x65, 0x73, 0x74, 0x69, 0x65, 0x20, 0x65, 0x6c, 0x69, 0x74, 0x2e, 0x20, 0x49,
		0x6e, 0x20, 0x76, 0x6f, 0x6c, 0x75, 0x74, 0x70, 0x61, 0x74, 0x20, 0x61, 0x6c, 0x69, 0x71, 0x75,
		0x65, 0x74, 0x20, 0x64, 0x69, 0x61, 0x6d, 0x2c, 0x20, 0x66, 0x65, 0x75, 0x67, 0x69, 0x61, 0x74,
		0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x6d, 0x61, 0x75,
		0x72, 0x69, 0x73, 0x20, 0x72, 0x75, 0x74, 0x72, 0x75, 0x6d, 0x20, 0x61, 0x2e, 0x20, 0x41, 0x6c,
		0x69, 0x71, 0x75, 0x61, 0x6d, 0x20, 0x65, 0x72, 0x61, 0x74, 0x20, 0x76, 0x6f, 0x6c, 0x75, 0x74,
		0x70, 0x61, 0x74, 0x2e, 0x20, 0x4e, 0x61, 0x6d, 0x20, 0x73, 0x65, 0x6d, 0x20, 0x73, 0x65, 0x6d,
		0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x65, 0x75,
		0x20, 0x65, 0x75, 0x69, 0x73, 0x6d, 0x6f, 0x64, 0x20, 0x61, 0x74, 0x2c, 0x20, 0x63, 0x6f, 0x6d,
		0x6d, 0x6f, 0x64, 0x6f, 0x20, 0x61, 0x74, 0x20, 0x64, 0x75, 0x69, 0x2e, 0x20, 0x49, 0x6e, 0x20,
		0x68, 0x65, 0x6e, 0x64, 0x72, 0x65, 0x72, 0x69, 0x74, 0x20, 0x61, 0x6e, 0x74, 0x65, 0x20, 0x6d,
		0x61, 0x73, 0x73, 0x61, 0x2e, 0x20, 0x53, 0x65, 0x64, 0x20, 0x65, 0x74, 0x20, 0x75, 0x6c, 0x6c,
		0x61, 0x6d, 0x63, 0x6f, 0x72, 0x70, 0x65, 0x72, 0x20, 0x6d, 0x61, 0x67, 0x6e, 0x61, 0x2e, 0x20,
		0x44, 0x75, 0x69, 0x73, 0x20, 0x68, 0x65, 0x6e, 0x64, 0x72, 0x65, 0x72, 0x69, 0x74, 0x20, 0x65,
		0x6c, 0x65, 0x69, 0x66, 0x65, 0x6e, 0x64, 0x20, 0x6c, 0x69, 0x67, 0x75, 0x6c, 0x61, 0x2c, 0x20,
		0x65, 0x67, 0x65, 0x74, 0x20, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x75, 0x6d, 0x20, 0x6f,
		0x72, 0x63, 0x69, 0x2e, 0x20, 0x56, 0x69, 0x76, 0x61, 0x6d, 0x75, 0x73, 0x20, 0x65, 0x6c, 0x69,
		0x74, 0x20, 0x66, 0x65, 0x6c, 0x69, 0x73, 0x2c, 0x20, 0x68, 0x65, 0x6e, 0x64, 0x72, 0x65, 0x72,
		0x69, 0x74, 0x20, 0x6e, 0x65, 0x63, 0x20, 0x64, 0x69, 0x61, 0x6d, 0x20, 0x6d, 0x61, 0x78, 0x69,
		0x6d, 0x75, 0x73, 0x2c, 0x20, 0x66, 0x61, 0x63, 0x69, 0x6c, 0x69, 0x73, 0x69, 0x73, 0x20, 0x66,
		0x61, 0x63, 0x69, 0x6c, 0x69, 0x73, 0x69, 0x73, 0x20, 0x6e, 0x75, 0x6e, 0x63, 0x2e, 0x20, 0x43,
		0x72, 0x61, 0x73, 0x20, 0x6f, 0x72, 0x6e, 0x61, 0x72, 0x65, 0x20, 0x65, 0x6c, 0x69, 0x74, 0x20,
		0x61, 0x20, 0x61, 0x72, 0x63, 0x75, 0x20, 0x73, 0x6f, 0x6c, 0x6c, 0x69, 0x63, 0x69, 0x74, 0x75,
		0x64, 0x69, 0x6e, 0x2c, 0x20, 0x65, 0x67, 0x65, 0x73, 0x74, 0x61, 0x73, 0x20, 0x73, 0x61, 0x67,
		0x69, 0x74, 0x74, 0x69, 0x73, 0x20, 0x6e, 0x65, 0x71, 0x75, 0x65, 0x20, 0x72, 0x68, 0x6f, 0x6e,
		0x63, 0x75, 0x73, 0x2e, 0x20, 0x56, 0x69, 0x76, 0x61, 0x6d, 0x75, 0x73, 0x20, 0x65, 0x74, 0x20,
		0x72, 0x69, 0x73, 0x75, 0x73, 0x20, 0x75, 0x72, 0x6e, 0x61, 0x2e, 0x20, 0x4f, 0x72, 0x63, 0x69,
		0x20, 0x76, 0x61, 0x72, 0x69, 0x75, 0x73, 0x20, 0x6e, 0x61, 0x74, 0x6f, 0x71, 0x75, 0x65, 0x20,
		0x70, 0x65, 0x6e, 0x61, 0x74, 0x69, 0x62, 0x75, 0x73, 0x20, 0x65, 0x74, 0x20, 0x6d, 0x61, 0x67,
		0x6e, 0x69, 0x73, 0x20, 0x64, 0x69, 0x73, 0x20, 0x70, 0x61, 0x72, 0x74, 0x75, 0x72, 0x69, 0x65,
		0x6e, 0x74, 0x20, 0x6d, 0x6f, 0x6e, 0x74, 0x65, 0x73, 0x2c, 0x20, 0x6e, 0x61, 0x73, 0x63, 0x65,
		0x74, 0x75, 0x72, 0x20, 0x72, 0x69, 0x64, 0x69, 0x63, 0x75, 0x6c, 0x75, 0x73, 0x20, 0x6d, 0x75,
		0x73, 0x2e, 0x20, 0x4d, 0x61, 0x65, 0x63, 0x65, 0x6e, 0x61, 0x73, 0x20, 0x74, 0x69, 0x6e, 0x63,
		0x69, 0x64, 0x75, 0x6e, 0x74, 0x20, 0x6c, 0x75, 0x63, 0x74, 0x75, 0x73, 0x20, 0x64, 0x75, 0x69,
		0x2c, 0x20, 0x61, 0x63, 0x20, 0x61, 0x6c, 0x69, 0x71, 0x75, 0x61, 0x6d, 0x20, 0x6e, 0x69, 0x73,
		0x69, 0x20, 0x6c, 0x61, 0x6f, 0x72, 0x65, 0x65, 0x74, 0x20, 0x73, 0x65, 0x64, 0x2e, 0x0a, 0x0a,
		0x4d, 0x6f, 0x72, 0x62, 0x69, 0x20, 0x61, 0x75, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x75, 0x6c, 0x74,
		0x72, 0x69, 0x63, 0x65, 0x73, 0x20, 0x74, 0x65, 0x6c, 0x6c, 0x75, 0x73, 0x2c, 0x20, 0x69, 0x64,
		0x20, 0x74, 0x72, 0x69, 0x73, 0x74, 0x69, 0x71, 0x75, 0x65, 0x20, 0x6f, 0x64, 0x69, 0x6f, 0x20,
		0x69, 0x6d, 0x70, 0x65, 0x72, 0x64, 0x69, 0x65, 0x74, 0x20, 0x6e, 0x6f, 0x6e, 0x2e, 0x20, 0x4d,
		0x61, 0x75, 0x72, 0x69, 0x73, 0x20, 0x65, 0x67, 0x65, 0x74, 0x20, 0x74, 0x65, 0x6d, 0x70, 0x75,
		0x73, 0x20, 0x61, 0x75, 0x67, 0x75, 0x65, 0x2e, 0x20, 0x44, 0x6f, 0x6e, 0x65, 0x63, 0x20, 0x73,
		0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x20, 0x65, 0x6e, 0x69, 0x6d, 0x20, 0x76, 0x69, 0x74,
		0x61, 0x65, 0x20, 0x6e, 0x69, 0x73, 0x6c, 0x20, 0x76, 0x61, 0x72, 0x69, 0x75, 0x73, 0x20, 0x76,
		0x75, 0x6c, 0x70, 0x75, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x20, 0x44, 0x6f, 0x6e, 0x65, 0x63, 0x20,
		0x76, 0x69, 0x74, 0x61, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x67, 0x75, 0x65, 0x20, 0x71, 0x75, 0x61,
		0x6d, 0x2e, 0x20, 0x4d, 0x6f, 0x72, 0x62, 0x69, 0x20, 0x70, 0x72, 0x65, 0x74, 0x69, 0x75, 0x6d,
		0x20, 0x70, 0x68, 0x61, 0x72, 0x65, 0x74, 0x72, 0x61, 0x20, 0x72, 0x69, 0x73, 0x75, 0x73, 0x2c,
		0x20, 0x69, 0x64, 0x20, 0x76, 0x75, 0x6c, 0x70, 0x75, 0x74, 0x61, 0x74, 0x65, 0x20, 0x6c, 0x6f,
		0x72, 0x65, 0x6d, 0x20, 0x67, 0x72, 0x61, 0x76, 0x69, 0x64, 0x61, 0x20, 0x65, 0x75, 0x2e, 0x20,
		0x50, 0x72, 0x6f, 0x69, 0x6e, 0x20, 0x74, 0x65, 0x6d, 0x70, 0x6f, 0x72, 0x20, 0x75, 0x6c, 0x6c,
		0x61, 0x6d, 0x63, 0x6f, 0x72, 0x70, 0x65, 0x72, 0x20, 0x6e, 0x69, 0x73, 0x6c, 0x20, 0x6e, 0x65,
		0x63, 0x20, 0x74, 0x65, 0x6d, 0x70, 0x6f, 0x72, 0x2e, 0x20, 0x4e, 0x75, 0x6c, 0x6c, 0x61, 0x20,
		0x61, 0x6c, 0x69, 0x71, 0x75, 0x65, 0x74, 0x20, 0x71, 0x75, 0x61, 0x6d, 0x20, 0x76, 0x69, 0x76,
		0x65, 0x72, 0x72, 0x61, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x73, 0x6f, 0x64, 0x61, 0x6c,
		0x65, 0x73, 0x2c, 0x20, 0x65, 0x67, 0x65, 0x74, 0x20, 0x6c, 0x61, 0x63, 0x69, 0x6e, 0x69, 0x61,
		0x20, 0x65, 0x78, 0x2e, 0x0a
	};
	char *pkt = bytes; 

	/* Read destination Ethernet address. */
	char buffer[64];
	uint8_t daddr[6];
	FILE *f = fopen("/tmp/daddr", "r");
	if (fgets(buffer, sizeof(buffer), f) == NULL) {
		printf("WARNING, couldn't read destination MAC address\n");
		fclose(f);
		return 0;
	}
	fclose(f);
	sscanf(buffer, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&daddr[0], &daddr[1], &daddr[2],
		&daddr[3], &daddr[4], &daddr[5]);

	/* Read source Ethernet address. */
	uint8_t saddr[6];
	f = fopen("/tmp/saddr", "r");
	if (fgets(buffer, sizeof(buffer), f) == NULL) {
		printf("WARNING, couldn't read source MAC address\n");
		fclose(f);
		return 0;
	}
	fclose(f);
	sscanf(buffer, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&saddr[0], &saddr[1], &saddr[2],
		&saddr[3], &saddr[4], &saddr[5]);

	if (strstr(argv[1], "gibps") == NULL && strstr(argv[1], "mibps") == NULL) {
		printf("Did not recognize speed: %s\n", argv[1]);
		return 0;
	}

	char params_path[32];
	unsigned int pkt_size;
	unsigned int delay;
	unsigned int delay_iter;
	unsigned int sleep_time;
	snprintf(params_path, sizeof(params_path), "/home/ubuntu/%s", argv[1]);
	f = fopen(params_path, "r");
	if (fgets(buffer, sizeof(buffer), f) == NULL) {
		printf("WARNING, couldn't read calibrated parameters\n");
		fclose(f);
		return 0;
	}
	fclose(f);
	sscanf(buffer, "%u %u %u %u", &pkt_size, &delay, &delay_iter, &sleep_time);

	/* Put Ethernet addresses in frame. */
	unsigned long long i;
	for (i = 0; i < sizeof(daddr); i++) {
		pkt[i] = daddr[i];
		pkt[i + 6] = saddr[i];
	}

	struct ip *inner_iphdr = (struct ip *)(pkt + 14);

	const unsigned int num_flows = 8000; // total of 16000

	/* Come up with random source addresses. */
	uint32_t arr[num_flows];
	uint16_t ipchk[num_flows];
	uint16_t tcpchk[num_flows];
	srand(time(NULL));
	for (i = 0; i < num_flows; i++) {
		arr[i] = rand();
		inner_iphdr->ip_src.s_addr = arr[i];
		inner_iphdr->ip_sum = 0;
		inner_iphdr->ip_sum = checksum_ip(inner_iphdr);
		ipchk[i] = inner_iphdr->ip_sum;
		tcpchk[i] = checksum_l4(inner_iphdr);
	}
	uint16_t *tcp_cksum = (uint16_t *)(bytes + 50);

	i = 0;
	while (1) {
		int r = rand() % num_flows; 
		inner_iphdr->ip_src.s_addr = arr[r];
		inner_iphdr->ip_sum = ipchk[r];
		*tcp_cksum = tcpchk[r];
		if (sendto(sockfd, pkt, sizeof(bytes), 0,
				(struct sockaddr*)&socket_address,
				sizeof(struct sockaddr_ll)) < 0) {
			printf("Send failed\n");
		}
		if (delay && i % delay_iter == 0)
			usleep(sleep_time);
		i++;
	}

	return 0;
}
