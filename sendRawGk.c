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

static void
checksum_l4(uint8_t *data)
{
	int hlen, plen, proto, csum_offset;
	uint16_t csum;

	if ((data[14] & 0xf0) != 0x40)
		return; /* not IPv4 */
	hlen = (data[14] & 0x0f) * 4;
	plen = (data[16] << 8 | data[17]) - hlen;
	proto = data[23];

	switch (proto) {
	case PROTO_TCP:
		csum_offset = 16;
		break;
	case PROTO_UDP:
		csum_offset = 6;
		break;
	default:
		return;
	}

	if (plen < csum_offset+2)
		return;

	data[14 + hlen + csum_offset]   = 0;
	data[14 + hlen + csum_offset+1] = 0;
	csum = net_checksum_tcpudp(plen, proto,
		data + 14 + 12, data + 14 + hlen);
	data[14 + hlen + csum_offset]   = csum >> 8;
	data[14 + hlen + csum_offset + 1] = csum & 0xff;
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

	char bytes[2048] = {
		/* Ethernet header. */
		0x06, 0xa3, 0xa0, 0x16, 0x1f, 0x86, 0x06, 0xdb, 0xde, 0xb0, 0xbb, 0xd0, 0x08, 0x00,
		/* Outer IP header. */
		0x45, 0x00, 0x04, 0x33, 0x00, 0x00, 0x00, 0x00, 0x40, 0x04, 0x1c, 0xff, 0xac, 0x1f, 0x00, 0x5f,
		0xac, 0x1f, 0x01, 0x2b,
		/* Inner IP header. */
		0x45, 0x00, 0x04, 0x1f, 0x9c, 0x16, 0x40, 0x00, 0x40, 0x11, 0x3e, 0x52, 0xac, 0x1f, 0x00, 0x5f,
		0xac, 0x1f, 0x03, 0xc8,
		/* UDP header. */
		0xbf, 0x07, 0x1f, 0x90, 0x04, 0x0b, 0xcc, 0xec
	};
	size_t header_len = 14 + 20 + 20 + 8;

	/* Read in data from file. */
	char *data = bytes + header_len;
	FILE *fp = fopen("text.txt", "r");
	size_t new_len;
	if (fp != NULL) {
		new_len = fread(data, sizeof(char),
			sizeof(bytes) - header_len, fp) + header_len;
		if (ferror(fp) != 0) {
			fputs("Error reading file", stderr);
		}
		fclose(fp);
	}
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

	/* Come up with random source addresses. */
	uint32_t arr[1000];
	srand(time(NULL));
	for (i = 0; i < 1000; i++) {
		arr[i] = rand();
	}

	struct ip *iphdr = (struct ip *)(pkt + 34);
	i = 0;
	while (1) {
		iphdr->ip_src.s_addr = arr[rand() % 1000];
		iphdr->ip_sum = 0;
		iphdr->ip_sum = checksum_ip(iphdr);
		checksum_l4((uint8_t *)pkt);
		if (sendto(sockfd, pkt, new_len, 0,
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
