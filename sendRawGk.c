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
#include <unistd.h>
#include <sys/types.h>

#define MY_DEST_MAC0	0x00
#define MY_DEST_MAC1	0x00
#define MY_DEST_MAC2	0x00
#define MY_DEST_MAC3	0x00
#define MY_DEST_MAC4	0x00
#define MY_DEST_MAC5	0x00

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

	cpu_set_t set;
	int cpu_id = atoi(argv[1]);
	CPU_SET(cpu_id, &set);

	if (sched_setaffinity(getpid(), sizeof(set), &set) == -1) {
		perror("Failed to call sched_setaffinity()");
		return -1;
	}

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, DEFAULT_IF, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, DEFAULT_IF, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = MY_DEST_MAC0;
	socket_address.sll_addr[1] = MY_DEST_MAC1;
	socket_address.sll_addr[2] = MY_DEST_MAC2;
	socket_address.sll_addr[3] = MY_DEST_MAC3;
	socket_address.sll_addr[4] = MY_DEST_MAC4;
	socket_address.sll_addr[5] = MY_DEST_MAC5;

	/* 256 + 14 + 20 + 20 + 8. */
	char bytes[319] = {
0x06, 0x1c, 0x43, 0xd6, 0xd1, 0x8a, 0x06, 0xbf, 0xe8, 0x19, 0xb3, 0xa4, 0x08, 0x00, 0x45, 0x00,
0x01, 0x31, 0x00, 0x00, 0x00, 0x00, 0x40, 0x04, 0x20, 0x01, 0xac, 0x1f, 0x00, 0x5f, 0xac, 0x1f,
0x01, 0x2b, 0x45, 0x00, 0x01, 0x1d, 0x52, 0x3b, 0x40, 0x00, 0x40, 0x11, 0x8b, 0x2f, 0xac, 0x1f,
0x00, 0x5f, 0xac, 0x1f, 0x03, 0xc8, 0xc4, 0xd0, 0x1f, 0x90, 0x01, 0x09, 0x7f, 0x1b, 0x4c, 0x6f,
0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72, 0x20,
0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63,
0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69, 0x73, 0x63, 0x69, 0x6e, 0x67,
0x20, 0x65, 0x6c, 0x69, 0x74, 0x2e, 0x20, 0x4e, 0x75, 0x6e, 0x63, 0x20, 0x73, 0x63, 0x65, 0x6c,
0x65, 0x72, 0x69, 0x73, 0x71, 0x75, 0x65, 0x20, 0x65, 0x73, 0x74, 0x20, 0x69, 0x64, 0x20, 0x76,
0x65, 0x6c, 0x69, 0x74, 0x20, 0x6d, 0x61, 0x74, 0x74, 0x69, 0x73, 0x2c, 0x20, 0x61, 0x74, 0x20,
0x74, 0x69, 0x6e, 0x63, 0x69, 0x64, 0x75, 0x6e, 0x74, 0x20, 0x75, 0x72, 0x6e, 0x61, 0x20, 0x72,
0x68, 0x6f, 0x6e, 0x63, 0x75, 0x73, 0x2e, 0x20, 0x4d, 0x61, 0x65, 0x63, 0x65, 0x6e, 0x61, 0x73,
0x20, 0x6c, 0x75, 0x63, 0x74, 0x75, 0x73, 0x20, 0x6d, 0x61, 0x74, 0x74, 0x69, 0x73, 0x20, 0x74,
0x69, 0x6e, 0x63, 0x69, 0x64, 0x75, 0x6e, 0x74, 0x2e, 0x20, 0x50, 0x68, 0x61, 0x73, 0x65, 0x6c,
0x6c, 0x75, 0x73, 0x20, 0x6c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x72, 0x69, 0x73, 0x75, 0x73, 0x2c,
0x20, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x75, 0x6d, 0x20, 0x73, 0x69, 0x74, 0x20, 0x61,
0x6d, 0x65, 0x74, 0x20, 0x6f, 0x64, 0x69, 0x6f, 0x20, 0x73, 0x65, 0x64, 0x2c, 0x20, 0x65, 0x67,
0x65, 0x73, 0x74, 0x61, 0x73, 0x20, 0x70, 0x6f, 0x73, 0x75, 0x65, 0x72, 0x65, 0x20, 0x6c, 0x61,
0x63, 0x75, 0x73, 0x2e, 0x20, 0x4e, 0x75, 0x6c, 0x6c, 0x61, 0x20, 0x76, 0x65, 0x6c, 0x69, 0x74,
0x20, 0x6e, 0x65, 0x71, 0x75, 0x65, 0x20, 0x73, 0x61, 0x70, 0x69, 0x65, 0x6e, 0x2e, 0x0a
	};

	/* 512 + 14 + 20 + 20 + 8. */
	char bytes2[575] = {
0x06, 0x1c, 0x43, 0xd6, 0xd1, 0x8a, 0x06, 0xbf, 0xe8, 0x19, 0xb3, 0xa4, 0x08, 0x00, 0x45, 0x00,
0x02, 0x31, 0x00, 0x00, 0x00, 0x00, 0x40, 0x04, 0x1f, 0x01, 0xac, 0x1f, 0x00, 0x5f, 0xac, 0x1f,
0x01, 0x2b, 0x45, 0x00, 0x02, 0x1d, 0x7a, 0x61, 0x40, 0x00, 0x40, 0x11, 0x62, 0x09, 0xac, 0x1f,
0x00, 0x5f, 0xac, 0x1f, 0x03, 0xc8, 0xc1, 0x0e, 0x1f, 0x90, 0x02, 0x09, 0xe6, 0x9e, 0x4c, 0x6f,
0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72, 0x20,
0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63,
0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69, 0x73, 0x63, 0x69, 0x6e, 0x67,
0x20, 0x65, 0x6c, 0x69, 0x74, 0x2e, 0x20, 0x56, 0x65, 0x73, 0x74, 0x69, 0x62, 0x75, 0x6c, 0x75,
0x6d, 0x20, 0x6d, 0x6f, 0x6c, 0x6c, 0x69, 0x73, 0x20, 0x61, 0x63, 0x20, 0x6e, 0x75, 0x6e, 0x63,
0x20, 0x61, 0x74, 0x20, 0x72, 0x75, 0x74, 0x72, 0x75, 0x6d, 0x2e, 0x20, 0x4d, 0x6f, 0x72, 0x62,
0x69, 0x20, 0x61, 0x75, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x76, 0x65, 0x6c, 0x69, 0x74, 0x20, 0x65,
0x67, 0x65, 0x74, 0x20, 0x6d, 0x61, 0x67, 0x6e, 0x61, 0x20, 0x75, 0x6c, 0x6c, 0x61, 0x6d, 0x63,
0x6f, 0x72, 0x70, 0x65, 0x72, 0x2c, 0x20, 0x61, 0x74, 0x20, 0x68, 0x65, 0x6e, 0x64, 0x72, 0x65,
0x72, 0x69, 0x74, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x74, 0x69, 0x6e, 0x63, 0x69, 0x64,
0x75, 0x6e, 0x74, 0x2e, 0x20, 0x44, 0x6f, 0x6e, 0x65, 0x63, 0x20, 0x73, 0x75, 0x73, 0x63, 0x69,
0x70, 0x69, 0x74, 0x20, 0x6d, 0x61, 0x67, 0x6e, 0x61, 0x20, 0x6f, 0x64, 0x69, 0x6f, 0x2e, 0x20,
0x49, 0x6e, 0x74, 0x65, 0x67, 0x65, 0x72, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72, 0x20, 0x71, 0x75,
0x61, 0x6d, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x64, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x75, 0x6d, 0x20,
0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x20, 0x6f, 0x64, 0x69, 0x6f, 0x20, 0x6e, 0x65,
0x63, 0x2c, 0x20, 0x6c, 0x61, 0x63, 0x69, 0x6e, 0x69, 0x61, 0x20, 0x65, 0x75, 0x69, 0x73, 0x6d,
0x6f, 0x64, 0x20, 0x6c, 0x69, 0x67, 0x75, 0x6c, 0x61, 0x2e, 0x20, 0x43, 0x72, 0x61, 0x73, 0x20,
0x65, 0x6e, 0x69, 0x6d, 0x20, 0x65, 0x6e, 0x69, 0x6d, 0x2c, 0x20, 0x70, 0x65, 0x6c, 0x6c, 0x65,
0x6e, 0x74, 0x65, 0x73, 0x71, 0x75, 0x65, 0x20, 0x71, 0x75, 0x69, 0x73, 0x20, 0x63, 0x75, 0x72,
0x73, 0x75, 0x73, 0x20, 0x69, 0x6e, 0x2c, 0x20, 0x76, 0x65, 0x6e, 0x65, 0x6e, 0x61, 0x74, 0x69,
0x73, 0x20, 0x65, 0x75, 0x20, 0x65, 0x6e, 0x69, 0x6d, 0x2e, 0x20, 0x4d, 0x61, 0x65, 0x63, 0x65,
0x6e, 0x61, 0x73, 0x20, 0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x20, 0x6c, 0x65, 0x6f,
0x20, 0x69, 0x64, 0x20, 0x6c, 0x65, 0x6f, 0x20, 0x67, 0x72, 0x61, 0x76, 0x69, 0x64, 0x61, 0x20,
0x61, 0x6c, 0x69, 0x71, 0x75, 0x65, 0x74, 0x2e, 0x20, 0x44, 0x75, 0x69, 0x73, 0x20, 0x74, 0x69,
0x6e, 0x63, 0x69, 0x64, 0x75, 0x6e, 0x74, 0x2c, 0x20, 0x6f, 0x64, 0x69, 0x6f, 0x20, 0x71, 0x75,
0x69, 0x73, 0x20, 0x67, 0x72, 0x61, 0x76, 0x69, 0x64, 0x61, 0x20, 0x66, 0x69, 0x6e, 0x69, 0x62,
0x75, 0x73, 0x2c, 0x20, 0x6c, 0x61, 0x63, 0x75, 0x73, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x61, 0x20,
0x61, 0x63, 0x63, 0x75, 0x6d, 0x73, 0x61, 0x6e, 0x20, 0x6e, 0x75, 0x6e, 0x63, 0x2c, 0x20, 0x61,
0x74, 0x20, 0x6d, 0x6f, 0x6c, 0x6c, 0x69, 0x73, 0x20, 0x6a, 0x75, 0x73, 0x74, 0x6f, 0x20, 0x74,
0x6f, 0x72, 0x74, 0x6f, 0x72, 0x20, 0x6e, 0x65, 0x63, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x61, 0x2e,
0x20, 0x44, 0x6f, 0x6e, 0x65, 0x63, 0x20, 0x6d, 0x6f, 0x6c, 0x65, 0x73, 0x74, 0x69, 0x65, 0x20,
0x73, 0x61, 0x70, 0x69, 0x65, 0x6e, 0x20, 0x76, 0x65, 0x6c, 0x20, 0x6d, 0x69, 0x2e, 0x0a
	};

	/* 768 + 14 + 20 + 20 + 8. */
	char bytes3[833] = {
0x06, 0x1c, 0x43, 0xd6, 0xd1, 0x8a, 0x06, 0xbf, 0xe8, 0x19, 0xb3, 0xa4, 0x08, 0x00, 0x45, 0x00,
0x03, 0x33, 0x00, 0x00, 0x00, 0x00, 0x40, 0x04, 0x1d, 0xff, 0xac, 0x1f, 0x00, 0x5f, 0xac, 0x1f,
0x01, 0x2b, 0x45, 0x00, 0x03, 0x1f, 0xca, 0xca, 0x40, 0x00, 0x40, 0x11, 0x10, 0x9e, 0xac, 0x1f,
0x00, 0x5f, 0xac, 0x1f, 0x03, 0xc8, 0xa8, 0x22, 0x1f, 0x90, 0x03, 0x0b, 0xd2, 0xf2, 0x4c, 0x6f,
0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72, 0x20,
0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63,
0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69, 0x73, 0x63, 0x69, 0x6e, 0x67,
0x20, 0x65, 0x6c, 0x69, 0x74, 0x2e, 0x20, 0x4d, 0x6f, 0x72, 0x62, 0x69, 0x20, 0x6c, 0x61, 0x63,
0x69, 0x6e, 0x69, 0x61, 0x20, 0x6d, 0x61, 0x75, 0x72, 0x69, 0x73, 0x20, 0x65, 0x67, 0x65, 0x74,
0x20, 0x72, 0x68, 0x6f, 0x6e, 0x63, 0x75, 0x73, 0x20, 0x72, 0x75, 0x74, 0x72, 0x75, 0x6d, 0x2e,
0x20, 0x55, 0x74, 0x20, 0x75, 0x6c, 0x6c, 0x61, 0x6d, 0x63, 0x6f, 0x72, 0x70, 0x65, 0x72, 0x20,
0x73, 0x61, 0x70, 0x69, 0x65, 0x6e, 0x20, 0x74, 0x65, 0x6c, 0x6c, 0x75, 0x73, 0x2c, 0x20, 0x6e,
0x65, 0x63, 0x20, 0x73, 0x6f, 0x6c, 0x6c, 0x69, 0x63, 0x69, 0x74, 0x75, 0x64, 0x69, 0x6e, 0x20,
0x61, 0x6e, 0x74, 0x65, 0x20, 0x75, 0x6c, 0x74, 0x72, 0x69, 0x63, 0x69, 0x65, 0x73, 0x20, 0x69,
0x6e, 0x2e, 0x20, 0x46, 0x75, 0x73, 0x63, 0x65, 0x20, 0x73, 0x75, 0x73, 0x63, 0x69, 0x70, 0x69,
0x74, 0x20, 0x73, 0x65, 0x6d, 0x20, 0x76, 0x65, 0x6c, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x61, 0x20,
0x66, 0x65, 0x75, 0x67, 0x69, 0x61, 0x74, 0x2c, 0x20, 0x61, 0x74, 0x20, 0x70, 0x72, 0x65, 0x74,
0x69, 0x75, 0x6d, 0x20, 0x6c, 0x61, 0x63, 0x75, 0x73, 0x20, 0x6d, 0x61, 0x78, 0x69, 0x6d, 0x75,
0x73, 0x2e, 0x20, 0x53, 0x75, 0x73, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x73, 0x73, 0x65, 0x20, 0x70,
0x6c, 0x61, 0x63, 0x65, 0x72, 0x61, 0x74, 0x20, 0x66, 0x65, 0x75, 0x67, 0x69, 0x61, 0x74, 0x20,
0x6d, 0x61, 0x73, 0x73, 0x61, 0x20, 0x76, 0x65, 0x68, 0x69, 0x63, 0x75, 0x6c, 0x61, 0x20, 0x63,
0x6f, 0x6e, 0x73, 0x65, 0x71, 0x75, 0x61, 0x74, 0x2e, 0x20, 0x53, 0x75, 0x73, 0x70, 0x65, 0x6e,
0x64, 0x69, 0x73, 0x73, 0x65, 0x20, 0x76, 0x61, 0x72, 0x69, 0x75, 0x73, 0x20, 0x74, 0x75, 0x72,
0x70, 0x69, 0x73, 0x20, 0x64, 0x69, 0x61, 0x6d, 0x2c, 0x20, 0x65, 0x75, 0x20, 0x6c, 0x61, 0x63,
0x69, 0x6e, 0x69, 0x61, 0x20, 0x74, 0x65, 0x6c, 0x6c, 0x75, 0x73, 0x20, 0x66, 0x65, 0x72, 0x6d,
0x65, 0x6e, 0x74, 0x75, 0x6d, 0x20, 0x76, 0x69, 0x74, 0x61, 0x65, 0x2e, 0x20, 0x53, 0x65, 0x64,
0x20, 0x61, 0x75, 0x67, 0x75, 0x65, 0x20, 0x6a, 0x75, 0x73, 0x74, 0x6f, 0x2c, 0x20, 0x73, 0x75,
0x73, 0x63, 0x69, 0x70, 0x69, 0x74, 0x20, 0x76, 0x69, 0x74, 0x61, 0x65, 0x20, 0x68, 0x65, 0x6e,
0x64, 0x72, 0x65, 0x72, 0x69, 0x74, 0x20, 0x69, 0x64, 0x2c, 0x20, 0x63, 0x75, 0x72, 0x73, 0x75,
0x73, 0x20, 0x69, 0x64, 0x20, 0x61, 0x72, 0x63, 0x75, 0x2e, 0x20, 0x4d, 0x6f, 0x72, 0x62, 0x69,
0x20, 0x66, 0x65, 0x72, 0x6d, 0x65, 0x6e, 0x74, 0x75, 0x6d, 0x20, 0x76, 0x65, 0x6c, 0x69, 0x74,
0x20, 0x6e, 0x6f, 0x6e, 0x20, 0x76, 0x65, 0x6c, 0x69, 0x74, 0x20, 0x65, 0x6c, 0x65, 0x69, 0x66,
0x65, 0x6e, 0x64, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x64, 0x6f, 0x2e, 0x20, 0x53, 0x65, 0x64,
0x20, 0x75, 0x74, 0x20, 0x6e, 0x65, 0x71, 0x75, 0x65, 0x20, 0x6e, 0x6f, 0x6e, 0x20, 0x6f, 0x72,
0x63, 0x69, 0x20, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x72, 0x61, 0x74, 0x20, 0x76, 0x69, 0x76, 0x65,
0x72, 0x72, 0x61, 0x2e, 0x20, 0x4e, 0x75, 0x6c, 0x6c, 0x61, 0x20, 0x6c, 0x61, 0x6f, 0x72, 0x65,
0x65, 0x74, 0x20, 0x6e, 0x69, 0x73, 0x69, 0x20, 0x76, 0x65, 0x6c, 0x20, 0x6c, 0x6f, 0x62, 0x6f,
0x72, 0x74, 0x69, 0x73, 0x20, 0x74, 0x69, 0x6e, 0x63, 0x69, 0x64, 0x75, 0x6e, 0x74, 0x2e, 0x0a,
0x0a, 0x51, 0x75, 0x69, 0x73, 0x71, 0x75, 0x65, 0x20, 0x61, 0x74, 0x20, 0x6e, 0x75, 0x6e, 0x63,
0x20, 0x68, 0x65, 0x6e, 0x64, 0x72, 0x65, 0x72, 0x69, 0x74, 0x2c, 0x20, 0x72, 0x75, 0x74, 0x72,
0x75, 0x6d, 0x20, 0x6e, 0x69, 0x62, 0x68, 0x20, 0x65, 0x74, 0x2c, 0x20, 0x67, 0x72, 0x61, 0x76,
0x69, 0x64, 0x61, 0x20, 0x6e, 0x69, 0x73, 0x69, 0x2e, 0x20, 0x4e, 0x75, 0x6e, 0x63, 0x20, 0x70,
0x6f, 0x73, 0x75, 0x65, 0x72, 0x65, 0x20, 0x70, 0x6f, 0x72, 0x74, 0x74, 0x69, 0x74, 0x6f, 0x72,
0x20, 0x76, 0x65, 0x6c, 0x69, 0x74, 0x2c, 0x20, 0x6e, 0x65, 0x63, 0x20, 0x74, 0x69, 0x6e, 0x63,
0x69, 0x64, 0x75, 0x6e, 0x74, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x61, 0x20, 0x63, 0x6f, 0x6d, 0x6d,
0x6f, 0x64, 0x6f, 0x20, 0x76, 0x69, 0x74, 0x61, 0x65, 0x2e, 0x20, 0x46, 0x75, 0x73, 0x63, 0x65,
0x20, 0x74, 0x6f, 0x72, 0x74, 0x6f, 0x72, 0x20, 0x65, 0x6e, 0x69, 0x6d, 0x2c, 0x20, 0x6d, 0x61,
0x6c, 0x65, 0x73, 0x75, 0x61, 0x64, 0x61, 0x20, 0x6e, 0x65, 0x63, 0x20, 0x6d, 0x69, 0x20, 0x73,
0x65, 0x6d, 0x70, 0x65, 0x72, 0x2c, 0x20, 0x70, 0x72, 0x65, 0x74, 0x69, 0x75, 0x6d, 0x20, 0x73,
0x6f, 0x6c, 0x6c, 0x69, 0x63, 0x69, 0x74, 0x75, 0x64, 0x69, 0x6e, 0x20, 0x64, 0x6f, 0x6c, 0x6f,
0x72, 0x2e, 0x20, 0x49, 0x6e, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x64, 0x6f, 0x20, 0x70, 0x6f,
0x73, 0x75, 0x65, 0x72, 0x65, 0x20, 0x6e, 0x69, 0x73, 0x69, 0x20, 0x71, 0x75, 0x69, 0x73, 0x2e,
0x0a  
	};

	/* 1024 + 14 + 20 + 20 + 8. */
	char bytes4[1089] = {
0x06, 0x1c, 0x43, 0xd6, 0xd1, 0x8a, 0x06, 0xbf, 0xe8, 0x19, 0xb3, 0xa4, 0x08, 0x00, 0x45, 0x00,
0x04, 0x33, 0x00, 0x00, 0x00, 0x00, 0x40, 0x04, 0x1c, 0xff, 0xac, 0x1f, 0x00, 0x5f, 0xac, 0x1f,
0x01, 0x2b, 0x45, 0x00, 0x04, 0x1f, 0x9c, 0x16, 0x40, 0x00, 0x40, 0x11, 0x3e, 0x52, 0xac, 0x1f,
0x00, 0x5f, 0xac, 0x1f, 0x03, 0xc8, 0xbf, 0x07, 0x1f, 0x90, 0x04, 0x0b, 0xcc, 0xec, 0x4c, 0x6f,
0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72, 0x20,
0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63,
0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69, 0x73, 0x63, 0x69, 0x6e, 0x67,
0x20, 0x65, 0x6c, 0x69, 0x74, 0x2e, 0x20, 0x53, 0x65, 0x64, 0x20, 0x66, 0x61, 0x75, 0x63, 0x69,
0x62, 0x75, 0x73, 0x20, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x20, 0x6e, 0x69, 0x73, 0x6c, 0x20, 0x61,
0x74, 0x20, 0x73, 0x63, 0x65, 0x6c, 0x65, 0x72, 0x69, 0x73, 0x71, 0x75, 0x65, 0x2e, 0x20, 0x4d,
0x61, 0x65, 0x63, 0x65, 0x6e, 0x61, 0x73, 0x20, 0x6a, 0x75, 0x73, 0x74, 0x6f, 0x20, 0x6e, 0x65,
0x71, 0x75, 0x65, 0x2c, 0x20, 0x76, 0x6f, 0x6c, 0x75, 0x74, 0x70, 0x61, 0x74, 0x20, 0x6d, 0x61,
0x6c, 0x65, 0x73, 0x75, 0x61, 0x64, 0x61, 0x20, 0x65, 0x78, 0x20, 0x65, 0x67, 0x65, 0x74, 0x2c,
0x20, 0x73, 0x61, 0x67, 0x69, 0x74, 0x74, 0x69, 0x73, 0x20, 0x6d, 0x6f, 0x6c, 0x6c, 0x69, 0x73,
0x20, 0x70, 0x75, 0x72, 0x75, 0x73, 0x2e, 0x20, 0x4d, 0x6f, 0x72, 0x62, 0x69, 0x20, 0x73, 0x69,
0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x20, 0x61, 0x6c, 0x69, 0x71, 0x75, 0x61, 0x6d, 0x20, 0x6f,
0x64, 0x69, 0x6f, 0x2e, 0x20, 0x50, 0x72, 0x61, 0x65, 0x73, 0x65, 0x6e, 0x74, 0x20, 0x61, 0x63,
0x20, 0x6f, 0x72, 0x63, 0x69, 0x20, 0x65, 0x78, 0x2e, 0x20, 0x56, 0x69, 0x76, 0x61, 0x6d, 0x75,
0x73, 0x20, 0x61, 0x63, 0x20, 0x6c, 0x61, 0x63, 0x69, 0x6e, 0x69, 0x61, 0x20, 0x76, 0x65, 0x6c,
0x69, 0x74, 0x2e, 0x20, 0x50, 0x65, 0x6c, 0x6c, 0x65, 0x6e, 0x74, 0x65, 0x73, 0x71, 0x75, 0x65,
0x20, 0x61, 0x20, 0x74, 0x69, 0x6e, 0x63, 0x69, 0x64, 0x75, 0x6e, 0x74, 0x20, 0x6d, 0x65, 0x74,
0x75, 0x73, 0x2c, 0x20, 0x6e, 0x6f, 0x6e, 0x20, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x20, 0x64, 0x6f,
0x6c, 0x6f, 0x72, 0x2e, 0x20, 0x4e, 0x61, 0x6d, 0x20, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x72, 0x61,
0x74, 0x20, 0x6d, 0x61, 0x75, 0x72, 0x69, 0x73, 0x20, 0x72, 0x69, 0x73, 0x75, 0x73, 0x2c, 0x20,
0x65, 0x74, 0x20, 0x6d, 0x61, 0x74, 0x74, 0x69, 0x73, 0x20, 0x6f, 0x72, 0x63, 0x69, 0x20, 0x70,
0x6c, 0x61, 0x63, 0x65, 0x72, 0x61, 0x74, 0x20, 0x6e, 0x6f, 0x6e, 0x2e, 0x20, 0x4d, 0x61, 0x65,
0x63, 0x65, 0x6e, 0x61, 0x73, 0x20, 0x64, 0x69, 0x63, 0x74, 0x75, 0x6d, 0x20, 0x65, 0x78, 0x20,
0x73, 0x65, 0x64, 0x20, 0x70, 0x75, 0x72, 0x75, 0x73, 0x20, 0x70, 0x6f, 0x72, 0x74, 0x74, 0x69,
0x74, 0x6f, 0x72, 0x20, 0x6d, 0x61, 0x6c, 0x65, 0x73, 0x75, 0x61, 0x64, 0x61, 0x2e, 0x20, 0x45,
0x74, 0x69, 0x61, 0x6d, 0x20, 0x75, 0x6c, 0x74, 0x72, 0x69, 0x63, 0x69, 0x65, 0x73, 0x20, 0x70,
0x75, 0x72, 0x75, 0x73, 0x20, 0x75, 0x74, 0x20, 0x61, 0x72, 0x63, 0x75, 0x20, 0x61, 0x6c, 0x69,
0x71, 0x75, 0x65, 0x74, 0x20, 0x73, 0x6f, 0x64, 0x61, 0x6c, 0x65, 0x73, 0x2e, 0x20, 0x53, 0x65,
0x64, 0x20, 0x65, 0x74, 0x20, 0x61, 0x72, 0x63, 0x75, 0x20, 0x61, 0x20, 0x6f, 0x64, 0x69, 0x6f,
0x20, 0x76, 0x75, 0x6c, 0x70, 0x75, 0x74, 0x61, 0x74, 0x65, 0x20, 0x72, 0x68, 0x6f, 0x6e, 0x63,
0x75, 0x73, 0x20, 0x65, 0x74, 0x20, 0x61, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72, 0x2e, 0x0a, 0x0a,
0x41, 0x65, 0x6e, 0x65, 0x61, 0x6e, 0x20, 0x73, 0x75, 0x73, 0x63, 0x69, 0x70, 0x69, 0x74, 0x20,
0x72, 0x69, 0x73, 0x75, 0x73, 0x20, 0x75, 0x6c, 0x6c, 0x61, 0x6d, 0x63, 0x6f, 0x72, 0x70, 0x65,
0x72, 0x20, 0x74, 0x75, 0x72, 0x70, 0x69, 0x73, 0x20, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x64, 0x75,
0x6d, 0x20, 0x6d, 0x61, 0x6c, 0x65, 0x73, 0x75, 0x61, 0x64, 0x61, 0x2e, 0x20, 0x4e, 0x61, 0x6d,
0x20, 0x68, 0x65, 0x6e, 0x64, 0x72, 0x65, 0x72, 0x69, 0x74, 0x20, 0x69, 0x6e, 0x20, 0x6e, 0x69,
0x73, 0x6c, 0x20, 0x76, 0x65, 0x6c, 0x20, 0x73, 0x6f, 0x64, 0x61, 0x6c, 0x65, 0x73, 0x2e, 0x20,
0x55, 0x74, 0x20, 0x74, 0x72, 0x69, 0x73, 0x74, 0x69, 0x71, 0x75, 0x65, 0x20, 0x74, 0x75, 0x72,
0x70, 0x69, 0x73, 0x20, 0x65, 0x6c, 0x69, 0x74, 0x2c, 0x20, 0x61, 0x74, 0x20, 0x70, 0x6f, 0x72,
0x74, 0x61, 0x20, 0x6e, 0x69, 0x73, 0x69, 0x20, 0x68, 0x65, 0x6e, 0x64, 0x72, 0x65, 0x72, 0x69,
0x74, 0x20, 0x76, 0x69, 0x74, 0x61, 0x65, 0x2e, 0x20, 0x53, 0x65, 0x64, 0x20, 0x63, 0x6f, 0x6d,
0x6d, 0x6f, 0x64, 0x6f, 0x20, 0x76, 0x69, 0x74, 0x61, 0x65, 0x20, 0x6a, 0x75, 0x73, 0x74, 0x6f,
0x20, 0x61, 0x20, 0x6c, 0x61, 0x6f, 0x72, 0x65, 0x65, 0x74, 0x2e, 0x20, 0x56, 0x65, 0x73, 0x74,
0x69, 0x62, 0x75, 0x6c, 0x75, 0x6d, 0x20, 0x6d, 0x61, 0x74, 0x74, 0x69, 0x73, 0x20, 0x74, 0x75,
0x72, 0x70, 0x69, 0x73, 0x20, 0x75, 0x74, 0x20, 0x70, 0x6f, 0x72, 0x74, 0x74, 0x69, 0x74, 0x6f,
0x72, 0x20, 0x62, 0x6c, 0x61, 0x6e, 0x64, 0x69, 0x74, 0x2e, 0x20, 0x45, 0x74, 0x69, 0x61, 0x6d,
0x20, 0x73, 0x61, 0x67, 0x69, 0x74, 0x74, 0x69, 0x73, 0x20, 0x74, 0x6f, 0x72, 0x74, 0x6f, 0x72,
0x20, 0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x20, 0x6f, 0x64, 0x69, 0x6f, 0x20, 0x67,
0x72, 0x61, 0x76, 0x69, 0x64, 0x61, 0x2c, 0x20, 0x65, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x76, 0x61,
0x6c, 0x6c, 0x69, 0x73, 0x20, 0x6a, 0x75, 0x73, 0x74, 0x6f, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65,
0x63, 0x74, 0x65, 0x74, 0x75, 0x72, 0x2e, 0x20, 0x55, 0x74, 0x20, 0x61, 0x63, 0x20, 0x6f, 0x64,
0x69, 0x6f, 0x20, 0x61, 0x20, 0x65, 0x78, 0x20, 0x61, 0x63, 0x63, 0x75, 0x6d, 0x73, 0x61, 0x6e,
0x20, 0x69, 0x6d, 0x70, 0x65, 0x72, 0x64, 0x69, 0x65, 0x74, 0x20, 0x76, 0x65, 0x6c, 0x20, 0x65,
0x67, 0x65, 0x74, 0x20, 0x6e, 0x69, 0x73, 0x69, 0x2e, 0x20, 0x4e, 0x75, 0x6c, 0x6c, 0x61, 0x20,
0x69, 0x6e, 0x20, 0x6e, 0x69, 0x62, 0x68, 0x20, 0x61, 0x74, 0x20, 0x6f, 0x72, 0x63, 0x69, 0x20,
0x73, 0x63, 0x65, 0x6c, 0x65, 0x72, 0x69, 0x73, 0x71, 0x75, 0x65, 0x20, 0x61, 0x75, 0x63, 0x74,
0x6f, 0x72, 0x2e, 0x20, 0x50, 0x68, 0x61, 0x73, 0x65, 0x6c, 0x6c, 0x75, 0x73, 0x20, 0x65, 0x67,
0x65, 0x74, 0x20, 0x72, 0x69, 0x73, 0x75, 0x73, 0x20, 0x6c, 0x75, 0x63, 0x74, 0x75, 0x73, 0x2c,
0x20, 0x6d, 0x61, 0x6c, 0x65, 0x73, 0x75, 0x61, 0x64, 0x61, 0x20, 0x73, 0x61, 0x70, 0x69, 0x65,
0x6e, 0x20, 0x76, 0x65, 0x68, 0x69, 0x63, 0x75, 0x6c, 0x61, 0x2c, 0x20, 0x61, 0x63, 0x63, 0x75,
0x6d, 0x73, 0x61, 0x6e, 0x20, 0x6c, 0x61, 0x63, 0x75, 0x73, 0x2e, 0x20, 0x4e, 0x61, 0x6d, 0x20,
0x70, 0x6f, 0x73, 0x75, 0x65, 0x72, 0x65, 0x20, 0x6f, 0x72, 0x6e, 0x61, 0x72, 0x65, 0x20, 0x6f,
0x72, 0x63, 0x69, 0x20, 0x6e, 0x6f, 0x6e, 0x20, 0x66, 0x65, 0x75, 0x67, 0x69, 0x61, 0x74, 0x2e,
0x20, 0x53, 0x65, 0x64, 0x20, 0x6e, 0x6f, 0x6e, 0x20, 0x61, 0x65, 0x6e, 0x65, 0x61, 0x6e, 0x2e,
0x0a    
	};

	struct ip *iphdr = (struct ip *)(bytes + 34);
	struct ip *iphdr2 = (struct ip *)(bytes2 + 34);
	struct ip *iphdr3 = (struct ip *)(bytes3 + 34);
	struct ip *iphdr4 = (struct ip *)(bytes4 + 34);

	uint32_t arr[1000];
	unsigned long long i = 0;
	for (i = 0; i < 1000; i++) {
		arr[i] = rand();
	}

	/* Send packet */
	i = 0;
	int mbps100 = strcmp(argv[2], "100mbps") == 0;
	int mbps500 = strcmp(argv[2], "500mbps") == 0;
	int gbps1 = strcmp(argv[2], "1gbps") == 0;
	int gbps2 = strcmp(argv[2], "2gbps") == 0;
	int gbps3 = strcmp(argv[2], "3gbps") == 0;
	int gbps4 = strcmp(argv[2], "4gbps") == 0;
	int gbps5 = strcmp(argv[2], "5gbps") == 0;
	int gbps6 = strcmp(argv[2], "6gbps") == 0;
	int gbps7 = strcmp(argv[2], "7gbps") == 0;
	int gbps8 = strcmp(argv[2], "8gbps") == 0;
	int gbps9 = strcmp(argv[2], "9gbps") == 0;
	int gbps10 = strcmp(argv[2], "10gbps") == 0;
	while (1) {
		if (mbps100) {
			iphdr->ip_src.s_addr = arr[i % 1000];
			iphdr->ip_sum = 0;
			iphdr->ip_sum = checksum_ip(iphdr);
			checksum_l4((uint8_t *)bytes);
			if (sendto(sockfd, bytes, sizeof(bytes), 0,
					(struct sockaddr*)&socket_address,
					sizeof(struct sockaddr_ll)) < 0) {
				printf("Send failed\n");
			}
			if (i % 4 == 0)
				usleep(25);
		} else if (mbps500) {
			iphdr->ip_src.s_addr = arr[i % 1000];
			iphdr->ip_sum = 0;
			iphdr->ip_sum = checksum_ip(iphdr);
			checksum_l4((uint8_t *)bytes);
			if (sendto(sockfd, bytes, sizeof(bytes), 0,
					(struct sockaddr*)&socket_address,
					sizeof(struct sockaddr_ll)) < 0) {
				printf("Send failed\n");
			}
			if (i % 20 == 0)
				usleep(1);
		} else if (gbps1) {
			iphdr->ip_src.s_addr = arr[i % 1000];
			iphdr->ip_sum = 0;
			iphdr->ip_sum = checksum_ip(iphdr);
			checksum_l4((uint8_t *)bytes);
			if (sendto(sockfd, bytes, sizeof(bytes), 0,
					(struct sockaddr*)&socket_address,
					sizeof(struct sockaddr_ll)) < 0) {
				printf("Send failed\n");
			}
			if (i % 40 == 0)
				usleep(50);
		} else if (gbps2) {
			/* Can only achieve 2 Gbps when run twice. */
			iphdr2->ip_src.s_addr = arr[i % 1000];
			iphdr2->ip_sum = 0;
			iphdr2->ip_sum = checksum_ip(iphdr2);
			checksum_l4((uint8_t *)bytes2);
			if (sendto(sockfd, bytes2, sizeof(bytes2), 0,
					(struct sockaddr*)&socket_address,
					sizeof(struct sockaddr_ll)) < 0) {
				printf("Send failed\n");
			}
			if (i % 200 == 0)
				usleep(450);
		} else if (gbps3) {
			/* Can only achieve 3 Gbps when run three times. */
			iphdr2->ip_src.s_addr = arr[i % 1000];
			iphdr2->ip_sum = 0;
			iphdr2->ip_sum = checksum_ip(iphdr2);
			checksum_l4((uint8_t *)bytes2);
			if (sendto(sockfd, bytes2, sizeof(bytes2), 0,
					(struct sockaddr*)&socket_address,
					sizeof(struct sockaddr_ll)) < 0) {
				printf("Send failed\n");
			}
			if (i % 200 == 0)
				usleep(425);
		} else if (gbps4) {
			/* Can only achieve 4 Gbps when run four times. */
			iphdr2->ip_src.s_addr = arr[i % 1000];
			iphdr2->ip_sum = 0;
			iphdr2->ip_sum = checksum_ip(iphdr2);
			checksum_l4((uint8_t *)bytes2);
			if (sendto(sockfd, bytes2, sizeof(bytes2), 0,
					(struct sockaddr*)&socket_address,
					sizeof(struct sockaddr_ll)) < 0) {
				printf("Send failed\n");
			}
			if (i % 150 == 0)
				usleep(200);
		} else if (gbps5) {
			/* Can only achieve 5 Gbps when run five times. */
			iphdr3->ip_src.s_addr = arr[i % 1000];
			iphdr3->ip_sum = 0;
			iphdr3->ip_sum = checksum_ip(iphdr3);
			checksum_l4((uint8_t *)bytes3);
			if (sendto(sockfd, bytes3, sizeof(bytes3), 0,
					(struct sockaddr*)&socket_address,
					sizeof(struct sockaddr_ll)) < 0) {
				printf("Send failed\n");
			}
			if (i % 200 == 0)
				usleep(675);
		} else if (gbps6) {
			/* Can only achieve 6 Gbps when run six times. */
			iphdr3->ip_src.s_addr = arr[i % 1000];
			iphdr3->ip_sum = 0;
			iphdr3->ip_sum = checksum_ip(iphdr3);
			checksum_l4((uint8_t *)bytes3);
			if (sendto(sockfd, bytes3, sizeof(bytes3), 0,
					(struct sockaddr*)&socket_address,
					sizeof(struct sockaddr_ll)) < 0) {
				printf("Send failed\n");
			}
			if (i % 40 == 0)
				usleep(50);
		} else if (gbps7) {
			/* Can only achieve 7 Gbps when run seven times. */
			iphdr4->ip_src.s_addr = arr[i % 1000];
			iphdr4->ip_sum = 0;
			iphdr4->ip_sum = checksum_ip(iphdr4);
			checksum_l4((uint8_t *)bytes4);
			if (sendto(sockfd, bytes4, sizeof(bytes4), 0,
					(struct sockaddr*)&socket_address,
					sizeof(struct sockaddr_ll)) < 0) {
				printf("Send failed\n");
			}
			if (i % 100 == 0)
				usleep(480);
		} else if (gbps8) {
			/* Can only achieve 8 Gbps when run eight times. */
			iphdr4->ip_src.s_addr = arr[i % 1000];
			iphdr4->ip_sum = 0;
			iphdr4->ip_sum = checksum_ip(iphdr4);
			checksum_l4((uint8_t *)bytes4);
			if (sendto(sockfd, bytes4, sizeof(bytes4), 0,
					(struct sockaddr*)&socket_address,
					sizeof(struct sockaddr_ll)) < 0) {
				printf("Send failed\n");
			}
			if (i % 20 == 0)
				usleep(1);
		} else if (gbps9) {
			/* Can only achieve 9 Gbps when run nine times. */
			iphdr4->ip_src.s_addr = arr[i % 1000];
			iphdr4->ip_sum = 0;
			iphdr4->ip_sum = checksum_ip(iphdr4);
			checksum_l4((uint8_t *)bytes4);
			if (sendto(sockfd, bytes4, sizeof(bytes4), 0,
					(struct sockaddr*)&socket_address,
					sizeof(struct sockaddr_ll)) < 0) {
				printf("Send failed\n");
			}
			if (i % 750 == 0)
				usleep(1);
		} else if (gbps10) {
			/* Can only achieve 10 Gbps when run ten times. */
			iphdr4->ip_src.s_addr = arr[i % 1000];
			iphdr4->ip_sum = 0;
			iphdr4->ip_sum = checksum_ip(iphdr4);
			checksum_l4((uint8_t *)bytes4);
			if (sendto(sockfd, bytes4, sizeof(bytes4), 0,
					(struct sockaddr*)&socket_address,
					sizeof(struct sockaddr_ll)) < 0) {
				printf("Send failed\n");
			}
			//if (i % 150 == 0)
			//	usleep(1);
		}

		i++;
	}

	return 0;
}
