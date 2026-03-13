#pragma once

#include <stdint.h>

#define ETH_ALEN	6
#define ETH_P_IP	0x0800
#define ETH_P_ARP	0x0806
#define ETH_P_IPV6	0x86dd

struct eth_header {
	uint8_t		dst[ETH_ALEN];
	uint8_t		src[ETH_ALEN];
	uint16_t	ethertype;
};

struct ip_header {
	uint8_t		version;
	uint8_t		ihl;
	uint8_t		tos;
	uint16_t	total_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t		ttl;
	uint8_t		protocol;
	uint16_t	checksum;
	uint32_t	src;
	uint32_t	dst;
	int		options_len;
	const uint8_t	*options;
};

struct tcp_header {
	uint16_t	src_port;
	uint16_t	dst_port;
	uint32_t	seq;
	uint32_t	ack;
	uint8_t		data_off;
	uint8_t		flags;
	uint16_t	window;
	uint16_t	checksum;
	uint16_t	urg_ptr;
	int		options_len;
	const uint8_t	*options;
};

#define TCP_FIN		0x01
#define TCP_SYN		0x02
#define TCP_RST		0x04
#define TCP_PSH		0x08
#define TCP_ACK		0x10
#define TCP_URG		0x20

struct udp_header {
	uint16_t	src_port;
	uint16_t	dst_port;
	uint16_t	length;
	uint16_t	checksum;
};

struct icmp_header {
	uint8_t		type;
	uint8_t		code;
	uint16_t	checksum;
	uint32_t	rest;
};

struct arp_header {
	uint16_t	hw_type;
	uint16_t	proto_type;
	uint8_t		hw_len;
	uint8_t		proto_len;
	uint16_t	opcode;
	uint8_t		sender_mac[ETH_ALEN];
	uint32_t	sender_ip;
	uint8_t		target_mac[ETH_ALEN];
	uint32_t	target_ip;
};

int parse_ethernet(const uint8_t *raw, int len, struct eth_header *out);
int parse_ip(const uint8_t *raw, int len, struct ip_header *out);
int parse_tcp(const uint8_t *raw, int len, struct tcp_header *out);
int parse_udp(const uint8_t *raw, int len, struct udp_header *out);
int parse_icmp(const uint8_t *raw, int len, struct icmp_header *out);
int parse_arp(const uint8_t *raw, int len, struct arp_header *out);
void dump_packet(const uint8_t *raw, int len);
const char *proto_name(uint8_t proto);
