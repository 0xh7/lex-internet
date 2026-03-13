#include "packet_parser.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

static uint16_t
rd16(const uint8_t *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

static uint32_t
rd32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | p[3];
}

int
parse_ethernet(const uint8_t *raw, int len, struct eth_header *out)
{
	if (raw == NULL || out == NULL || len < 14) {
		errno = EINVAL;
		return -1;
	}
	memcpy(out->dst, raw, ETH_ALEN);
	memcpy(out->src, raw + 6, ETH_ALEN);
	out->ethertype = rd16(raw + 12);
	return 14;
}

int
parse_ip(const uint8_t *raw, int len, struct ip_header *out)
{
	int hdr_len;

	if (raw == NULL || out == NULL || len < 20) {
		errno = EINVAL;
		return -1;
	}

	out->version = (raw[0] >> 4) & 0x0f;
	out->ihl = raw[0] & 0x0f;
	/* IHL is stored in 32-bit words. Convert it before checking packet bounds. */
	hdr_len = out->ihl * 4;

	if (out->version != 4 || hdr_len < 20 || hdr_len > len) {
		errno = EINVAL;
		return -1;
	}

	out->tos = raw[1];
	out->total_len = rd16(raw + 2);
	out->id = rd16(raw + 4);
	out->frag_off = rd16(raw + 6);
	out->ttl = raw[8];
	out->protocol = raw[9];
	out->checksum = rd16(raw + 10);
	out->src = rd32(raw + 12);
	out->dst = rd32(raw + 16);

	if (hdr_len > 20) {
		out->options = raw + 20;
		out->options_len = hdr_len - 20;
	} else {
		out->options = NULL;
		out->options_len = 0;
	}

	return hdr_len;
}

int
parse_tcp(const uint8_t *raw, int len, struct tcp_header *out)
{
	int hdr_len;

	if (raw == NULL || out == NULL || len < 20) {
		errno = EINVAL;
		return -1;
	}

	out->src_port = rd16(raw);
	out->dst_port = rd16(raw + 2);
	out->seq = rd32(raw + 4);
	out->ack = rd32(raw + 8);
	out->data_off = (raw[12] >> 4) & 0x0f;
	out->flags = raw[13] & 0x3f;
	out->window = rd16(raw + 14);
	out->checksum = rd16(raw + 16);
	out->urg_ptr = rd16(raw + 18);

	/* TCP uses the same 32-bit word unit for header length. */
	hdr_len = out->data_off * 4;
	if (hdr_len < 20 || hdr_len > len) {
		errno = EINVAL;
		return -1;
	}

	if (hdr_len > 20) {
		out->options = raw + 20;
		out->options_len = hdr_len - 20;
	} else {
		out->options = NULL;
		out->options_len = 0;
	}

	return hdr_len;
}

int
parse_udp(const uint8_t *raw, int len, struct udp_header *out)
{
	if (raw == NULL || out == NULL || len < 8) {
		errno = EINVAL;
		return -1;
	}

	out->src_port = rd16(raw);
	out->dst_port = rd16(raw + 2);
	out->length = rd16(raw + 4);
	out->checksum = rd16(raw + 6);

	if (out->length < 8 || out->length > (uint16_t)len) {
		errno = EINVAL;
		return -1;
	}

	return 8;
}

int
parse_icmp(const uint8_t *raw, int len, struct icmp_header *out)
{
	if (raw == NULL || out == NULL || len < 8) {
		errno = EINVAL;
		return -1;
	}

	out->type = raw[0];
	out->code = raw[1];
	out->checksum = rd16(raw + 2);
	out->rest = rd32(raw + 4);

	return 8;
}

int
parse_arp(const uint8_t *raw, int len, struct arp_header *out)
{
	if (raw == NULL || out == NULL || len < 28) {
		errno = EINVAL;
		return -1;
	}

	out->hw_type = rd16(raw);
	out->proto_type = rd16(raw + 2);
	out->hw_len = raw[4];
	out->proto_len = raw[5];
	out->opcode = rd16(raw + 6);

	if (out->hw_len != 6 || out->proto_len != 4) {
		errno = ENOTSUP;
		return -1;
	}

	memcpy(out->sender_mac, raw + 8, 6);
	out->sender_ip = rd32(raw + 14);
	memcpy(out->target_mac, raw + 18, 6);
	out->target_ip = rd32(raw + 24);

	return 28;
}

void
dump_packet(const uint8_t *raw, int len)
{
	int i;

	if (raw == NULL || len <= 0)
		return;

	for (i = 0; i < len; i++) {
		if (i > 0 && (i % 16) == 0)
			printf("\n");
		else if (i > 0 && (i % 8) == 0)
			printf(" ");
		printf("%02x ", raw[i]);
	}
	printf("\n");
}

const char *
proto_name(uint8_t proto)
{
	switch (proto) {
	case 1:  return "ICMP";
	case 2:  return "IGMP";
	case 6:  return "TCP";
	case 17: return "UDP";
	case 41: return "IPv6";
	case 47: return "GRE";
	case 50: return "ESP";
	case 51: return "AH";
	case 58: return "ICMPv6";
	case 89: return "OSPF";
	case 132: return "SCTP";
	default: return "unknown";
	}
}
