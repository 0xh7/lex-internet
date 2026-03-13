#include "checksum.h"
#include <string.h>

uint32_t
ones_complement_sum(const void *buf, int len, uint32_t initial)
{
	const uint8_t *p = buf;
	uint32_t sum = initial;
	int i;

	for (i = 0; i + 1 < len; i += 2)
		sum += (uint16_t)(p[i] << 8 | p[i + 1]);

	if (len & 1)
		sum += p[len - 1] << 8;

	return sum;
}

static uint16_t
fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

uint16_t
ip_checksum(const void *buf, int len)
{
	return fold(ones_complement_sum(buf, len, 0));
}

static uint16_t
transport_checksum(uint32_t src, uint32_t dst, uint8_t proto,
		   const uint8_t *seg, int len)
{
	uint8_t pseudo[12];
	uint32_t sum;

	pseudo[0] = src >> 24;
	pseudo[1] = src >> 16;
	pseudo[2] = src >> 8;
	pseudo[3] = src;
	pseudo[4] = dst >> 24;
	pseudo[5] = dst >> 16;
	pseudo[6] = dst >> 8;
	pseudo[7] = dst;
	pseudo[8] = 0;
	pseudo[9] = proto;
	pseudo[10] = (uint8_t)((len >> 8) & 0xff);
	pseudo[11] = (uint8_t)(len & 0xff);

	sum = ones_complement_sum(pseudo, 12, 0);
	sum = ones_complement_sum(seg, len, sum);
	return fold(sum);
}

uint16_t
tcp_checksum(uint32_t src, uint32_t dst, const uint8_t *tcp_seg, int len)
{
	return transport_checksum(src, dst, 6, tcp_seg, len);
}

uint16_t
udp_checksum(uint32_t src, uint32_t dst, const uint8_t *udp_seg, int len)
{
	uint16_t cksum = transport_checksum(src, dst, 17, udp_seg, len);
	if (cksum == 0)
		cksum = 0xffff;
	return cksum;
}
