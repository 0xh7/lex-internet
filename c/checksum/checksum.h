#pragma once

#include <stdint.h>

uint32_t ones_complement_sum(const void *buf, int len, uint32_t initial);
uint16_t ip_checksum(const void *buf, int len);
uint16_t tcp_checksum(uint32_t src, uint32_t dst, const uint8_t *tcp_seg, int len);
uint16_t udp_checksum(uint32_t src, uint32_t dst, const uint8_t *udp_seg, int len);