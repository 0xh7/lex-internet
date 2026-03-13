#pragma once

#include <stdint.h>
#include "../raw_socket/raw_socket.h"

#define ARP_CACHE_SIZE	64
#define ARP_TIMEOUT_SEC	300

struct arp_entry {
	uint32_t	ip;
	uint8_t		mac[6];
	int		valid;
	long		timestamp;
};

struct arp_cache {
	struct arp_entry	entries[ARP_CACHE_SIZE];
	int			count;
};

void arp_cache_init(struct arp_cache *cache);
int arp_cache_lookup(struct arp_cache *cache, uint32_t ip, uint8_t *mac_out);
void arp_cache_insert(struct arp_cache *cache, uint32_t ip, const uint8_t *mac);

int arp_request(raw_socket_t sock, uint32_t target_ip, const uint8_t *src_mac,
		uint32_t src_ip, uint8_t *dst_mac);
int arp_reply(raw_socket_t sock, const uint8_t *dst_mac, uint32_t dst_ip,
	      const uint8_t *src_mac, uint32_t src_ip);
int arp_resolve(const char *iface, uint32_t target_ip, uint8_t *mac_out);
