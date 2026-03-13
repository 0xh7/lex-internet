#include "arp.h"
#include "../raw_socket/raw_socket.h"
#include "../packet_parser/packet_parser.h"

#include <string.h>
#include <errno.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdlib.h>
#else
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/select.h>
#endif

#define ARP_OP_REQUEST	1
#define ARP_OP_REPLY	2
#define HW_ETHERNET	1

static const uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void
arp_cache_init(struct arp_cache *cache)
{
	if (cache == NULL)
		return;
	memset(cache, 0, sizeof(*cache));
}

int
arp_cache_lookup(struct arp_cache *cache, uint32_t ip, uint8_t *mac_out)
{
	long now;
	int i;

	if (cache == NULL || mac_out == NULL)
		return -1;

	now = (long)time(NULL);

	for (i = 0; i < cache->count; i++) {
		if (!cache->entries[i].valid)
			continue;
		if (cache->entries[i].ip != ip)
			continue;
		if (now - cache->entries[i].timestamp > ARP_TIMEOUT_SEC) {
			cache->entries[i].valid = 0;
			continue;
		}
		memcpy(mac_out, cache->entries[i].mac, 6);
		return 0;
	}
	return -1;
}

void
arp_cache_insert(struct arp_cache *cache, uint32_t ip, const uint8_t *mac)
{
	int slot = -1;

	if (cache == NULL || mac == NULL)
		return;
	long oldest = 0;
	int oldest_idx = 0;
	int i;

	/* Reuse an existing slot, otherwise take a free one, otherwise evict the oldest entry. */
	for (i = 0; i < cache->count; i++) {
		if (cache->entries[i].ip == ip) {
			slot = i;
			break;
		}
		if (!cache->entries[i].valid) {
			slot = i;
			break;
		}
		if (oldest == 0 || cache->entries[i].timestamp < oldest) {
			oldest = cache->entries[i].timestamp;
			oldest_idx = i;
		}
	}

	if (slot < 0) {
		if (cache->count < ARP_CACHE_SIZE) {
			slot = cache->count++;
		} else {
			slot = oldest_idx;
		}
	}

	cache->entries[slot].ip = ip;
	memcpy(cache->entries[slot].mac, mac, 6);
	cache->entries[slot].valid = 1;
	cache->entries[slot].timestamp = (long)time(NULL);
}

static void
wr16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

static void
wr32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

static int
build_arp_packet(uint8_t *pkt, uint16_t op,
		 const uint8_t *sender_mac, uint32_t sender_ip,
		 const uint8_t *target_mac, uint32_t target_ip)
{
	if (op == ARP_OP_REQUEST)
		memcpy(pkt, broadcast_mac, 6);
	else
		memcpy(pkt, target_mac, 6);
	memcpy(pkt + 6, sender_mac, 6);
	wr16(pkt + 12, ETH_P_ARP);

	wr16(pkt + 14, HW_ETHERNET);
	wr16(pkt + 16, ETH_P_IP);
	pkt[18] = 6;
	pkt[19] = 4;
	wr16(pkt + 20, op);
	memcpy(pkt + 22, sender_mac, 6);
	wr32(pkt + 28, sender_ip);
	memcpy(pkt + 32, target_mac, 6);
	wr32(pkt + 38, target_ip);

	return 42;
}

int
arp_request(raw_socket_t sock, uint32_t target_ip, const uint8_t *src_mac,
	    uint32_t src_ip, uint8_t *dst_mac)
{
	uint8_t pkt[42];
	uint8_t recv_buf[1500];
	struct eth_header eth;
	struct arp_header arp;
	struct timeval tv;
	fd_set fds;
	int pktlen, n, attempts;

	static const uint8_t zero_mac[6] = {0};

	pktlen = build_arp_packet(pkt, ARP_OP_REQUEST,
				  src_mac, src_ip, zero_mac, target_ip);

	for (attempts = 0; attempts < 3; attempts++) {
		if (raw_socket_send(sock, pkt, pktlen, 0xffffffff) < 0)
			return -1;

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(sock, &fds);

		if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0)
			continue;

		n = raw_socket_recv(sock, recv_buf, sizeof(recv_buf));
		if (n < 42)
			continue;

		/* Ignore unrelated ARP traffic and stop on the first reply for the target IP. */
		if (parse_ethernet(recv_buf, n, &eth) < 0)
			continue;
		if (eth.ethertype != ETH_P_ARP)
			continue;
		if (parse_arp(recv_buf + 14, n - 14, &arp) < 0)
			continue;
		if (arp.opcode != ARP_OP_REPLY)
			continue;
		if (arp.sender_ip != target_ip)
			continue;

		memcpy(dst_mac, arp.sender_mac, 6);
		return 0;
	}

	errno = ETIMEDOUT;
	return -1;
}

int
arp_reply(raw_socket_t sock, const uint8_t *dst_mac, uint32_t dst_ip,
	  const uint8_t *src_mac, uint32_t src_ip)
{
	uint8_t pkt[42];
	int pktlen;

	pktlen = build_arp_packet(pkt, ARP_OP_REPLY,
				  src_mac, src_ip, dst_mac, dst_ip);

	if (raw_socket_send(sock, pkt, pktlen, dst_ip) < 0)
		return -1;

	return 0;
}

static int
get_iface_mac(const char *iface, uint8_t *mac_out)
{
#ifdef _WIN32
	/* On Windows, use GetAdaptersAddresses to find the adapter whose
	   unicast address matches the IP string supplied in @iface. */
	ULONG family = AF_INET;
	ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
	ULONG bufsz = 15000;
	IP_ADAPTER_ADDRESSES *addrs = NULL, *cur;
	struct in_addr want_addr;
	DWORD ret;

	if (inet_pton(AF_INET, iface, &want_addr) != 1)
		return -1;

	addrs = (IP_ADAPTER_ADDRESSES *)malloc(bufsz);
	if (addrs == NULL)
		return -1;

	ret = GetAdaptersAddresses(family, flags, NULL, addrs, &bufsz);
	if (ret == ERROR_BUFFER_OVERFLOW) {
		free(addrs);
		addrs = (IP_ADAPTER_ADDRESSES *)malloc(bufsz);
		if (addrs == NULL)
			return -1;
		ret = GetAdaptersAddresses(family, flags, NULL, addrs, &bufsz);
	}
	if (ret != NO_ERROR) {
		free(addrs);
		return -1;
	}

	for (cur = addrs; cur != NULL; cur = cur->Next) {
		IP_ADAPTER_UNICAST_ADDRESS *uni;
		if (cur->PhysicalAddressLength != 6)
			continue;
		for (uni = cur->FirstUnicastAddress; uni != NULL; uni = uni->Next) {
			struct sockaddr_in *sa = (struct sockaddr_in *)uni->Address.lpSockaddr;
			if (sa->sin_family != AF_INET)
				continue;
			if (sa->sin_addr.s_addr == want_addr.s_addr) {
				memcpy(mac_out, cur->PhysicalAddress, 6);
				free(addrs);
				return 0;
			}
		}
	}
	free(addrs);
	return -1;
#else
	/* On Linux/UNIX, use SIOCGIFHWADDR via ioctl.  If @iface looks like an
	   IP address rather than a device name, iterate all interfaces to find
	   the one that owns that address. */
	struct ifreq ifr;

	if (strchr(iface, '.') != NULL || strchr(iface, ':') != NULL) {
		/* iface is an IP string – find the matching device name */
		struct ifconf ifc;
		char ifcbuf[4096];
		struct in_addr want_addr;
		int tmpsock, i;

		if (inet_pton(AF_INET, iface, &want_addr) != 1)
			return -1;

		tmpsock = socket(AF_INET, SOCK_DGRAM, 0);
		if (tmpsock < 0)
			return -1;

		ifc.ifc_len = sizeof(ifcbuf);
		ifc.ifc_buf = ifcbuf;
		if (ioctl(tmpsock, SIOCGIFCONF, &ifc) < 0) {
			close(tmpsock);
			return -1;
		}

		for (i = 0; i < (int)(ifc.ifc_len / sizeof(struct ifreq)); i++) {
			struct sockaddr_in *sa = (struct sockaddr_in *)&ifc.ifc_req[i].ifr_addr;
			if (sa->sin_family != AF_INET)
				continue;
			if (sa->sin_addr.s_addr != want_addr.s_addr)
				continue;

			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, ifc.ifc_req[i].ifr_name, IFNAMSIZ - 1);
			if (ioctl(tmpsock, SIOCGIFHWADDR, &ifr) == 0) {
				memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
				close(tmpsock);
				return 0;
			}
		}
		close(tmpsock);
		return -1;
	}

	/* iface is a device name – direct lookup */
	int tmpsock = socket(AF_INET, SOCK_DGRAM, 0);
	if (tmpsock < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	if (ioctl(tmpsock, SIOCGIFHWADDR, &ifr) < 0) {
		close(tmpsock);
		return -1;
	}
	memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
	close(tmpsock);
	return 0;
#endif
}

#ifdef _WIN32
static INIT_ONCE arp_init_once = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION arp_lock;

static BOOL CALLBACK arp_lock_init_cb(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
	(void)once; (void)param; (void)ctx;
	InitializeCriticalSection(&arp_lock);
	return TRUE;
}

static void arp_lock_init(void)
{
	InitOnceExecuteOnce(&arp_init_once, arp_lock_init_cb, NULL, NULL);
}
#define ARP_LOCK()   do { arp_lock_init(); EnterCriticalSection(&arp_lock); } while(0)
#define ARP_UNLOCK() LeaveCriticalSection(&arp_lock)
#else
#include <pthread.h>
static pthread_mutex_t arp_lock = PTHREAD_MUTEX_INITIALIZER;
#define ARP_LOCK()   pthread_mutex_lock(&arp_lock)
#define ARP_UNLOCK() pthread_mutex_unlock(&arp_lock)
#endif

int
arp_resolve(const char *iface, uint32_t target_ip, uint8_t *mac_out)
{
	static struct arp_cache cache;
	static int cache_inited;
	raw_socket_t sock;
	int ret;

	uint8_t src_mac[6] = {0};
	uint32_t src_ip = 0;
	struct in_addr parsed_addr;

	if (iface == NULL || mac_out == NULL) {
		errno = EINVAL;
		return -1;
	}

	/* Parse the interface address to use as source IP in ARP requests */
	if (inet_pton(AF_INET, iface, &parsed_addr) == 1)
		src_ip = ntohl(parsed_addr.s_addr);

	/* Obtain the real MAC address of the local interface */
	if (get_iface_mac(iface, src_mac) < 0) {
		errno = ENODEV;
		return -1;
	}

	ARP_LOCK();

	if (!cache_inited) {
		arp_cache_init(&cache);
		cache_inited = 1;
	}

	if (arp_cache_lookup(&cache, target_ip, mac_out) == 0) {
		ARP_UNLOCK();
		return 0;
	}

	ARP_UNLOCK();

	sock = raw_socket_open(0);
	if (sock == RAW_SOCKET_INVALID)
		return -1;

	if (raw_socket_bind(sock, iface) < 0) {
		raw_socket_close(sock);
		return -1;
	}

	ret = arp_request(sock, target_ip, src_mac, src_ip, mac_out);

	ARP_LOCK();
	if (ret == 0)
		arp_cache_insert(&cache, target_ip, mac_out);
	ARP_UNLOCK();

	raw_socket_close(sock);
	return ret;
}
