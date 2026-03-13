#include "raw_socket.h"

#include <string.h>
#include <errno.h>

#ifdef _WIN32

#include <ws2tcpip.h>
#include <mstcpip.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

static int wsa_started;

int
raw_socket_init(void)
{
	WSADATA wsa;
	if (wsa_started)
		return 0;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		errno = ENETDOWN;
		return -1;
	}
	wsa_started = 1;
	return 0;
}

void
raw_socket_cleanup(void)
{
	if (wsa_started) {
		WSACleanup();
		wsa_started = 0;
	}
}

raw_socket_t
raw_socket_open(int protocol)
{
	SOCKET s;

	if (raw_socket_init() < 0)
		return RAW_SOCKET_INVALID;

	s = socket(AF_INET, SOCK_RAW, protocol);
	if (s == INVALID_SOCKET) {
		errno = EPERM;
		return RAW_SOCKET_INVALID;
	}
	return s;
}

int
raw_socket_bind(raw_socket_t sock, const char *iface)
{
	struct sockaddr_in addr;

	if (iface == NULL || *iface == '\0') {
		errno = EINVAL;
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;

	if (inet_pton(AF_INET, iface, &addr.sin_addr) != 1) {
		errno = EINVAL;
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
		errno = EADDRNOTAVAIL;
		return -1;
	}

	return 0;
}

int
raw_socket_send(raw_socket_t sock, const uint8_t *buf, size_t len, uint32_t dst_ip)
{
	struct sockaddr_in dst;
	int n;

	if (len > INT_MAX) {
		errno = EINVAL;
		return -1;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(dst_ip);

	n = sendto(sock, (const char *)buf, (int)len, 0,
		   (struct sockaddr *)&dst, sizeof(dst));
	if (n == SOCKET_ERROR) {
		errno = EIO;
		return -1;
	}
	return n;
}

int
raw_socket_recv(raw_socket_t sock, uint8_t *buf, size_t maxlen)
{
	int n;
	if (maxlen > INT_MAX)
		maxlen = INT_MAX;
	n = recvfrom(sock, (char *)buf, (int)maxlen, 0, NULL, NULL);
	if (n == SOCKET_ERROR) {
		errno = EIO;
		return -1;
	}
	return n;
}

void
raw_socket_close(raw_socket_t sock)
{
	closesocket(sock);
}

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <limits.h>

#ifndef SSIZE_MAX
#define SSIZE_MAX ((ssize_t)(SIZE_MAX >> 1))
#endif

int
raw_socket_init(void)
{
	return 0;
}

void
raw_socket_cleanup(void)
{
}

raw_socket_t
raw_socket_open(int protocol)
{
	int sock = socket(AF_INET, SOCK_RAW, protocol);
	if (sock < 0)
		return RAW_SOCKET_INVALID;

	int on = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		close(sock);
		return RAW_SOCKET_INVALID;
	}

	return sock;
}

int
raw_socket_bind(raw_socket_t sock, const char *iface)
{
	struct sockaddr_in addr;

	if (iface == NULL || *iface == '\0') {
		errno = EINVAL;
		return -1;
	}

#ifdef SO_BINDTODEVICE
	if (strchr(iface, '.') == NULL && strchr(iface, ':') == NULL) {
		size_t iflen = strlen(iface);
		if (iflen > 0 && iflen < 16) {
			if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
				       iface, (socklen_t)iflen + 1) == 0)
				return 0;
		}
	}
#endif

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (inet_pton(AF_INET, iface, &addr.sin_addr) != 1) {
		errno = EINVAL;
		return -1;
	}
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		return -1;

	return 0;
}

int
raw_socket_send(raw_socket_t sock, const uint8_t *buf, size_t len, uint32_t dst_ip)
{
	struct sockaddr_in dst;

	if (len > (size_t)SSIZE_MAX) {
		errno = EINVAL;
		return -1;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(dst_ip);

	return (int)sendto(sock, buf, len, 0,
			   (struct sockaddr *)&dst, sizeof(dst));
}

int
raw_socket_recv(raw_socket_t sock, uint8_t *buf, size_t maxlen)
{
	if (maxlen > (size_t)SSIZE_MAX)
		maxlen = (size_t)SSIZE_MAX;
	return (int)recvfrom(sock, buf, maxlen, 0, NULL, NULL);
}

void
raw_socket_close(raw_socket_t sock)
{
	close(sock);
}

#endif
