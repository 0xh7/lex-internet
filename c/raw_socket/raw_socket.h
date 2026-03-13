#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET raw_socket_t;
#define RAW_SOCKET_INVALID INVALID_SOCKET
#else
typedef int raw_socket_t;
#define RAW_SOCKET_INVALID (-1)
#endif

raw_socket_t raw_socket_open(int protocol);
int raw_socket_bind(raw_socket_t sock, const char *iface);
int raw_socket_send(raw_socket_t sock, const uint8_t *buf, size_t len, uint32_t dst_ip);
int raw_socket_recv(raw_socket_t sock, uint8_t *buf, size_t maxlen);
void raw_socket_close(raw_socket_t sock);
int raw_socket_init(void);
void raw_socket_cleanup(void);
