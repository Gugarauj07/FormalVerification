/*
 * network_common.h — tipos e declaracoes compartilhados para harnesses
 * que usam esbmc_models/network_stubs.c com ESBMC.
 */
#ifndef NETWORK_COMMON_H
#define NETWORK_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
int socket(int domain, int type, int protocol);
int close(int fd);

#endif /* NETWORK_COMMON_H */
