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

/* --- Core socket API --- */
int     socket(int domain, int type, int protocol);
int     bind(int sockfd, const void *addr, int addrlen);
int     listen(int sockfd, int backlog);
int     accept(int sockfd, void *addr, int *addrlen);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
int     close(int fd);

/* --- I/O multiplexing (select / poll) --- */
#ifndef FD_SETSIZE
#define FD_SETSIZE 64
#endif

typedef struct {
    unsigned long fds_bits[FD_SETSIZE / (8 * sizeof(unsigned long)) + 1];
} fd_set;

struct timeval {
    long tv_sec;
    long tv_usec;
};

int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout);

#ifndef POLLIN
#define POLLIN   0x0001
#define POLLOUT  0x0004
#define POLLERR  0x0008
#define POLLHUP  0x0010
#define POLLNVAL 0x0020
#endif

struct pollfd {
    int   fd;
    short events;
    short revents;
};

int poll(struct pollfd *fds, unsigned int nfds, int timeout);

#endif /* NETWORK_COMMON_H */
