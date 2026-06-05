/*
 * network_stubs.c — operational models minimos para APIs POSIX de rede.
 *
 * Uso com ESBMC:
 *   esbmc meu_harness.c esbmc_models/network_stubs.c --unwind 8
 *
 * Modelo: socket retorna fd simbolico; recv preenche buffer com bytes nondet;
 * send retorna sucesso. Nao modela TCP real nem erros de OS.
 */

#include <stdint.h>
#include <stddef.h>

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif

typedef int socklen_t;

extern int __VERIFIER_nondet_int(void);

int socket(int domain, int type, int protocol)
{
    (void)domain;
    (void)type;
    (void)protocol;
    int fd = __VERIFIER_nondet_int();
    __ESBMC_assume(fd >= 3 && fd < 64);
    return fd;
}

int bind(int sockfd, const void *addr, socklen_t addrlen)
{
    (void)sockfd;
    (void)addr;
    (void)addrlen;
    return 0;
}

int listen(int sockfd, int backlog)
{
    (void)sockfd;
    (void)backlog;
    return 0;
}

int accept(int sockfd, void *addr, socklen_t *addrlen)
{
    (void)sockfd;
    (void)addr;
    (void)addrlen;
    int cfd = __VERIFIER_nondet_int();
    __ESBMC_assume(cfd >= 3 && cfd < 64);
    return cfd;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    (void)sockfd;
    (void)flags;
    if (!buf || len == 0) {
        return 0;
    }
    uint8_t *p = (uint8_t *)buf;
    for (size_t i = 0; i < len && i < 256; i++) {
        p[i] = (uint8_t)__VERIFIER_nondet_int();
    }
    ssize_t n = __VERIFIER_nondet_int();
    __ESBMC_assume(n >= 0 && (size_t)n <= len);
    return n;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    (void)sockfd;
    (void)buf;
    (void)flags;
    ssize_t n = __VERIFIER_nondet_int();
    __ESBMC_assume(n >= 0 && (size_t)n <= len);
    return n;
}

int close(int fd)
{
    (void)fd;
    return 0;
}
