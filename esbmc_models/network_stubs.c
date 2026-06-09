/*
 * network_stubs.c — operational models minimos para APIs POSIX de rede.
 *
 * Uso com ESBMC:
 *   esbmc meu_harness.c esbmc_models/network_stubs.c --unwind 8
 *
 * Modelo: socket retorna fd simbolico; recv preenche buffer com bytes nondet;
 * send retorna sucesso; select/poll retornam resultado nondet indicando
 * quais descritores estao prontos. Nao modela TCP real nem erros de OS.
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

/* -----------------------------------------------------------------------
 * select() — modelo operacional para multiplexacao de I/O
 *
 * Semantica abstrata:
 *   - Retorna um valor nondet entre -1 e nfds (inclusive).
 *   - Se o retorno for > 0, marca bits nondet em readfds/writefds/exceptfds
 *     dentro do intervalo [0, nfds), modelando o comportamento de qualquer
 *     subconjunto de descritores que podem estar prontos.
 *   - Se o retorno for 0, nenhum bit e marcado (timeout).
 *   - Se o retorno for -1, os conjuntos nao sao modificados (erro).
 *   - O argumento timeout e ignorado: o modelo e instantaneo para o
 *     verificador, que explora todos os resultados possiveis.
 * ----------------------------------------------------------------------- */
#ifndef FD_SETSIZE
#define FD_SETSIZE 64
#endif

typedef struct {
    unsigned long fds_bits[FD_SETSIZE / (8 * sizeof(unsigned long)) + 1];
} fd_set_stub;

struct timeval_stub {
    long tv_sec;
    long tv_usec;
};

int select(int nfds, fd_set_stub *readfds, fd_set_stub *writefds,
           fd_set_stub *exceptfds, struct timeval_stub *timeout)
{
    (void)timeout;
    int ret = __VERIFIER_nondet_int();
    __ESBMC_assume(ret >= -1 && ret <= nfds);
    if (ret > 0) {
        /* Mark nondet bits inside [0, nfds) for each non-NULL set. */
        int word_count = (nfds / (int)(8 * sizeof(unsigned long))) + 1;
        if (readfds) {
            for (int i = 0; i < word_count; i++)
                readfds->fds_bits[i] = (unsigned long)__VERIFIER_nondet_int();
        }
        if (writefds) {
            for (int i = 0; i < word_count; i++)
                writefds->fds_bits[i] = (unsigned long)__VERIFIER_nondet_int();
        }
        if (exceptfds) {
            for (int i = 0; i < word_count; i++)
                exceptfds->fds_bits[i] = (unsigned long)__VERIFIER_nondet_int();
        }
    }
    return ret;
}

/* -----------------------------------------------------------------------
 * poll() — modelo operacional para multiplexacao de I/O (POSIX)
 *
 * Semantica abstrata:
 *   - Para cada pollfd na lista, preenche revents com um bitfield nondet,
 *     restrito aos eventos solicitados em events (ou POLLERR/POLLHUP que
 *     sempre podem ocorrer).
 *   - Retorna um valor nondet entre -1 e nfds indicando quantos descritores
 *     tem eventos pendentes.
 * ----------------------------------------------------------------------- */
#ifndef POLLIN
#define POLLIN   0x0001
#define POLLOUT  0x0004
#define POLLERR  0x0008
#define POLLHUP  0x0010
#define POLLNVAL 0x0020
#endif

struct pollfd_stub {
    int   fd;
    short events;
    short revents;
};

int poll(struct pollfd_stub *fds, unsigned int nfds, int timeout)
{
    (void)timeout;
    if (!fds || nfds == 0) return 0;

    for (unsigned int i = 0; i < nfds; i++) {
        /* revents is a nondet subset of requested events plus error flags */
        short mask = (short)(fds[i].events | POLLERR | POLLHUP | POLLNVAL);
        short rv   = (short)__VERIFIER_nondet_int();
        fds[i].revents = rv & mask;
    }
    int ret = __VERIFIER_nondet_int();
    __ESBMC_assume(ret >= -1 && ret <= (int)nfds);
    return ret;
}
