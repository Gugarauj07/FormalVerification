/*
 * packet_recv_remaining_length_harness_fixed.c
 *
 * Versao corrigida do harness de integracao (CVE-2017-7651 fix).
 * Limita Remaining Length a 4 bytes de continuacao (MQTT spec).
 *
 * Compilar:
 *   esbmc harnesses/mosquitto/packet_recv_remaining_length_harness_fixed.c \
 *         esbmc_models/network_stubs.c --unwind 8
 */

#include <stdint.h>
#include <stddef.h>
#include "../../esbmc_models/network_common.h"

#define MOSQ_ERR_SUCCESS            0
#define MOSQ_ERR_MALFORMED_PACKET  13

typedef long ssize_t;

ssize_t recv(int sockfd, void *buf, size_t len, int flags);

static int read_byte(int sockfd, uint8_t *byte)
{
    ssize_t n = recv(sockfd, byte, 1, 0);
    if (n != 1) {
        return MOSQ_ERR_MALFORMED_PACKET;
    }
    return MOSQ_ERR_SUCCESS;
}

static int read_remaining_length_fixed(int sockfd,
                                       uint32_t *out_length,
                                       int *out_bytes_used)
{
    uint32_t remaining_length = 0;
    uint32_t remaining_mult   = 1;
    int      pos              = 0;
    uint8_t  byte;
    int      rc;

    do {
        if (pos >= 4) {
            return MOSQ_ERR_MALFORMED_PACKET;
        }

        rc = read_byte(sockfd, &byte);
        if (rc != MOSQ_ERR_SUCCESS) {
            return rc;
        }

        remaining_length += (byte & 127u) * remaining_mult;
        remaining_mult *= 128;
        pos++;
    } while ((byte & 128) != 0);

    *out_length     = remaining_length;
    *out_bytes_used = pos;
    return MOSQ_ERR_SUCCESS;
}

int main(void)
{
    int      sockfd = 3;
    uint32_t length = 0;
    int      used   = 0;

    int rc = read_remaining_length_fixed(sockfd, &length, &used);

    if (rc == MOSQ_ERR_SUCCESS) {
        __ESBMC_assert(length <= 268435455u,
            "Remaining Length excede maximo MQTT apos correcao");
        __ESBMC_assert(used <= 4,
            "Mais de 4 bytes no Remaining Length apos correcao");
    }

    return 0;
}
