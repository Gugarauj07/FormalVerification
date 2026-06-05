/*
 * packet_recv_remaining_length_harness.c
 *
 * Harness de INTEGRACAO: leitura do Remaining Length via recv() stub.
 *
 * Diferente dos harnesses isolados (ex.: remaining_length_harness.c), este
 * simula o fluxo real do broker Mosquitto — bytes chegam pela rede e sao
 * lidos com recv(). O operational model em esbmc_models/network_stubs.c
 * fornece entrada simbolica (atacante controla o que recv devolve).
 *
 * CVE-2017-7651: versao vulneravel nao limita bytes de continuacao.
 * Propriedade: length <= 268435455 e used <= 4 (MQTT spec).
 *
 * Compilar:
 *   esbmc harnesses/mosquitto/packet_recv_remaining_length_harness.c \
 *         esbmc_models/network_stubs.c --unwind 8 --unsigned-overflow-check
 */

#include <stdint.h>
#include <stddef.h>
#include "../../esbmc_models/network_common.h"

#define MOSQ_ERR_SUCCESS            0
#define MOSQ_ERR_MALFORMED_PACKET  13

/* Le um byte via recv; retorna MOSQ_ERR_SUCCESS ou erro. */
static int read_byte(int sockfd, uint8_t *byte)
{
    ssize_t n = recv(sockfd, byte, 1, 0);
    if (n != 1) {
        return MOSQ_ERR_MALFORMED_PACKET;
    }
    return MOSQ_ERR_SUCCESS;
}

/*
 * Parser vulneravel: loop sem limite de bytes de continuacao.
 * Equivalente logico a remaining_length_harness.c, mas alimentado por recv.
 */
static int read_remaining_length_vulnerable(int sockfd,
                                            uint32_t *out_length,
                                            int *out_bytes_used)
{
    uint32_t remaining_length = 0;
    uint32_t remaining_mult   = 1;
    int      pos              = 0;
    uint8_t  byte;
    int      rc;

    do {
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
    int      sockfd = 3; /* fd valido dentro do range assumido pelo stub */
    uint32_t length = 0;
    int      used   = 0;

    int rc = read_remaining_length_vulnerable(sockfd, &length, &used);

    if (rc == MOSQ_ERR_SUCCESS) {
        __ESBMC_assert(length <= 268435455u,
            "CVE-2017-7651 (recv): remaining_length excede maximo MQTT");
        __ESBMC_assert(used <= 4,
            "CVE-2017-7651 (recv): mais de 4 bytes no Remaining Length");
    }

    return 0;
}
