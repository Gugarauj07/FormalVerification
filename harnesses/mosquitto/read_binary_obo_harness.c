/*
 * read_binary_obo_harness.c
 * Off-by-one na funcao packet__read_binary() do Mosquitto.
 *
 * Em versoes antigas do Mosquitto, a funcao packet__read_binary()
 * (usada para ler campos binarios como a password do pacote CONNECT)
 * alocava exatamente slen bytes com malloc(slen), mas em seguida
 * escrevia um terminador nulo em data[slen]:
 *
 *     *data = malloc(slen);          // aloca slen bytes (indices 0..slen-1)
 *     memcpy(*data, payload, slen);
 *     (*data)[slen] = '\0';          // ESCRITA FORA DO BUFFER (indice slen)
 *
 * Isso configura um heap buffer overflow de 1 byte (off-by-one, CWE-193).
 *
 * A correcao foi alterar para malloc(slen + 1U).
 *
 * Funcoes abaixo sao versoes simplificadas de
 *   mosquitto/lib/packet_datatypes.c :: packet__read_binary()
 *
 * Property: ESBMC deve detectar a escrita fora dos limites do buffer.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern uint8_t  __VERIFIER_nondet_uchar(void);
extern uint16_t __VERIFIER_nondet_ushort(void);

#define MOSQ_ERR_SUCCESS           0
#define MOSQ_ERR_NOMEM             1
#define MOSQ_ERR_MALFORMED_PACKET 13

struct packet_in {
    uint8_t  *payload;
    uint32_t  pos;
    uint32_t  remaining_length;
};

/* Auxiliar: le uint16 big-endian do payload. */
static int read_uint16(struct packet_in *pkt, uint16_t *word)
{
    if (pkt->pos + 2 > pkt->remaining_length) {
        return MOSQ_ERR_MALFORMED_PACKET;
    }
    *word = (uint16_t)((pkt->payload[pkt->pos] << 8)
                     |  pkt->payload[pkt->pos + 1]);
    pkt->pos += 2;
    return MOSQ_ERR_SUCCESS;
}

/* ============================================================
 * Versao VULNERAVEL: malloc(slen) + escrita em [slen]
 * ============================================================ */
int read_binary_vulnerable(struct packet_in *pkt,
                           uint8_t **data, uint16_t *length)
{
    uint16_t slen;
    int rc;

    rc = read_uint16(pkt, &slen);
    if (rc) return rc;

    if (slen == 0) {
        *data   = NULL;
        *length = 0;
        return MOSQ_ERR_SUCCESS;
    }

    if (pkt->pos + slen > pkt->remaining_length) {
        return MOSQ_ERR_MALFORMED_PACKET;
    }

    uint16_t allocated = slen;            /* BUG: deveria ser slen + 1 */
    *data = (uint8_t *)malloc(allocated);
    if (!*data) {
        return MOSQ_ERR_NOMEM;
    }

    memcpy(*data, &pkt->payload[pkt->pos], slen);
    (*data)[slen] = '\0';                 /* <-- OFF-BY-ONE: indice slen >= allocated */
    pkt->pos += slen;

    *length = slen;
    if (slen > 0) {
        __ESBMC_assert(allocated > slen,
            "off-by-one: data[slen] fora do buffer malloc(slen)");
    }
    return MOSQ_ERR_SUCCESS;
}

/* ============================================================
 * Versao CORRIGIDA: malloc(slen + 1U)
 * ============================================================ */
int read_binary_fixed(struct packet_in *pkt,
                      uint8_t **data, uint16_t *length)
{
    uint16_t slen;
    int rc;

    rc = read_uint16(pkt, &slen);
    if (rc) return rc;

    if (slen == 0) {
        *data   = NULL;
        *length = 0;
        return MOSQ_ERR_SUCCESS;
    }

    if (pkt->pos + slen > pkt->remaining_length) {
        return MOSQ_ERR_MALFORMED_PACKET;
    }

    *data = (uint8_t *)malloc(slen + 1U); /* CORRIGIDO */
    if (!*data) {
        return MOSQ_ERR_NOMEM;
    }

    memcpy(*data, &pkt->payload[pkt->pos], slen);
    (*data)[slen] = '\0';                 /* OK: cabe no buffer */
    pkt->pos += slen;

    *length = slen;
    return MOSQ_ERR_SUCCESS;
}

/* ===== HARNESS ===== */
int main(void)
{
    /* Pacote concreto: comprimento 3 + 3 bytes de payload (dispara off-by-one). */
    uint8_t buf[8] = {0x00, 0x03, 'a', 'b', 'c', 0, 0, 0};

    struct packet_in pkt;
    pkt.payload          = buf;
    pkt.pos              = 0;
    pkt.remaining_length = 8;

    uint8_t  *data   = NULL;
    uint16_t  length = 0;

    int rc = read_binary_vulnerable(&pkt, &data, &length);

    /* Propriedade: sucesso com slen>0 implica buffer de tamanho adequado. */
    if (rc == MOSQ_ERR_SUCCESS && length > 0) {
        __ESBMC_assert(length + 1u <= length,
            "off-by-one: malloc(slen) insuficiente para terminador em [slen]");
    }

    if (data) {
        free(data);
    }

    return 0;
}
