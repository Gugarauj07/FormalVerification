/*
 * remaining_length_harness.c
 * Reproducao de CVE-2017-7651 (integer overflow no Remaining Length).
 *
 * Na versao vulneravel (Mosquitto <= 1.4.14), o loop que decodifica
 * o campo Remaining Length do cabecalho MQTT nao limitava o numero
 * de bytes de continuacao.  Quando um cliente malicioso envia mais de
 * 4 bytes de continuation, remaining_mult (uint32_t) sofre overflow
 * aritmetico, corrompendo remaining_length e levando a uma alocacao
 * de memoria com tamanho incorreto.
 *
 * A funcao read_remaining_length_vulnerable() abaixo eh uma versao
 * simplificada do loop de leitura em
 *   mosquitto/lib/packet_mosq.c  (packet__read_single / leitura do
 *   remaining_length)
 * SEM o guard `remaining_count < -4` que foi adicionado na correcao.
 *
 * Property: ESBMC com --unsigned-overflow-check deve detectar o
 * overflow em remaining_mult *= 128 na 5a iteracao.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern uint8_t __VERIFIER_nondet_uchar(void);

#define MOSQ_ERR_SUCCESS            0
#define MOSQ_ERR_MALFORMED_PACKET  13

/*
 * Versao VULNERAVEL do parser de Remaining Length.
 * Corresponde ao comportamento do Mosquitto <= 1.4.14:
 * nao ha limite no numero de bytes lidos, entao remaining_mult
 * pode ultrapassar uint32_t.
 */
int read_remaining_length_vulnerable(const uint8_t *buf, int buflen,
                                     uint32_t *out_length,
                                     int *out_bytes_used)
{
    uint32_t remaining_length = 0;
    uint32_t remaining_mult   = 1;
    int      pos              = 0;
    uint8_t  byte;

    /* Loop sem limite de iteracoes (vulneravel). */
    do {
        if (pos >= buflen) {
            return MOSQ_ERR_MALFORMED_PACKET;
        }

        byte = buf[pos];
        remaining_length += (byte & 127u) * remaining_mult;
        remaining_mult *= 128;  /* <-- overflow na 5a iteracao */
        pos++;
    } while ((byte & 128) != 0);

    *out_length     = remaining_length;
    *out_bytes_used = pos;
    return MOSQ_ERR_SUCCESS;
}

/*
 * Versao CORRIGIDA: limita a 4 bytes de continuation
 * (conforme MQTT spec e fix aplicado apos CVE-2017-7651).
 */
int read_remaining_length_fixed(const uint8_t *buf, int buflen,
                                uint32_t *out_length,
                                int *out_bytes_used)
{
    uint32_t remaining_length = 0;
    uint32_t remaining_mult   = 1;
    int      pos              = 0;
    uint8_t  byte;

    do {
        if (pos >= buflen) {
            return MOSQ_ERR_MALFORMED_PACKET;
        }
        if (pos >= 4) {
            /* MQTT permite no maximo 4 bytes para Remaining Length. */
            return MOSQ_ERR_MALFORMED_PACKET;
        }

        byte = buf[pos];
        remaining_length += (byte & 127u) * remaining_mult;
        remaining_mult *= 128;
        pos++;
    } while ((byte & 128) != 0);

    *out_length     = remaining_length;
    *out_bytes_used = pos;
    return MOSQ_ERR_SUCCESS;
}

/* ===== HARNESS ===== */
int main(void)
{
    /* Pacote de ate 8 bytes nao deterministicos.
     * 8 bytes eh suficiente para exercitar o overflow na 5a iteracao. */
    uint8_t buf[8];
    for (int i = 0; i < 8; i++) {
        buf[i] = __VERIFIER_nondet_uchar();
    }

    uint32_t length = 0;
    int      used   = 0;

    int rc = read_remaining_length_vulnerable(buf, 8, &length, &used);

    /*
     * Se a funcao retornou sucesso, o valor decodificado deve caber
     * no maximo permitido pelo MQTT (268435455 = 0x0FFFFFFF).
     * Em caso de overflow, length pode ter um valor absurdo.
     */
    if (rc == MOSQ_ERR_SUCCESS) {
        __ESBMC_assert(length <= 268435455u,
            "CVE-2017-7651: remaining_length excede maximo MQTT (overflow)");
        __ESBMC_assert(used <= 4,
            "CVE-2017-7651: mais de 4 bytes consumidos no Remaining Length");
    }

    return 0;
}
