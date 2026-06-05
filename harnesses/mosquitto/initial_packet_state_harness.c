/*
 * initial_packet_state_harness.c
 * CVE-2023-0809: broker aceitava pacotes nao-CONNECT no estado conectado,
 * permitindo alocacao excessiva de memoria com Remaining Length malicioso.
 *
 * Modelo de lib/packet_mosq.c (packet__read): guard de primeiro comando.
 * Vulneravel: state == mosq_cs_connected
 * Corrigido:  state == mosq_cs_new
 */

#include <stdint.h>
#include <stddef.h>

extern uint8_t __VERIFIER_nondet_uchar(void);

#define MOSQ_ERR_SUCCESS  0
#define MOSQ_ERR_PROTOCOL 2

#define CMD_CONNECT 0x10
#define CMD_PUBLISH 0x30

#define mosq_cs_new        0
#define mosq_cs_connected  1

/* Vulneravel (<= 2.0.15): rejeita nao-CONNECT so se ja "connected". */
int validate_first_command_vulnerable(int state, int is_bridge, uint8_t command_byte)
{
    uint8_t cmd = (uint8_t)(command_byte & 0xF0);

    if (!is_bridge && state == mosq_cs_connected && cmd != CMD_CONNECT) {
        return MOSQ_ERR_PROTOCOL;
    }
    return MOSQ_ERR_SUCCESS;
}

int main(void)
{
    uint8_t byte = __VERIFIER_nondet_uchar();
    /* Pacote PUBLISH como primeiro byte de comando (nao CONNECT). */
    __ESBMC_assume((byte & 0xF0) == CMD_PUBLISH);

    int rc = validate_first_command_vulnerable(mosq_cs_new, 0, byte);

    /* Propriedade de seguranca: em estado novo, nao-CONNECT deve falhar. */
    __ESBMC_assert(rc != MOSQ_ERR_SUCCESS,
        "CVE-2023-0809: broker vulneravel aceita PUBLISH antes de CONNECT");

    return 0;
}
