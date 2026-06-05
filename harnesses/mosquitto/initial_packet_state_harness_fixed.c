/*
 * initial_packet_state_harness_fixed.c
 * CVE-2023-0809 corrigido (commit a3c680f).
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

int validate_first_command_fixed(int state, int is_bridge, uint8_t command_byte)
{
    uint8_t cmd = (uint8_t)(command_byte & 0xF0);

    if (!is_bridge && state == mosq_cs_new && cmd != CMD_CONNECT) {
        return MOSQ_ERR_PROTOCOL;
    }
    return MOSQ_ERR_SUCCESS;
}

int main(void)
{
    uint8_t byte = __VERIFIER_nondet_uchar();
    __ESBMC_assume((byte & 0xF0) == CMD_PUBLISH);

    int rc = validate_first_command_fixed(mosq_cs_new, 0, byte);

    __ESBMC_assert(rc == MOSQ_ERR_PROTOCOL,
        "CVE-2023-0809: primeiro pacote nao-CONNECT rejeitado apos correcao");

    return 0;
}
