/*
 * packet_recv_initial_command_harness_fixed.c
 *
 * Versao corrigida (commit a3c680f): rejeita nao-CONNECT em mosq_cs_new.
 *
 * Compilar:
 *   esbmc harnesses/mosquitto/packet_recv_initial_command_harness_fixed.c \
 *         esbmc_models/network_stubs.c --unwind 4
 */

#include <stdint.h>
#include <stddef.h>
#include "../../esbmc_models/network_common.h"

#define MOSQ_ERR_SUCCESS  0
#define MOSQ_ERR_PROTOCOL 2

#define CMD_CONNECT 0x10
#define CMD_PUBLISH 0x30

#define mosq_cs_new        0
#define mosq_cs_connected  1

static int read_first_byte(int sockfd, uint8_t *byte)
{
    ssize_t n = recv(sockfd, byte, 1, 0);
    if (n != 1) {
        return MOSQ_ERR_PROTOCOL;
    }
    return MOSQ_ERR_SUCCESS;
}

static int validate_first_command_fixed(int state, int is_bridge,
                                        uint8_t command_byte)
{
    uint8_t cmd = (uint8_t)(command_byte & 0xF0);

    if (!is_bridge && state == mosq_cs_new && cmd != CMD_CONNECT) {
        return MOSQ_ERR_PROTOCOL;
    }
    return MOSQ_ERR_SUCCESS;
}

int main(void)
{
    int      sockfd = 3;
    uint8_t  byte   = 0;
    int      rc;

    rc = read_first_byte(sockfd, &byte);
    if (rc != MOSQ_ERR_SUCCESS) {
        return 0;
    }

    __ESBMC_assume((byte & 0xF0) == CMD_PUBLISH);

    rc = validate_first_command_fixed(mosq_cs_new, 0, byte);

    __ESBMC_assert(rc == MOSQ_ERR_PROTOCOL,
        "CVE-2023-0809 (recv): PUBLISH rejeitado em estado novo");

    return 0;
}
