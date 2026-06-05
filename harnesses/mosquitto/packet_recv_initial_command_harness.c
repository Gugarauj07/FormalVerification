/*
 * packet_recv_initial_command_harness.c
 *
 * Harness de INTEGRACAO: validacao do primeiro comando MQTT lido via recv().
 * CVE-2023-0809 — broker vulneravel aceita PUBLISH antes de CONNECT.
 *
 * Fluxo: recv() -> primeiro byte do pacote -> validate_first_command().
 *
 * Compilar:
 *   esbmc harnesses/mosquitto/packet_recv_initial_command_harness.c \
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

/* Vulneravel (<= 2.0.15): rejeita nao-CONNECT so se ja "connected". */
static int validate_first_command_vulnerable(int state, int is_bridge,
                                             uint8_t command_byte)
{
    uint8_t cmd = (uint8_t)(command_byte & 0xF0);

    if (!is_bridge && state == mosq_cs_connected && cmd != CMD_CONNECT) {
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

    /* Restringe a entrada simbolica de recv a pacotes PUBLISH. */
    __ESBMC_assume((byte & 0xF0) == CMD_PUBLISH);

    rc = validate_first_command_vulnerable(mosq_cs_new, 0, byte);

    __ESBMC_assert(rc != MOSQ_ERR_SUCCESS,
        "CVE-2023-0809 (recv): broker aceita PUBLISH antes de CONNECT");

    return 0;
}
