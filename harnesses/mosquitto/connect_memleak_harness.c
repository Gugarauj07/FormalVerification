/*
 * connect_memleak_harness.c
 * Reproducao de CVE-2017-7654 (memory leak no fluxo de conexao).
 *
 * Na versao vulneravel do Mosquitto (< 1.4.15 / 1.5-beta1), a funcao
 * que processa o pacote CONNECT alocava estruturas para o Will Message
 * (will_struct, payload, topic) e para username/password, mas nem
 * todos os caminhos de erro liberavam essa memoria antes de retornar.
 *
 * Um cliente malicioso podia repetidamente conectar, acionar um erro
 * apos a alocacao do Will, e nao ter os buffers liberados — vazando
 * memoria ate o broker cair por OOM.
 *
 * A versao corrigida centraliza a limpeza em um label error_cleanup
 * que libera will_struct, will_struct->msg.topic, will_struct->msg.payload,
 * username e password.
 *
 * Este harness modela o padrao vulneravel de forma isolada.
 *
 * Property: ESBMC com --memory-leak-check deve detectar o vazamento.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern uint8_t __VERIFIER_nondet_uchar(void);
extern int     __VERIFIER_nondet_int(void);

#define MOSQ_ERR_SUCCESS           0
#define MOSQ_ERR_NOMEM             1
#define MOSQ_ERR_PROTOCOL          2
#define MOSQ_ERR_MALFORMED_PACKET 13

/* Estrutura simplificada do Will Message do Mosquitto. */
struct will_message {
    char   *topic;
    void   *payload;
    int     payloadlen;
    int     qos;
    int     retain;
};

/* ============================================================
 * Versao VULNERAVEL: fluxo simplificado de leitura do Will no
 * pacote CONNECT.  Apos alocar will_struct e topic, um erro
 * (e.g. payload invalido) retorna sem liberar a memoria.
 * ============================================================ */
int process_connect_will_vulnerable(const uint8_t *data, int datalen)
{
    struct will_message *will_struct = NULL;

    /* Passo 1: aloca estrutura do will */
    will_struct = (struct will_message *)calloc(1, sizeof(struct will_message));
    if (!will_struct) {
        return MOSQ_ERR_NOMEM;
    }

    /* Passo 2: le topic do will (simulado) */
    if (datalen < 4) {
        /* VULNERAVEL: retorna sem liberar will_struct */
        return MOSQ_ERR_MALFORMED_PACKET;
    }

    uint16_t topic_len = (uint16_t)((data[0] << 8) | data[1]);
    if (topic_len == 0 || topic_len > (uint16_t)(datalen - 4)) {
        /* VULNERAVEL: retorna sem liberar will_struct */
        return MOSQ_ERR_PROTOCOL;
    }

    will_struct->topic = (char *)malloc(topic_len + 1u);
    if (!will_struct->topic) {
        free(will_struct);
        return MOSQ_ERR_NOMEM;
    }
    memcpy(will_struct->topic, &data[2], topic_len);
    will_struct->topic[topic_len] = '\0';

    /* Passo 3: le payload do will (simulado) */
    int offset = 2 + topic_len;
    uint16_t payload_len = (uint16_t)((data[offset] << 8) | data[offset + 1]);
    offset += 2;

    if (payload_len > 0) {
        if (offset + payload_len > datalen) {
            /* VULNERAVEL: retorna sem liberar will_struct NEM topic */
            return MOSQ_ERR_MALFORMED_PACKET;
        }
        will_struct->payload = malloc(payload_len);
        if (!will_struct->payload) {
            /* VULNERAVEL: retorna sem liberar will_struct NEM topic */
            return MOSQ_ERR_NOMEM;
        }
        memcpy(will_struct->payload, &data[offset], payload_len);
        will_struct->payloadlen = payload_len;
    }

    /* Sucesso: em producao, will_struct seria transferido para o contexto.
     * Aqui, simulamos a transferencia liberando a memoria. */
    free(will_struct->payload);
    free(will_struct->topic);
    free(will_struct);

    return MOSQ_ERR_SUCCESS;
}

/* ============================================================
 * Versao CORRIGIDA: todos os caminhos de erro liberam a memoria.
 * ============================================================ */
int process_connect_will_fixed(const uint8_t *data, int datalen)
{
    struct will_message *will_struct = NULL;
    int rc = MOSQ_ERR_SUCCESS;

    will_struct = (struct will_message *)calloc(1, sizeof(struct will_message));
    if (!will_struct) {
        return MOSQ_ERR_NOMEM;
    }

    if (datalen < 4) {
        rc = MOSQ_ERR_MALFORMED_PACKET;
        goto error_cleanup;
    }

    uint16_t topic_len = (uint16_t)((data[0] << 8) | data[1]);
    if (topic_len == 0 || topic_len > (uint16_t)(datalen - 4)) {
        rc = MOSQ_ERR_PROTOCOL;
        goto error_cleanup;
    }

    will_struct->topic = (char *)malloc(topic_len + 1u);
    if (!will_struct->topic) {
        rc = MOSQ_ERR_NOMEM;
        goto error_cleanup;
    }
    memcpy(will_struct->topic, &data[2], topic_len);
    will_struct->topic[topic_len] = '\0';

    int offset = 2 + topic_len;
    uint16_t payload_len = (uint16_t)((data[offset] << 8) | data[offset + 1]);
    offset += 2;

    if (payload_len > 0) {
        if (offset + payload_len > datalen) {
            rc = MOSQ_ERR_MALFORMED_PACKET;
            goto error_cleanup;
        }
        will_struct->payload = malloc(payload_len);
        if (!will_struct->payload) {
            rc = MOSQ_ERR_NOMEM;
            goto error_cleanup;
        }
        memcpy(will_struct->payload, &data[offset], payload_len);
        will_struct->payloadlen = payload_len;
    }

    /* Sucesso */
    free(will_struct->payload);
    free(will_struct->topic);
    free(will_struct);
    return MOSQ_ERR_SUCCESS;

error_cleanup:
    if (will_struct) {
        free(will_struct->topic);
        free(will_struct->payload);
        free(will_struct);
    }
    return rc;
}

/* ===== HARNESS ===== */
int main(void)
{
    /* Pacote de ate 8 bytes nao deterministicos.
     * Tamanho pequeno para manter o espaco de estados tratavel. */
    uint8_t buf[8];
    for (int i = 0; i < 8; i++) {
        buf[i] = __VERIFIER_nondet_uchar();
    }

    /* Tamanho do pacote: entre 0 e 8 (nao deterministico). */
    int datalen = __VERIFIER_nondet_int();
    __ESBMC_assume(datalen >= 0 && datalen <= 8);

    /*
     * Chama a versao VULNERAVEL.
     * ESBMC com --memory-leak-check deve reportar leak nos caminhos
     * de erro que nao liberam will_struct/topic/payload.
     */
    int rc = process_connect_will_vulnerable(buf, datalen);

    return 0;
}
