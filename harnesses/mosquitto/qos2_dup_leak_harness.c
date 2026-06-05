/*
 * qos2_dup_leak_harness.c
 * CVE-2023-28366: memory leak quando cliente envia varios PUBLISH QoS 2
 * com o mesmo message ID (dup) sem completar o handshake PUBREC/PUBREL.
 *
 * Modelo simplificado do caminho em handle__publish (2.0.15): ao receber
 * duplicata com mesmo mid, o broker reutilizava o store mas nao liberava
 * entradas inflight extras criadas em envios PUBREC repetidos.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern int __VERIFIER_nondet_int(void);

struct msg_store {
    void *payload;
    uint16_t mid;
};

struct inflight_msg {
    struct msg_store *store;
    uint8_t dup;
    struct inflight_msg *next;
};

/* Vulneravel: cada PUBLISH dup aloca novo store sem remover o anterior. */
int handle_qos2_dup_vulnerable(struct inflight_msg **head, struct msg_store *incoming)
{
    struct inflight_msg *existing = *head;

    if (existing && existing->store && existing->store->mid == incoming->mid) {
        /* Duplicata: deveria reutilizar; versao vulneravel aloca novo store. */
        struct msg_store *leaked = existing->store;
        (void)leaked;

        struct inflight_msg *node = calloc(1, sizeof(struct inflight_msg));
        if (!node) {
            return -1;
        }
        node->store = malloc(sizeof(struct msg_store));
        if (!node->store) {
            free(node);
            return -1;
        }
        node->store->payload = malloc(64);
        node->store->mid = incoming->mid;
        node->dup = existing->dup + 1;
        node->next = *head;
        *head = node;
        return 0;
    }

    struct inflight_msg *node = calloc(1, sizeof(struct inflight_msg));
    if (!node) {
        return -1;
    }
    node->store = incoming;
    node->dup = 0;
    node->next = NULL;
    *head = node;
    return 0;
}

int main(void)
{
    struct inflight_msg *head = NULL;
    struct msg_store first;
    first.payload = malloc(64);
    first.mid = 42;

    handle_qos2_dup_vulnerable(&head, &first);

    int again = __VERIFIER_nondet_int();
    __ESBMC_assume(again != 0);

    struct msg_store second;
    second.payload = malloc(64);
    second.mid = 42;
    handle_qos2_dup_vulnerable(&head, &second);

    /* Sem liberar lista — leak de stores antigos. */
    return 0;
}
