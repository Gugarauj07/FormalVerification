/*
 * qos2_dup_leak_harness_fixed.c
 * CVE-2023-28366: reutiliza store existente e limita dup (handle__publish 2.0.16).
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern int __VERIFIER_nondet_int(void);

#define MOSQ_ERR_PROTOCOL 2

struct msg_store {
    void *payload;
    uint16_t mid;
};

struct inflight_msg {
    struct msg_store *store;
    uint8_t dup;
};

int handle_qos2_dup_fixed(struct inflight_msg **head, struct msg_store *incoming)
{
    struct inflight_msg *existing = *head;

    if (existing && existing->store && existing->store->mid == incoming->mid) {
        existing->dup++;
        if (existing->dup > 2) {
            return MOSQ_ERR_PROTOCOL;
        }
        free(incoming->payload);
        free(incoming);
        return 0;
    }

    struct inflight_msg *node = calloc(1, sizeof(struct inflight_msg));
    if (!node) {
        return -1;
    }
    node->store = incoming;
    node->dup = 0;
    *head = node;
    return 0;
}

int main(void)
{
    struct inflight_msg *head = NULL;

    struct msg_store *first = calloc(1, sizeof(struct msg_store));
    __ESBMC_assume(first != NULL);
    first->payload = malloc(64);
    __ESBMC_assume(first->payload != NULL);
    first->mid = 42;
    handle_qos2_dup_fixed(&head, first);

    /* Segunda publicacao dup: store descartado e liberado (correcao 2.0.16). */
    struct msg_store *dup = calloc(1, sizeof(struct msg_store));
    __ESBMC_assume(dup != NULL);
    dup->payload = malloc(64);
    __ESBMC_assume(dup->payload != NULL);
    dup->mid = 42;
    handle_qos2_dup_fixed(&head, dup);

    if (head) {
        if (head->store) {
            free(head->store->payload);
            free(head->store);
        }
        free(head);
    }
    return 0;
}
