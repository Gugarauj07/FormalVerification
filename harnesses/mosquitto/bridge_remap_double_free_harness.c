/*
 * bridge_remap_double_free_harness.c
 * CVE-2024-3935: double free em bridge__remap_topic_in quando alocacao
 * de topico remapeado falha apos free(*topic) sem zerar o ponteiro.
 *
 * Modelo de src/bridge_topic.c (2.0.18) + caller que libera em erro.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern int __VERIFIER_nondet_int(void);

#define MOSQ_ERR_SUCCESS 0
#define MOSQ_ERR_NOMEM   1

int remap_topic_in_vulnerable(char **topic, int alloc_fails)
{
    if (alloc_fails) {
        free(*topic);
        /* BUG CVE-2024-3935: *topic nao e NULL; caller pode dar free de novo */
        return MOSQ_ERR_NOMEM;
    }

    char *topic_temp = malloc(32);
    if (!topic_temp) {
        free(*topic);
        return MOSQ_ERR_NOMEM;
    }
    snprintf(topic_temp, 32, "prefix/%s", *topic);
    free(*topic);
    *topic = topic_temp;
    return MOSQ_ERR_SUCCESS;
}

int bridge_handle_error_vulnerable(char **topic, int alloc_fails)
{
    int rc = remap_topic_in_vulnerable(topic, alloc_fails);
    if (rc == MOSQ_ERR_NOMEM) {
        free(*topic);
    }
    return rc;
}

int main(void)
{
    char *topic = malloc(16);
    __ESBMC_assume(topic != NULL);
    strcpy(topic, "sensor/room1");

    int alloc_fails = __VERIFIER_nondet_int();
    __ESBMC_assume(alloc_fails != 0);

    bridge_handle_error_vulnerable(&topic, alloc_fails);
    return 0;
}
