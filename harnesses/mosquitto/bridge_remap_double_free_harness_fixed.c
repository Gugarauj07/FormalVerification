/*
 * bridge_remap_double_free_harness_fixed.c
 * CVE-2024-3935 corrigido: *topic = NULL apos free em erro (commit ae7a804).
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern int __VERIFIER_nondet_int(void);

#define MOSQ_ERR_SUCCESS 0
#define MOSQ_ERR_NOMEM   1

int remap_topic_in_fixed(char **topic, int alloc_fails)
{
    if (alloc_fails) {
        free(*topic);
        *topic = NULL;
        return MOSQ_ERR_NOMEM;
    }

    char *topic_temp = malloc(32);
    if (!topic_temp) {
        free(*topic);
        *topic = NULL;
        return MOSQ_ERR_NOMEM;
    }
    snprintf(topic_temp, 32, "prefix/%s", *topic);
    free(*topic);
    *topic = topic_temp;
    return MOSQ_ERR_SUCCESS;
}

int bridge_handle_error_fixed(char **topic, int alloc_fails)
{
    int rc = remap_topic_in_fixed(topic, alloc_fails);
    if (rc == MOSQ_ERR_NOMEM && topic != NULL && *topic != NULL) {
        free(*topic);
        *topic = NULL;
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

    bridge_handle_error_fixed(&topic, alloc_fails);
    return 0;
}
