/*
 * will_properties_memleak_harness.c
 * CVE-2023-3592: memory leak when CONNECT v5 Will has invalid property types.
 *
 * Modelo simplificado de property__process_will() em src/property_broker.c
 * (Mosquitto < 2.0.16). No caminho default (tipo invalido), msg_properties
 * era alocado mas nao era atribuido a msg->properties antes do return,
 * impedindo a liberacao posterior.
 *
 * Fix (commit 00b24e0): msg->properties = msg_properties antes do return.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern uint8_t __VERIFIER_nondet_uchar(void);

#define MOSQ_ERR_SUCCESS  0
#define MOSQ_ERR_PROTOCOL 2

/* Tipos de propriedade MQTT v5 (subconjunto). */
#define MQTT_PROP_WILL_DELAY_INTERVAL  24
#define MQTT_PROP_PAYLOAD_FORMAT_INDICATOR 1
#define MQTT_PROP_MAX 42

struct mosquitto_message {
    void *properties;
};

static void *property__read_all(uint8_t prop_type)
{
    void *props = malloc(16);
    if (!props) {
        return NULL;
    }
    (void)prop_type;
    return props;
}

/* Versao VULNERAVEL (< 2.0.16). */
int property__process_will_vulnerable(struct mosquitto_message *msg, uint8_t prop_type)
{
    void *msg_properties = property__read_all(prop_type);

    if (!msg_properties) {
        return MOSQ_ERR_SUCCESS;
    }

    switch (prop_type) {
    case MQTT_PROP_WILL_DELAY_INTERVAL:
    case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
        msg->properties = msg_properties;
        return MOSQ_ERR_SUCCESS;
    default:
        /* VULNERAVEL: retorna sem associar msg_properties -> leak. */
        return MOSQ_ERR_PROTOCOL;
    }
}

/* ===== HARNESS ===== */
int main(void)
{
    struct mosquitto_message msg;
    msg.properties = NULL;

    uint8_t prop_type = __VERIFIER_nondet_uchar();
    /* Forca caminho default: tipo fora dos cases tratados. */
    __ESBMC_assume(prop_type > MQTT_PROP_PAYLOAD_FORMAT_INDICATOR
                && prop_type != MQTT_PROP_WILL_DELAY_INTERVAL
                && prop_type < MQTT_PROP_MAX);

    (void)property__process_will_vulnerable(&msg, prop_type);
    /* Sem free(msg.properties) — ESBMC --memory-leak-check deve reportar leak. */
    return 0;
}
