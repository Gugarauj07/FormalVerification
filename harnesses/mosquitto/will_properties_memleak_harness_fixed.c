/*
 * will_properties_memleak_harness_fixed.c
 * CVE-2023-3592 corrigido (commit 00b24e0).
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern uint8_t __VERIFIER_nondet_uchar(void);

#define MOSQ_ERR_SUCCESS  0
#define MOSQ_ERR_PROTOCOL 2

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

int property__process_will_fixed(struct mosquitto_message *msg, uint8_t prop_type)
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
        msg->properties = msg_properties;  /* FIX CVE-2023-3592 */
        return MOSQ_ERR_PROTOCOL;
    }
}

int main(void)
{
    struct mosquitto_message msg;
    msg.properties = NULL;

    uint8_t prop_type = __VERIFIER_nondet_uchar();
    __ESBMC_assume(prop_type > MQTT_PROP_PAYLOAD_FORMAT_INDICATOR
                && prop_type != MQTT_PROP_WILL_DELAY_INTERVAL
                && prop_type < MQTT_PROP_MAX);

    int rc = property__process_will_fixed(&msg, prop_type);
    if (rc == MOSQ_ERR_PROTOCOL && msg.properties) {
        free(msg.properties);
        msg.properties = NULL;
    }
    return 0;
}
