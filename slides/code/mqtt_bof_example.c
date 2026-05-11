#include <stdint.h>
#include <stddef.h>

#define MQTT_MAX_REMAINING_LENGTH 268435455U

uint32_t read_remaining_length(const uint8_t *buf, size_t buflen)
{
    uint32_t multiplier = 1;
    uint32_t value = 0;
    uint8_t  byte;
    size_t   pos = 0;

    do {
        if (pos >= buflen) return 0;
        byte = buf[pos++];
        value += (byte & 127) * multiplier;
        multiplier *= 128;
    } while ((byte & 128) != 0);

    return value;
}

int main(void)
{
    uint8_t packet[5] = {0xFF, 0xFF, 0xFF, 0xFF, 0x7F};

    uint32_t len = read_remaining_length(packet, 5);

    __ESBMC_assert(len <= MQTT_MAX_REMAINING_LENGTH,
                   "CVE-2017-7651: Remaining Length excede o maximo MQTT");
    return 0;
}
