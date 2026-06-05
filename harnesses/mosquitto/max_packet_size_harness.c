/*
 * max_packet_size_harness.c
 * Propriedade de seguranca no codigo recente do Mosquitto (2.1.x):
 * packet__read_varint nao deve decodificar Remaining Length acima do
 * maximo MQTT (268435455) nem consumir mais de 4 bytes de continuacao.
 *
 * Baseado em packet__read_varint() / limites MQTT v5 (OASIS).
 * Complementa varint_harness.c com checagem de limite superior estrito.
 */

#include <stdint.h>
#include <stddef.h>

#define MOSQ_ERR_SUCCESS           0
#define MOSQ_ERR_MALFORMED_PACKET 13
#define MQTT_MAX_REMAINING_LENGTH 268435455U

struct mosquitto__packet_in {
    uint8_t *payload;
    uint32_t pos;
    uint32_t remaining_length;
};

int packet__read_varint(struct mosquitto__packet_in *packet, uint32_t *word, uint8_t *bytes)
{
    int i;
    uint8_t byte;
    unsigned int remaining_mult = 1;
    uint32_t lword = 0;
    uint8_t lbytes = 0;

    for(i=0; i<4; i++){
        if(packet->pos < packet->remaining_length){
            lbytes++;
            byte = packet->payload[packet->pos];
            lword += (byte & 127) * remaining_mult;
            remaining_mult *= 128;
            packet->pos++;
            if((byte & 128) == 0){
                if(lbytes > 1 && byte == 0){
                    return MOSQ_ERR_MALFORMED_PACKET;
                }else{
                    *word = lword;
                    if(bytes){
                        (*bytes) = lbytes;
                    }
                    return MOSQ_ERR_SUCCESS;
                }
            }
        }else{
            return MOSQ_ERR_MALFORMED_PACKET;
        }
    }
    return MOSQ_ERR_MALFORMED_PACKET;
}

int main(void)
{
    uint8_t buf[5];
    for (int i = 0; i < 5; i++) {
        buf[i] = __VERIFIER_nondet_uchar();
    }

    struct mosquitto__packet_in p;
    p.payload          = buf;
    p.pos              = 0;
    p.remaining_length = 5;

    uint32_t word = 0;
    uint8_t  used = 0;
    int rc = packet__read_varint(&p, &word, &used);

    __ESBMC_assert(p.pos <= 4,
        "Remaining Length: no maximo 4 bytes de continuacao");

    if (rc == MOSQ_ERR_SUCCESS) {
        __ESBMC_assert(word <= MQTT_MAX_REMAINING_LENGTH,
            "Remaining Length: valor dentro do limite MQTT");
        __ESBMC_assert(used >= 1 && used <= 4,
            "Remaining Length: contagem de bytes valida");
    }

    return 0;
}
