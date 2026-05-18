/*
 * Harness para verificacao formal do parser de varints MQTT
 * do Eclipse Mosquitto com ESBMC.
 *
 * A funcao packet__read_varint() abaixo eh copia literal de
 *   mosquitto/lib/packet_datatypes.c
 * commit a609c2630444e103ae5d249dcb685f604828868f (v2.1.2-132-ga609c263).
 *
 * A struct mosquitto__packet_in foi reduzida ao minimo necessario
 * para verificacao isolada (apenas payload + pos + remaining_length).
 *
 * Codigos de retorno do Mosquitto, simplificados.
 */

#include <stdint.h>
#include <stddef.h>

#define MOSQ_ERR_SUCCESS           0
#define MOSQ_ERR_MALFORMED_PACKET 13

#define MQTT_MAX_REMAINING_LENGTH 268435455U /* 128^4 - 1 */

struct mosquitto__packet_in {
    uint8_t *payload;
    uint32_t pos;
    uint32_t remaining_length;
};

/* ============================================================
 * Copia literal de packet__read_varint() em
 *   mosquitto/lib/packet_datatypes.c
 * ============================================================ */
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

/* ============================================================
 * Harness: pacote de ate 5 bytes nao deterministicos.
 * ============================================================ */
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

    /* Propriedade 1: a funcao nunca consome mais que 4 bytes. */
    __ESBMC_assert(p.pos <= 4,
        "Mosquitto packet__read_varint nao deve consumir mais de 4 bytes");

    /* Propriedade 2: em caso de sucesso, o valor cabe no maximo MQTT. */
    if (rc == MOSQ_ERR_SUCCESS) {
        __ESBMC_assert(word <= MQTT_MAX_REMAINING_LENGTH,
            "Mosquitto packet__read_varint: word excede o maximo MQTT");
        __ESBMC_assert(used >= 1 && used <= 4,
            "Mosquitto packet__read_varint: numero de bytes consumidos invalido");
    }

    return 0;
}
