/*
 * proxy_v2_tlv_harness_fixed.c  --  Mosquitto 2.1.x (master, jun/2026)
 *
 * Versao CORRIGIDA do harness proxy_v2_tlv_harness.c.
 *
 * Correcao aplicada: adicionada verificacao
 *   if(len < 3 + tlv_len) return MOSQ_ERR_INVAL;
 * antes da subtracao em read_tlv_ssl, garantindo que `len` nunca sofra
 * underflow unsigned.
 *
 * Espera-se VERIFICATION SUCCESSFUL neste harness.
 *
 * Executar:
 *   esbmc proxy_v2_tlv_harness_fixed.c --unsigned-overflow-check
 */

#include <stdint.h>
#include <stddef.h>

#define MOSQ_ERR_SUCCESS   0
#define MOSQ_ERR_INVAL     3
#define PROXY_PACKET_LIMIT 500

extern int __VERIFIER_nondet_int(void);

int main(void)
{
    uint16_t ssl_tlv_len = (uint16_t)__VERIFIER_nondet_int();
    __ESBMC_assume(ssl_tlv_len >= 5);
    __ESBMC_assume(ssl_tlv_len <= PROXY_PACKET_LIMIT);

    uint16_t len = (uint16_t)(ssl_tlv_len - 5);

    if(len > 0){
        int pos_after_tlv_hdr = 5 + 3;

        uint16_t tlv_len = (uint16_t)__VERIFIER_nondet_int();
        __ESBMC_assume((int)tlv_len <= PROXY_PACKET_LIMIT - pos_after_tlv_hdr);

        /*
         * CORRECAO: verificar que 3 + tlv_len <= len antes da subtracao.
         * O codigo deveria retornar MOSQ_ERR_INVAL neste caso.
         */
        if((uint32_t)3 + (uint32_t)tlv_len > (uint32_t)len){
            return MOSQ_ERR_INVAL; /* FIX: rejeita pacote malformado */
        }

        /* Com a verificacao acima, esta subtracao nunca pode sofrer underflow */
        len = (uint16_t)(len - (3 + tlv_len));

        /* Propriedade: len permanece <= ssl_tlv_len - 5 (monotonicamente decrescente) */
        __ESBMC_assert(
            (uint32_t)len <= (uint32_t)(ssl_tlv_len - 5),
            "proxy_v2 read_tlv_ssl (fixed): len nunca excede o valor inicial"
        );
    }

    return 0;
}
