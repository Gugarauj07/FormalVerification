/*
 * proxy_v2_tlv_harness.c  --  Mosquitto 2.1.x (master, jun/2026)
 *
 * Harness para verificar o parser de sub-TLVs SSL no PROXY Protocol v2,
 * funcao read_tlv_ssl() em mosquitto/src/proxy_v2.c.
 *
 * Vulnerabilidade investigada
 * ---------------------------
 * A funcao read_tlv_ssl recebe um parametro `len` representando o numero de
 * bytes da carga util da SSL TLV externa. Em cada iteracao do loop, ela
 * subtrai (3 + tlv_len) de `len`. Contudo, a unica verificacao de limite
 * feita antes da subtracao e:
 *
 *   if(tlv_len > context->proxy.len - context->proxy.pos)
 *     return MOSQ_ERR_INVAL;
 *
 * Essa verificacao compara tlv_len contra o buffer GLOBAL (proxy.len - pos),
 * mas NAO contra o espaco restante DENTRO DA SSL TLV (`len`). Se um atacante
 * enviar uma SSL TLV com `len` pequeno (ex: 8 bytes), mas cujo TLV interno
 * declare `tlv_len` = 1, entao:
 *
 *   len = (uint16_t)(8 - 5) = 3          (apos ler cabecalho SSL)
 *   tlv_len = 1                           (do cabecalho pp2_tlv)
 *   buffer check: 1 <= global_space  OK  (buffer ainda tem espaco)
 *   len = (uint16_t)(3 - (3 + 1))        (underflow: -1 wraps para 65535)
 *   loop continua por ate ~21845 iter.   (DoS potencial)
 *
 * Propriedade verificada
 * ----------------------
 *   Para todo caminho de execucao, (3 + tlv_len) <= len
 *   deve ser verdade antes da subtracao.
 *
 * Nota sobre o harness
 * --------------------
 * Os valores de ssl_tlv_len e tlv_len sao modelados como entradas simbolicas
 * independentes (sem loop de inicializacao de buffer), o que permite ao ESBMC
 * explorar o espaco de estados sem restricoes de unrolling.
 *
 * Executar:
 *   esbmc proxy_v2_tlv_harness.c --unsigned-overflow-check
 */

#include <stdint.h>
#include <stddef.h>

/* ---- Constantes (proxy_v2.c) ---- */
#define MOSQ_ERR_SUCCESS   0
#define MOSQ_ERR_INVAL     3

/* Limite maximo do buffer PROXY (PROXY_PACKET_LIMIT em mosquitto) */
#define PROXY_PACKET_LIMIT 500

/* ---- Intrinsicos ESBMC ---- */
extern int __VERIFIER_nondet_int(void);

int main(void)
{
    /*
     * ssl_tlv_len: comprimento declarado pelo campo SSL TLV no cabecalho
     * PROXY v2 -- inteiramente controlado pelo cliente/atacante.
     */
    uint16_t ssl_tlv_len = (uint16_t)__VERIFIER_nondet_int();
    __ESBMC_assume(ssl_tlv_len >= 5);                  /* precisa ter o cabecalho SSL de 5 bytes */
    __ESBMC_assume(ssl_tlv_len <= PROXY_PACKET_LIMIT); /* limitado pelo buffer global            */

    /*
     * Calculo de `len` como em read_tlv_ssl: subtrai 5 bytes do cabecalho
     * SSL obrigatorio (1 byte client + 4 bytes verify).
     */
    uint16_t len = (uint16_t)(ssl_tlv_len - 5);

    if(len > 0){
        /*
         * pos_after_tlv_hdr: posicao do buffer apos consumir cabecalho SSL
         * (pos inicial do TLV externo) + 5 bytes SSL + 3 bytes pp2_tlv.
         * Conservativamente assuma pos inicial = 0.
         */
        int pos_after_tlv_hdr = 5 + 3; /* = 8 */

        /*
         * tlv_len: bytes de dados declarados pelo sub-TLV interno.
         * Tambem controlado pelo atacante (esta nos bytes do buffer).
         * A UNICA verificacao presente no codigo original e que
         * tlv_len <= espaco restante no BUFFER GLOBAL:
         */
        uint16_t tlv_len = (uint16_t)__VERIFIER_nondet_int();
        __ESBMC_assume((int)tlv_len <= PROXY_PACKET_LIMIT - pos_after_tlv_hdr);
        /* (Esta e exatamente a verificacao que o codigo original faz.)  */

        /*
         * PROPRIEDADE: antes de executar
         *   len = (uint16_t)(len - (3 + tlv_len));
         * o codigo deveria garantir que (3 + tlv_len) <= len.
         * O codigo original NAO faz isso, portanto a propriedade
         * pode ser violada (underflow unsigned).
         */
        __ESBMC_assert(
            (uint32_t)3 + (uint32_t)tlv_len <= (uint32_t)len,
            "proxy_v2 read_tlv_ssl: underflow em `len` -- "
            "inner TLV (3 + tlv_len) excede SSL TLV remaining (len)"
        );
    }

    return 0;
}
