# Catálogo de APIs externas — Mosquitto broker vs ESBMC

## Metodologia de levantamento

1. Objetivo: compilar `src/mosquitto.c` e bibliotecas do broker com ESBMC (front-end C).
2. Registrar símbolos não modelados (undefined function) e dependências de SO.
3. Agrupar por subsistema para priorizar modelos incrementais.

## APIs POSIX de rede (prioridade alta)

| API | Uso no Mosquitto | Impacto sem modelo | Status |
|-----|------------------|--------------------|--------|
| `socket` | listeners TCP/UDP | Estado de rede indefinido | **modelado** (`network_stubs.c`) |
| `bind` / `listen` / `accept` | aceitar conexões | Idem | **modelado** |
| `connect` | bridges outbound | Idem | stub trivial (retorna 0) |
| `send` / `recv` / `write` / `read` | I/O de pacotes MQTT | Traces não reproduzíveis | **modelado** |
| `select` / `poll` | loop principal do broker | Bloqueio / eventos abstratos | **modelado** (`network_stubs.c`) |
| `epoll_*` | loop principal (Linux) | Bloqueio / eventos abstratos | pendente |
| `getaddrinfo` / `getnameinfo` | resolução DNS | Não determinístico | pendente |

## APIs de sistema e tempo

| API | Uso |
|-----|-----|
| `pthread_*` | workers, mutexes |
| `clock_gettime` / `time` | keepalive, expiração |
| `signal` / `daemon` | modo serviço |

## TLS (WITH_TLS)

`SSL_*`, `TLS_*` — exigem modelo criptográfico ou stub que abstrai handshakes.

## Protótipo mínimo implementado

Ver [esbmc_models/network_stubs.c](../esbmc_models/network_stubs.c): stubs de `socket`, `recv`, `send`, `select` e `poll` com buffer simbólico e retorno nondet — suficientes para harnesses de integração, mas **não** substituem o broker completo.

## Subsistemas verificáveis sem rede (estado atual)

- Parser MQTT: `packet__read_varint`, Remaining Length, campos binários.
- ACL padrão: `mosquitto_acl_check_default` (v1.4.x).
- Propriedades MQTT v5 Will: `property__process_will`.
- Guards de protocolo: primeiro pacote CONNECT.
- Bridge topic remap (lógica de ponteiros).

## Harnesses de integração com `recv` (implementado)

| Harness | CVE | Resultado |
|---------|-----|-----------|
| `packet_recv_remaining_length_harness.c` | 2017-7651 | FAILED (overflow) |
| `packet_recv_remaining_length_harness_fixed.c` | fix | SUCCESSFUL |
| `packet_recv_initial_command_harness.c` | 2023-0809 | FAILED |
| `packet_recv_initial_command_harness_fixed.c` | fix | SUCCESSFUL |

Compilação: `esbmc harness.c esbmc_models/network_stubs.c --unwind N`.

## Novo achado (proxy_v2.c, 2.1.x)

| Harness | Tipo | Resultado |
|---------|------|-----------|
| `proxy_v2_tlv_harness.c` | underflow uint16 em `read_tlv_ssl` | FAILED |
| `proxy_v2_tlv_harness_fixed.c` | fix proposto | SUCCESSFUL |

## Próximo passo

Incorporar modelos em `socket_lib.c` na biblioteca c2goto do ESBMC (fork local) e verificar trechos reais de `packet_mosq.c` / loop principal com `select`/`poll`.
