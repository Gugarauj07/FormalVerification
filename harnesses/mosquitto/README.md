# Harnesses Eclipse Mosquitto + ESBMC

Harnesses isolados para verificação formal de CVEs históricos e recentes do broker Mosquitto.

## Pré-requisito

ESBMC 8.x no PATH, ou use o binário em `tools/esbmc/bin/esbmc.exe` (Windows).

```powershell
$env:ESBMC = "..\..\tools\esbmc\bin\esbmc.exe"   # a partir desta pasta
```

## Executar todos os casos

```powershell
.\run_all.ps1
```

## CVEs cobertos

| Harness | CVE | Flags ESBMC esperadas | Resultado esperado |
|---------|-----|----------------------|-------------------|
| `remaining_length_harness.c` | CVE-2017-7651 | `--unwind 8 --unsigned-overflow-check` | FAILED (overflow / assert) |
| `connect_memleak_harness.c` | CVE-2017-7654 | `--unwind 16 --memory-leak-check` | FAILED (CWE-401 leak) |
| `read_binary_obo_harness.c` | CWE-193 (parser) | `--unwind 8` | FAILED (assert OOB) |
| `acl_bypass_harness.c` | CVE-2017-7650 | `--unwind 32` | FAILED (ACL bypass) |
| `acl_bypass_harness_fixed.c` | fix 7650 | `--unwind 32` | SUCCESSFUL |
| `will_properties_memleak_harness.c` | CVE-2023-3592 | `--unwind 8 --memory-leak-check` | FAILED (vuln) / SUCCESSFUL (fix) |
| `initial_packet_state_harness.c` | CVE-2023-0809 | `--unwind 4` | FAILED (vuln) / SUCCESSFUL (fix) |
| `qos2_dup_leak_harness.c` | CVE-2023-28366 | `--unwind 8 --memory-leak-check` (vuln) | FAILED (vuln) |
| `qos2_dup_leak_harness_fixed.c` | CVE-2023-28366 fix | `--unwind 8` | SUCCESSFUL |
| `bridge_remap_double_free_harness.c` | CVE-2024-3935 | `--unwind 8 --memory-leak-check` | FAILED (vuln) / SUCCESSFUL (fix) |
| `varint_harness.c` | propriedade MQTT (2.1.x) | `--unwind 8` | SUCCESSFUL |
| `max_packet_size_harness.c` | propriedade 2.1.x | `--unwind 8` | SUCCESSFUL |
| `packet_recv_remaining_length_harness.c` | CVE-2017-7651 via `recv` | `--unwind 8 --unsigned-overflow-check` + `network_stubs.c` | FAILED (integração) |
| `packet_recv_remaining_length_harness_fixed.c` | fix 7651 via `recv` | `--unwind 8` + `network_stubs.c` | SUCCESSFUL |
| `packet_recv_initial_command_harness.c` | CVE-2023-0809 via `recv` | `--unwind 4` + `network_stubs.c` | FAILED |
| `packet_recv_initial_command_harness_fixed.c` | fix 0809 via `recv` | `--unwind 4` + `network_stubs.c` | SUCCESSFUL |
| `proxy_v2_tlv_harness.c` | underflow PROXY v2 SSL TLV (2.1.x) | `--unsigned-overflow-check` | FAILED |
| `proxy_v2_tlv_harness_fixed.c` | fix PROXY v2 | `--unsigned-overflow-check` | SUCCESSFUL |

Logs gerados: `*.log` neste diretório.

## Benchmark (tempo e memória)

```powershell
.\run_bench.ps1
```

Gera `bench_results.csv` com tempo de wall-clock e pico de memória por harness.

## Harnesses de integração (operational models)

Estes harnesses leem bytes **via `recv()`** em vez de buffers fixos. Compilam junto com `esbmc_models/network_stubs.c`, que modela `socket`, `recv`, `send`, `select` e `poll` com bytes não-determinísticos (entrada simbólica do atacante). Header compartilhado: `esbmc_models/network_common.h`.

## Metodologia

1. Extrair função vulnerável do commit/tag Mosquitto (NVD + `git show`).
2. Reduzir structs e dependências ao mínimo.
3. Entrada simbólica via `__VERIFIER_nondet_*` + `__ESBMC_assume`.
4. Propriedade de segurança em `__ESBMC_assert` ou checks nativos (`--memory-leak-check`, `--unsigned-overflow-check`).
5. Repetir com versão corrigida (arquivo `_fixed` ou função `*_fixed`).
