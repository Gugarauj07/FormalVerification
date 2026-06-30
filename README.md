# Formal Verification — Eclipse Mosquitto + ESBMC

Verificação formal de vulnerabilidades no broker MQTT Eclipse Mosquitto usando o [ESBMC](https://github.com/esbmc/esbmc) (context-bounded model checking).

Trabalho de graduação — UFAM, orientação Prof. Lucas Cordeiro.

## Estrutura

| Diretório | Conteúdo |
|-----------|----------|
| [`harnesses/mosquitto/`](harnesses/mosquitto/) | 21 harnesses ESBMC (CVEs históricos, integração com `recv`, achado em `proxy_v2.c`) |
| [`esbmc_models/`](esbmc_models/) | Operational models de rede (referência local; integrados ao `c2goto` via PR upstream) |
| [`docs/api_catalog.md`](docs/api_catalog.md) | Catálogo de APIs do Mosquitto vs. cobertura de modelos |
| [`paper/`](paper/) | Relatório (`main.tex`) e [disclosure Eclipse #551](paper/disclosure_draft.md) |
| [`slides/`](slides/) | Apresentação da defesa final |

## Executar os harnesses

```powershell
cd harnesses/mosquitto
.\run_all.ps1      # todos os casos
.\run_bench.ps1    # benchmark (tempo e memória)
```

Requer ESBMC 8.x no `PATH`.

## Achado principal (`v2.1.2-132-ga609c263`)

Integer underflow (CWE-191) em `src/proxy_v2.c` (`read_tlv_ssl`). Reportado ao [Eclipse Security #551](https://gitlab.eclipse.org/security/vulnerability-reports/-/work_items/551) (junho/2026).

## Status (jun./2026)

- **Concluído**: metodologia validada em 7 CVEs; modelos de rede no `c2goto` (PR aceito); disclosure enviado; paper e slides finais preparados.
- **Em andamento**: acompanhamento da resposta do Eclipse (CVE/patch) e verificação de módulos reais do Mosquitto.
- **Trabalho futuro**: modelos `epoll`/`getaddrinfo`/TLS.
