# Operational models (protótipo)

Arquivo `network_stubs.c`: modelos mínimos de `socket`, `bind`, `listen`, `accept`, `recv`, `send`, `close`, `select` e `poll` para compilação com ESBMC.

Exemplo:

```text
esbmc meu_teste.c esbmc_models/network_stubs.c --unwind 8
```

Ver também [docs/api_catalog.md](../docs/api_catalog.md).

Arquivos:
- `network_stubs.c` — stubs (`socket`, `recv`, `send`, `select`, `poll`, …)
- `network_common.h` — declarações compartilhadas para harnesses de integração
