# Responsible Disclosure — Eclipse Mosquitto

**Status**: enviado (junho/2026) — [Eclipse Security Report #551](https://gitlab.eclipse.org/security/vulnerability-reports/-/work_items/551)
**Project**: Eclipse Mosquitto (https://github.com/eclipse-mosquitto/mosquitto)

---

## Issue title: [Eclipse Mosquitto] Integer Underflow in PROXY v2 SSL TLV Parser (CWE-191)

---

## Basic information

**Project name:** Eclipse Mosquitto

**Project id:** iot.mosquitto

## What are the affected versions?

Confirmed on master branch (`v2.1.2-132-ga609c263`, June 2026).
Likely affects all versions since PROXY Protocol v2 SSL TLV support was added.
Requires `proxy_protocol true` in `mosquitto.conf`.

## Details of the issue

An integer underflow (CWE-191) exists in `src/proxy_v2.c`, function
`read_tlv_ssl()`. After consuming the 5-byte mandatory SSL header, the function
loops over inner TLVs decrementing a `uint16_t len` counter:

```c
len = (uint16_t)(len - (3 + tlv_len));
```

The existing checks (A) and (B) validate `tlv_len` against the global proxy
buffer, but neither validates against the remaining space declared by the SSL TLV
(`len`). If `3 + tlv_len > len`, the subtraction is evaluated as signed `int`
(implicit C promotion), yields a negative value, and is truncated to `uint16_t`,
wrapping to ~65,535. The loop then continues reading bytes well beyond the SSL
TLV's declared boundary.

The connection is always ultimately rejected (`MOSQ_ERR_PROXY`), but during
the extra iterations `context->proxy.tls_version`, `context->proxy.cipher`,
or `context->username` may be overwritten from attacker-controlled bytes
outside the SSL TLV's declared scope.

CVSS v3.1 estimate: `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N` — Base Score ~3.7 (Low)
(`AC:H` because `proxy_protocol true` is a non-default configuration)

**Proposed fix** — add immediately before the subtraction (~line 150 of `src/proxy_v2.c`):

```c
if((uint32_t)sizeof(struct pp2_tlv) + (uint32_t)tlv_len > (uint32_t)len){
    return MOSQ_ERR_INVAL;
}
```

## Steps to reproduce

Send a PROXY v2 header to a broker with `proxy_protocol true`, containing an
SSL TLV where the inner TLV's declared length exceeds the SSL TLV's remaining
space. Concrete counterexample found by ESBMC:

- `ssl_tlv_len = 256` → `len = 251` (after reading the 5-byte SSL header)
- `tlv_len = 253` → passes global buffer check (`253 ≤ 492`)
- `3 + 253 = 256 > 251` → `len` wraps to **65531**

**Formal proof of concept (ESBMC 8.3, z3 solver, < 1 s):**

Vulnerable harness — run with `esbmc proxy_v2_tlv_harness.c --unsigned-overflow-check` → **VERIFICATION FAILED**:

```c
#include <stdint.h>
#include <stddef.h>

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

        /* Missing check in original code: */
        __ESBMC_assert(
            (uint32_t)3 + (uint32_t)tlv_len <= (uint32_t)len,
            "proxy_v2 read_tlv_ssl: underflow in `len` -- "
            "inner TLV (3 + tlv_len) exceeds SSL TLV remaining (len)"
        );
    }
    return 0;
}
```

Fixed harness — run with `esbmc proxy_v2_tlv_harness_fixed.c --unsigned-overflow-check` → **VERIFICATION SUCCESSFUL**:

```c
#include <stdint.h>
#include <stddef.h>

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

        /* Proposed fix: */
        if((uint32_t)3 + (uint32_t)tlv_len > (uint32_t)len){
            return MOSQ_ERR_INVAL;
        }

        len = (uint16_t)(len - (3 + tlv_len));

        __ESBMC_assert(
            (uint32_t)len <= (uint32_t)(ssl_tlv_len - 5),
            "proxy_v2 read_tlv_ssl (fixed): len never exceeds initial value"
        );
    }
    return 0;
}
```

This vulnerability was discovered using the ESBMC bounded model checker as part
of formal-verification research on the Mosquitto codebase at UFAM (Universidade
Federal do Amazonas), under supervision of Prof. Lucas Cordeiro.

Reporters: Gustavo Lima, Willian Jean, Paulo Gomes

## Do you know any mitigations of the issue?

Set `proxy_protocol false` (the default) in `mosquitto.conf`. The vulnerability
is only reachable when the broker is configured to accept PROXY Protocol v2
headers, typically when deployed behind a load balancer.

/confidential
