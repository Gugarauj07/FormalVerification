# Responsible Disclosure Draft — Eclipse Mosquitto

**Submit via**: https://gitlab.eclipse.org/security/vulnerability-reports/-/issues/new?issuable_template=new_vulnerability  
**OR email**: security@eclipse-foundation.org  
**Project**: Eclipse Mosquitto (https://github.com/eclipse-mosquitto/mosquitto)

---

## Vulnerability Report: Integer Underflow in PROXY Protocol v2 SSL TLV Parser

### Summary

An integer underflow (CWE-191) exists in `src/proxy_v2.c`, function
`read_tlv_ssl()`, in all currently released versions of Eclipse Mosquitto that
include PROXY Protocol v2 support. A malformed PROXY v2 header causes the
`len` counter (uint16_t) to wrap from a small value to ~65,535, leading the
parser to read bytes beyond the declared SSL TLV boundary.

The vulnerability was discovered using the ESBMC bounded model checker as part
of formal-verification research on the Mosquitto codebase.

---

### Affected Versions

- Confirmed on: **master branch** (`v2.1.2-132-ga609c263`, June 2026)
- Likely affects all versions since PROXY Protocol v2 SSL TLV support was added
- **Requires** `proxy_protocol true` in `mosquitto.conf` (i.e., the broker is
  deployed behind a load balancer / reverse proxy that injects PROXY v2 headers)

---

### Technical Details

**File**: `src/proxy_v2.c`  
**Function**: `read_tlv_ssl(struct mosquitto *context, uint16_t len, bool *have_certificate)`

After consuming the 5-byte mandatory SSL header (`client` + `verify`), the
function loops over inner TLVs:

```c
while(len > 0){
    if(context->proxy.len - context->proxy.pos < (int)sizeof(struct pp2_tlv)){
        return MOSQ_ERR_INVAL;      // (A) checks global buffer
    }
    struct pp2_tlv *tlv = (struct pp2_tlv *)(&context->proxy.buf[context->proxy.pos]);
    uint16_t tlv_len = (uint16_t)((tlv->length_h<<8) + tlv->length_l);
    context->proxy.pos = (uint16_t)(context->proxy.pos + sizeof(struct pp2_tlv));

    if(tlv_len > context->proxy.len - context->proxy.pos){
        return MOSQ_ERR_INVAL;      // (B) checks global buffer
    }
    // ... switch(tlv->type) { ... }

    // BUG: NO check that (3 + tlv_len) <= len before this subtraction
    len = (uint16_t)(len - (sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + tlv_len));
    //            = (uint16_t)(len - (3 + tlv_len))
    context->proxy.pos = (uint16_t)(context->proxy.pos + tlv_len);
}
```

Check **(A)** and check **(B)** both validate `tlv_len` against the **global
proxy buffer** (max 500 bytes via `PROXY_PACKET_LIMIT`), but neither validates
`tlv_len` against the **remaining space declared by the SSL TLV** (`len`).

**Missing check** (fix):
```c
if((uint32_t)3 + (uint32_t)tlv_len > (uint32_t)len){
    return MOSQ_ERR_INVAL;
}
```

---

### Concrete Attack Scenario

An attacker sends a PROXY v2 header (requires network access to a listener with
`proxy_protocol true`) containing an SSL TLV where:

| Field | Value | Explanation |
|---|---|---|
| SSL TLV outer length | 8 | 5 bytes header + 3 bytes inner TLV header |
| `ssl.client` | 0x01 | PP2_CLIENT_SSL |
| `ssl.verify` | 0x00000000 | 4 bytes |
| Inner TLV type | 0x22 | PP2_SUBTYPE_SSL_CN |
| Inner TLV length | 1 | 1 byte of data follows |
| Proxy buffer | ...any bytes... | |

Execution trace:
1. `len = 8 − 5 = 3` (after reading SSL mandatory header)
2. `tlv_len = 1` (from inner TLV header bytes)
3. Check (B): `1 ≤ 500 − pos` — **PASSES** (global buffer still has space)
4. Switch case PP2_SUBTYPE_SSL_CN may set `context->username` (if `use_identity_as_username true`)
5. **`len = (uint16_t)(3 − (3 + 1)) = (uint16_t)(−1) = 65535`** — UNDERFLOW
6. Loop continues reading ~167 extra TLV iterations from the proxy buffer
7. Eventually check (A) fires (buffer exhausted) → `MOSQ_ERR_INVAL` returned
8. `proxy_v2__read` rejects the connection: `MOSQ_ERR_PROXY`

The connection is always rejected. Side effects during the extra iterations:
- `context->proxy.tls_version`, `context->proxy.cipher`, or `context->username`
  may be written from bytes outside the SSL TLV's declared scope (though all
  bytes are in the attacker-controlled proxy buffer).

---

### CVSS v3.1 Estimate

```
AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N
Base Score: ~3.7 (Low)
```

`AC:H` because the attack requires `proxy_protocol true` (non-default
configuration, typically only used behind a load balancer); the load balancer
itself would ordinarily be the source of PROXY headers.

---

### Proof of Concept (Formal Verification)

The attached ESBMC harness (`proxy_v2_tlv_harness.c`) models the inputs
symbolically and asserts the missing property. ESBMC 8.3 (z3 solver) produces
a counterexample in < 1 second:

```
Violated property:
  proxy_v2 read_tlv_ssl: underflow em `len` -- inner TLV (3 + tlv_len) excede
  SSL TLV remaining (len)
  3 + (unsigned int)tlv_len <= (unsigned int)len

Counterexample:
  ssl_tlv_len = 256   →   len = 251 (after SSL header)
  tlv_len     = 253   →   passes buffer check (253 ≤ 492)
  3 + 253 = 256 > 251 → len wraps to 65531
```

The fixed harness (`proxy_v2_tlv_harness_fixed.c`) adds the missing check and
ESBMC reports VERIFICATION SUCCESSFUL.

---

### Proposed Fix

In `read_tlv_ssl()`, add the following check immediately before the
problematic subtraction (around line 150 of `src/proxy_v2.c`):

```c
// Add this check:
if((uint32_t)sizeof(struct pp2_tlv) + (uint32_t)tlv_len > (uint32_t)len){
    return MOSQ_ERR_INVAL;
}
// Existing line:
len = (uint16_t)(len - (sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + tlv_len));
```

---

### Note on Existing Fuzzer

Commit `23c918ee` (January 2026) added `fuzzing/broker/broker_fuzz_proxy_v2.cpp`
for PROXY v2 testing and fixed several related issues. The fuzzer did not detect
this specific underflow, which was only found via symbolic/formal verification.
Extending the fuzzer corpus with a seed that has `ssl_outer_tlv_len < inner_3+tlv_len`
may help prevent regressions.

---

### Reporters

Gustavo Lima, Willian Jean, Paulo Gomes  
Universidade [...]  
(Research context: formal verification of Eclipse Mosquitto using ESBMC)
