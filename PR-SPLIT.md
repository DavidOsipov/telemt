# PR-421 Split Plan

**Original branch:** `pr-security-hardening`  
**Base:** `upstream/main` (`dda31b3`)  
**Total scope:** 85 files changed, +14 666 / −1 895 lines  

The original PR spans 9 architectural layers. A reviewer cannot hold enough context to evaluate invariant correctness across the full diff simultaneously — each layer has a different threat model (TLS anti-fingerprinting vs. SSRF filtering vs. replay-protection shards). This document records how the single big PR was split into 9 independent, stacked branches, each compilable and passing `cargo test` in isolation.

---

## Merge Order

Each branch depends on the one above it. Merge strictly in this order. After each merge, CI must be green before the next PR is opened.

```
upstream/main
    └── pr-sec-1   (CI & infra)
            └── pr-sec-2   (Crypto & Protocol Foundation)
                    └── pr-sec-3   (Stream Layer)
                            └── pr-sec-4   (TLS Fronting)
                                    └── pr-sec-5   (SSRF & Network)
                                            └── pr-sec-6a  (Middle Proxy Wire)
                                                    └── pr-sec-6b  (Middle Proxy Pool & Secrets)
                                                            └── pr-sec-7   (Stats & Replay Protection)
                                                                    └── pr-sec-8   (API / Config / Orchestration)
```

---

## PR Descriptions

### PR-SEC-1 — CI & Security Policy Infrastructure
**Branch:** `pr-sec-1` · **Commit:** `718fcba` · **Files:** 5  
**Depends on:** nothing (base: `upstream/main`)

No Rust source changes. Establishes the CI gates that all subsequent PRs must pass.

| File | Change |
|------|--------|
| `.cargo/deny.toml` | New — license and advisory policy for `cargo deny` |
| `.github/workflows/security.yml` | New — `cargo audit` + `cargo deny` on every push |
| `.github/workflows/rust.yml` | Updated — adds `Check benches compile`; Clippy gated at `-D clippy::correctness` only (strict policy deferred to PR-SEC-8) |
| `Cargo.toml` / `Cargo.lock` | Audit-related dependency additions |

> **Note:** Both `.cargo/config.toml` (the `rustflags` lint policy) and the strict Clippy enforcement in `rust.yml` are intentionally deferred to **PR-SEC-8**. Adding them here would break every intermediate branch before the source fixes land — see Cross-Cutting Design Notes for the full rationale.

---

### PR-SEC-2 — Crypto & Protocol Foundation
**Branch:** `pr-sec-2` · **Commit:** `c7e1608` · **Files:** 10  
**Depends on:** PR-SEC-1

Leaf modules only — nothing in the rest of the codebase that is changed here depends on anything changed later.

| File | Key change |
|------|------------|
| `src/error.rs` | New structured error variants for validation paths |
| `src/crypto/aes.rs` | Bounds-checked slice indexing; zeroize key material on drop |
| `src/crypto/hash.rs` | `unreachable!()` → `#[allow(clippy::expect_used)]` + `.expect()`; `clippy::panic` is globally denied but this call is structurally infallible |
| `src/crypto/random.rs` | Document CSPRNG interface; add adversarial-RNG test |
| `src/crypto/mod.rs` | Re-export compatibility shim (dropped in PR-SEC-6a) |
| `src/protocol/constants.rs` | Explicit `RESERVED_NONCE_FIRST_BYTES` / `RESERVED_NONCE_BEGINNINGS` arrays |
| `src/protocol/obfuscation.rs` | `unreachable!()` → `#[allow(clippy::panic)]` + `panic!()`; add `generate_nonce_panics_when_rng_always_returns_invalid_nonces` regression test |
| `src/protocol/tls.rs` | Stricter SessionID (≤32 bytes) and ALPN (≤255 bytes) validation |
| `src/protocol/frame.rs` · `mod.rs` | Coordinated updates |
| `src/util/ip.rs` | Deny bogon / loopback / link-local / private ranges — SSRF foundation used by later PRs |

**Black-hat tests to add in review:**
- Adversarial RNG returning invalid nonces on all 64 attempts → must panic with comprehensible message
- Every single-byte `RESERVED_NONCE_FIRST_BYTES` value individually verified by `is_valid_nonce`

---

### PR-SEC-3 — Stream Layer: Memory Safety & Protocol Framing
**Branch:** `pr-sec-3` · **Commit:** `5e05660` · **Files:** 9  
**Depends on:** PR-SEC-2

All 9 files are within `src/stream/`. Self-contained data-path layer.

| File | Key change |
|------|------------|
| `src/stream/buffer_pool.rs` | `fill(0u8)` + `clear()` before pool return — satisfies OWASP ASVS L2 V8.3.6; allocation stays live so the zeroization cannot be elided |
| `src/stream/frame_codec.rs` | Abridged / intermediate / secure framing invariants under QuickAck, zero-padding, and oversized frames |
| `src/stream/crypto_stream.rs` | Guard against CTR-mode drift on partial / blocked writes |
| `src/stream/tls_stream.rs` | TLS fatal alert `0x15 0x02 0xXX` must produce `ConnectionReset`, not clean EOF |
| `src/stream/frame_stream.rs` | Checked arithmetic on accumulated frame lengths |
| `src/stream/state.rs` · `traits.rs` · `frame.rs` · `mod.rs` | Coordinated state-machine updates |

**Black-hat tests to add in review:**
- Stream a frame with declared length `u32::MAX`
- Send 1-byte-at-a-time writes to trigger all partial-write paths
- Poison state → verify all subsequent operations return errors without panicking

---

### PR-SEC-4 — TLS Fronting & Anti-Fingerprinting
**Branch:** `pr-sec-4` · **Commit:** `3446e42` · **Files:** 4  
**Depends on:** PR-SEC-3

**Highest-stakes PR.** Active censorship probes work by comparing the server's TLS fingerprint against known-good nginx/Apache responses. Any distinguishable difference in the error path is observable. This PR contains the most security-critical single fix in the entire split.

| File | Key change |
|------|------------|
| `src/tls_front/fetcher.rs` | **Bug fix:** fallback branch used `ClientConfig::builder()` (global default provider) instead of `ClientConfig::builder_with_provider(provider.clone())` — silently switches crypto backend from `ring` to the system default precisely in the error path |
| `src/tls_front/cache.rs` | Rate-limit map flood protection; strict SessionID `> 32 bytes` rejection before `ServerHello` construction |
| `src/tls_front/emulator.rs` | `ServerHello` hardened against non-standard extension ordering |
| `src/tls_front/types.rs` | Coordinated type updates |

**Black-hat tests to add in review:**
- `ClientHello` with non-standard extension ordering → response indistinguishable from nginx/Apache
- `SessionID > 32 bytes` → rejected before `ServerHello` construction
- `ALPN string > 255 bytes` → clipped / rejected
- TLS fatal alert `0x15 0x02 0xXX` → `ConnectionReset`, not clean EOF
- Rate-limit map flood with 100 000 unique IPs → memory is bounded

---

### PR-SEC-5 — SSRF & Network Filters
**Branch:** `pr-sec-5` · **Commit:** `d4353cd` · **Files:** 6  
**Depends on:** PR-SEC-2 (for `util/ip.rs::is_bogon`); orthogonal to PR-SEC-3/4

| File | Key change |
|------|------------|
| `src/network/probe.rs` | Enforce bogon / loopback / private-range rejection via `is_bogon()` before outbound probe |
| `src/network/stun.rs` | Validate STUN response source against bogon ranges |
| `src/transport/proxy_protocol.rs` | PROXY v1 header length cap (107-byte spec limit); PROXY v2 family/address mismatch detection (TCP4 + IPv6 payload → rejected) |
| `src/transport/socket.rs` | Remove trivial `&i32 as *const i32` pointer casts; fix hidden lifetime parameters (`rust_2018_idioms`) |
| `src/transport/upstream.rs` | Upstream address validation before TCP connect |
| `src/transport/pool.rs` | Connection pool SSRF guards |

**Black-hat tests to add in review:**
- `proxy_for` pointing at `127.0.0.1`, `10.0.0.1`, `169.254.0.1`, `::1`, `0.0.0.0`, port 0 → all rejected
- PROXY v1 header exceeding 107 bytes
- PROXY v2 with `TCP4` family but IPv6 address in payload

---

### PR-SEC-6a — Middle Proxy Wire Layer
**Branch:** `pr-sec-6a` · **Commit:** `4967234` · **Files:** 8  
**Depends on:** PR-SEC-5

Serialization and protocol correctness. Reviewable independently of pool management logic.

| File | Key change |
|------|------------|
| `src/transport/middle_proxy/codec.rs` | Frame length validation; reject frames exceeding protocol maximums |
| `src/transport/middle_proxy/handshake.rs` | Remove `build_middleproxy_prekey` import (now via `crypto::hash` directly); SSRF guard via `is_bogon()` before TCP connect; fix `unsafe` `libc` calls |
| `src/transport/middle_proxy/wire.rs` | Checked arithmetic on wire-level length fields |
| `src/transport/middle_proxy/reader.rs` | Bounded read loop with explicit EOF handling |
| `src/transport/middle_proxy/send.rs` · `ping.rs` · `selftest.rs` | Coordinated updates |
| `src/crypto/mod.rs` | Drop the `build_middleproxy_prekey` compatibility re-export added in PR-SEC-2 (now that `handshake.rs` no longer needs it) |

---

### PR-SEC-6b — Middle Proxy Pool & Secret Management
**Branch:** `pr-sec-6b` · **Commit:** `a2bde08` · **Files:** 11  
**Depends on:** PR-SEC-6a

Concurrency, secret rotation, and streaming download safety.

| File | Key change |
|------|------------|
| `src/transport/middle_proxy/secret.rs` | **Bug fix:** `data.len() + chunk.len()` → `checked_add(...).ok_or_else(...)` — wrapping overflow produces a spuriously small `new_len`, silently bypassing the hard cap and enabling OOM from a malicious chunked HTTP response; temp file is removed on write failure; regression test `streaming_cap_checked_add_overflow_is_treated_as_cap_violation` added |
| `src/transport/middle_proxy/config_updater.rs` | Bounded reconnect loop; `JoinError` logging on `reconnect_all` |
| `src/transport/middle_proxy/pool_config.rs` | Config field validation before use |
| `src/transport/middle_proxy/pool.rs` · `pool_init.rs` · `pool_nat.rs` · `pool_refill.rs` · `pool_status.rs` · `pool_writer.rs` | Coordinated pool hardening |
| `src/transport/middle_proxy/registry.rs` · `rotation.rs` | Secret rotation safety |

---

### PR-SEC-7 — Stats, Replay Protection & Metrics
**Branch:** `pr-sec-7` · **Commit:** `8be4f3c` · **Files:** 3  
**Depends on:** PR-SEC-2 (error types); orthogonal to PR-SEC-3 through 6b

| File | Key change |
|------|------------|
| `src/stats/mod.rs` | Replay-checker shard hash for uniform key distribution across all 64 shards; error-code OOM guard (cap the map size to prevent flood of distinct synthetic codes from exhausting memory) |
| `src/stats/telemetry.rs` | Coordinated telemetry field update |
| `src/metrics.rs` | Bound the per-error-code metric map |

**Black-hat tests to add in review:**
- Flood with 50 000 distinct synthetic error codes → map cap prevents OOM
- Fill one replay shard to capacity, submit a key hashing to that shard → not accepted due to premature eviction
- Seed hasher with a known key, verify all 64 shards get coverage (uniform distribution)

---

### PR-SEC-8 — API, Config, CLI & Orchestration
**Branch:** `pr-sec-8` · **Commit:** `bfc6fe3` · **Files:** 29  
**Depends on:** all prior PRs. **Merge last.**

Integrating layer. Contains the deferred `.cargo/config.toml` — the `rustflags` lint policy (`-D unsafe_code`, `-D rust_2018_idioms`, `-D trivial_casts`) is only safe to activate once all underlying source files are patched.

| Area | Key changes |
|------|-------------|
| `src/api/events.rs` | Restore `ApiEventStore` to `pub(crate)`; add `pub(crate)` to `EdgeConnectionsCacheEntry` |
| `src/api/mod.rs` | Tighten `MinimalCacheEntry` and `EdgeConnectionsCacheEntry` visibility |
| `src/api/runtime_edge.rs` | New file — runtime edge API surface |
| `src/api/config_store.rs` · `http_utils.rs` · `users.rs` | Input validation hardening |
| `src/config/types.rs` | Fix hidden lifetime annotation; structured config validation |
| `src/config/load.rs` · `defaults.rs` · `hot_reload.rs` | Hot-reload safety |
| `src/maestro/mod.rs` | Restore `maestro::run()` to `pub` |
| `src/cli.rs` · `startup.rs` · `main.rs` | CLI hardening; bounded startup timeouts |
| `src/proxy/client.rs` · `handshake.rs` · `masking.rs` · `relay.rs` · `route_mode.rs` | Proxy hardening |
| `.cargo/config.toml` | Enforce rustc-native lints globally |
| `.github/workflows/rust.yml` | Upgrade Clippy from correctness-only (PR-SEC-1) to full strict policy with `-F clippy::unwrap_used`, `-F clippy::panic`, etc. |

---

## Verification Record

| Check | Result |
|-------|--------|
| `git diff pr-sec-8 pr-security-hardening --stat` | Empty — trees are identical |
| `cargo test` on `pr-sec-8` | 1008 passed, 0 failed, 2 ignored |
| `cargo check` on each intermediate branch | 0 errors on all 9 branches |

---

## Cross-Cutting Design Notes

### Why both `.cargo/config.toml` and the strict Clippy policy land in PR-SEC-8

`-D unsafe_code`, `-D trivial_casts`, and `-D rust_2018_idioms` are **compiler** lints (not Clippy lints). They apply to every `cargo build`, `cargo check`, and `cargo test` invocation. Adding them in PR-SEC-1 would have made every intermediate branch fail to compile, because:
- `src/transport/middle_proxy/handshake.rs` contains `unsafe { libc::... }` calls (fixed in PR-SEC-6a)
- `src/transport/socket.rs` has trivial pointer casts (fixed in PR-SEC-5)
- `src/config/types.rs` has hidden lifetime parameters (fixed in PR-SEC-8)

The strict **Clippy** policy (`-F clippy::panic`, `-F clippy::unwrap_used`, `-F clippy::expect_used`, etc.) must also land in PR-SEC-8 for the same reason. The `-F` (forbid) flag is stronger than `-D` (deny): it overrides any `#[allow]` annotation in source code, making it a hard compiler error. Intermediate branches add `#[allow(clippy::panic)]` (PR-SEC-2 `obfuscation.rs`) and `#[allow(clippy::expect_used)]` (PR-SEC-2 `hash.rs`) as the correct fix for structurally-infallible call sites — those `#[allow]` attributes would be illegal under `-F`. PR-SEC-1 therefore gates Clippy at `-D clippy::correctness` only, which catches real bugs without blocking in-progress source hardening.

Clipy lints (`clippy::unwrap_used`, `clippy::panic`, etc.) must **never** go in `rustflags` — `rustc` does not understand them and silently ignores them, defeating the enforcement intent. They belong in the `cargo clippy -- -D ...` invocation in `.github/workflows/rust.yml`.

### `crypto/mod.rs` across two PRs

PR-SEC-2 adds `build_middleproxy_prekey` to the `pub use` re-export list as a compatibility shim, because `src/transport/middle_proxy/handshake.rs` (unchanged at that point) imports it via `crate::crypto`. PR-SEC-6a updates `handshake.rs` and drops the re-export in the same commit, reaching the final state from `pr-security-hardening`.
