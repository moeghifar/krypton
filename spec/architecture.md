# Krypton — Architecture & Requirements

**Version**: 1.0.0
**Last Updated**: 2026-06-07
**Status**: Active Development — Core Complete, Compliance Validation Pending

---

## 1. Design Philosophy

### 1.1 Principles

- **Secure by Default**: All algorithms use safe parameters. Weak algorithms (FF3-1, MD5, SHA-1, 3DES, AES-ECB, AES-CBC, RSA-PKCS1-v1.5, DSA, Dual_EC_DRBG) are explicitly disabled.
- **Simple API**: Unified function families with consistent signatures. One call per operation.
- **Battle-Tested**: Every algorithm validated against NIST CAVP (Cryptographic Algorithm Validation Program) test vectors before release.
- **Transparent**: Full test coverage, benchmark results, and compliance documentation visible to users.
- **Modular**: Each `pkg/*` is independently importable. `lib/*` packages are internal only.

### 1.2 Package Layout

```
github.com/moeghifar/krypton/
├── pkg/                    # Public API — importable by external users
│   ├── cipher/             # Families 5, 6: encrypt/decrypt, encrypt_det/decrypt_det
│   ├── fpe/                # Family 8: fpe_encrypt/fpe_decrypt (FF1 only)
│   ├── hash/               # Families 1, 2: digest/digest_xof
│   ├── hpke/               # Family 15: hpke_seal/hpke_open
│   ├── kdf/                # Families 9, 10: kdf/kdf_password
│   ├── kem/                # Family 14: kem_encap/kem_decap
│   ├── keywrap/            # Family 16: key_wrap/key_unwrap
│   ├── mac/                # Families 3, 4: mac/mac_verify/mac_iv/mac_iv_verify
│   ├── password/           # Family 11: password_hash/password_verify
│   └── sig/                # Families 12, 13: keygen/sign/verify
├── lib/                    # Internal packages — NOT for external use
│   ├── cipher/siv/         # AES-SIV sub-package
│   ├── cipher/vol/         # AES-XTS volume encryption
│   ├── config/             # Mode management, algorithm registry
│   ├── drbg/               # Deterministic random bit generation
│   ├── encode/             # Base-N encoding with checksum
│   ├── envelope/           # Wire format structs
│   ├── errors/             # Error code definitions
│   └── types/              # Shared type definitions
├── example/                # Usage examples for each public package
├── spec/                   # Specifications and documentation
│   ├── architecture.md     # This document
│   ├── features.md         # Algorithm & function family reference
│   └── summary.md          # Implementation changelog
└── main.go                 # CLI entry point
```

### 1.3 Visibility Rules

| Directory | Importable? | Purpose |
|-----------|-------------|---------|
| `pkg/*` | ✅ Yes | Public cryptographic API |
| `lib/*` | ❌ No | Internal support packages |
| `example/` | ✅ Yes | Sample code, not a library |
| `spec/` | ❌ No | Documentation only |

External users should **only** import from `github.com/moeghifar/krypton/pkg/*`.

---

## 2. Algorithm Compliance

### 2.1 Approved Algorithms

All algorithms listed below are implemented and tested. Algorithms marked with ⚠️ require NIST CAVP test vector validation before production use.

| Family | Algorithm | Standard | NIST CAVP | Status |
|--------|-----------|----------|-----------|--------|
| 1 | SHA-256/384/512 | FIPS 180-4 | Required | ✅ Implemented |
| 1 | SHA3-256/384/512 | FIPS 202 | Required | ✅ Implemented |
| 2 | SHAKE128/256 | FIPS 202 | Required | ✅ Implemented |
| 3 | HMAC-SHA256/384/512 | FIPS 198-1 | Required | ✅ Implemented |
| 3 | HMAC-SHA3-256 | FIPS 198-1+202 | Required | ✅ Implemented |
| 3 | AES-CMAC | SP 800-38B | Required | ✅ Implemented |
| 4 | AES-GMAC | SP 800-38D | Required | ✅ Implemented |
| 5 | AES-256-GCM | FIPS 197+SP 800-38D | Required | ✅ Implemented |
| 5 | ChaCha20-Poly1305 | RFC 8439 | N/A (IETF) | ✅ Implemented |
| 6 | AES-256-SIV | RFC 5297 | Recommended | ✅ Implemented |
| 7 | AES-256-XTS | FIPS 197+SP 800-38E | Required | ✅ Implemented |
| 8 | FF1 | SP 800-38G | Required | ✅ Implemented |
| 9 | HKDF-SHA256/384/512 | RFC 5869+SP 800-56C | Required | ✅ Implemented |
| 9 | SP800-108-CTR | SP 800-108 Rev1 | Required | ✅ Implemented |
| 9 | ANSI-X9.63 | SP 800-56A | Required | ✅ Implemented |
| 10 | PBKDF2-SHA256/384 | SP 800-132 | Required | ✅ Implemented |
| 10 | Argon2id | RFC 9106 | Recommended | ✅ Implemented |
| 10 | scrypt | RFC 7914 | N/A | ✅ Implemented |
| 10 | bcrypt | — | Legacy compat | ⚠️ Warning emitted |
| 11 | Argon2id (PHC) | RFC 9106 | Recommended | ✅ Implemented |
| 11 | bcrypt ($2b$) | — | Legacy compat | ⚠️ Warning emitted |
| 12/13 | ECDSA-P256/384 | FIPS 186-5 | Required | ✅ Implemented |
| 12/13 | Ed25519 | FIPS 186-5+RFC 8032 | Required | ✅ Implemented |
| 12/13 | RSA-PSS-3072/4096 | FIPS 186-5 | Required | ✅ Implemented |
| 14 | ECDH-P256/384 | SP 800-56A | Required | ✅ Implemented |
| 14 | X25519 | RFC 7748 | N/A (IETF) | ✅ Implemented |
| 15 | HPKE-Classic | RFC 9180 | Recommended | ✅ Implemented |
| 16 | AES-256-KW/KWP | SP 800-38F+RFC 3394 | Required | ✅ Implemented |
| 17 | CTR_DRBG-AES256 | SP 800-90A Rev1 | Required | ✅ Implemented |
| 17 | HMAC_DRBG-SHA256 | SP 800-90A Rev1 | Required | ✅ Implemented |

### 2.2 Explicitly Disabled Algorithms

These algorithms are **never implemented** and return `ErrAlgorithmDisabled` if called:

| Algorithm | Reason |
|-----------|--------|
| MD5 | Broken (collisions) |
| SHA-1 (new ops) | Deprecated (SP 800-131A) |
| 3DES / TDEA | Disallowed post-2023 |
| AES-CBC | No authentication |
| AES-ECB | Deterministic pattern leakage |
| AES-CTR (standalone) | No authentication |
| RSA-PKCS1-v1.5 sign | Malleable |
| RSA < 3072-bit | Below key length floor |
| DSA | Deprecated (FIPS 186-5) |
| Dual_EC_DRBG | Retracted, potential backdoor |
| math/rand (Go) | Not cryptographically secure |
| ML-KEM-512 | Below recommended security level |
| FF3-1 | Removed — lacks NIST CAVP validation, known weaknesses |

### 2.3 PQC Algorithms (Deferred)

These algorithms return `ErrPQCDisabled` until pure Go implementations are available:

- ML-KEM-768, ML-KEM-1024 (FIPS 203)
- ML-DSA-65, ML-DSA-87 (FIPS 204)
- SLH-DSA-SHA2-128s (FIPS 205)
- HPKE-Hybrid (requires ML-KEM)

---

## 3. Test & Validation Requirements

### 3.1 NIST CAVP Test Vector Validation (MANDATORY)

Every algorithm **MUST** pass NIST CAVP Known Answer Tests (KAT) before being marked as production-ready.

**Test Vector Sources**:
- NIST CAVP: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
- NIST SP 800-38G Rev 1 Appendix F (FF1 test vectors)
- RFC 4231 (HMAC-SHA test vectors)
- RFC 5869 (HKDF test vectors)
- RFC 8032 (Ed25519 test vectors)
- NIST SP 800-38B (AES-CMAC test vectors)
- NIST SP 800-38D (AES-GCM test vectors)

**Validation Process**:
1. Download official test vectors from NIST CAVP
2. Create `testdata/` directory in each package with `.rsp` files
3. Write `TestKAT_*` functions that load and validate against vectors
4. Mark algorithm as `CAVP_VALIDATED` in documentation only after all vectors pass

**Current Status**:
- ⚠️ FF1: Implemented but NIST KAT vectors not yet integrated
- ⚠️ All other algorithms: Unit tests pass, CAVP validation pending

### 3.2 Unit Test Requirements

Every package **MUST** have 100% unit test coverage of:
- All exported functions
- All error paths
- All mode restrictions (fips_only, standard, pqc_hybrid, pqc_only)
- Boundary conditions (min/max key sizes, input lengths)
- Invalid input handling

**Run all unit tests**:
```bash
go test ./pkg/... ./lib/... -v -count=1
```

**Run tests with coverage**:
```bash
go test ./pkg/... ./lib/... -coverprofile=coverage.out -count=1
go tool cover -html=coverage.out -o coverage.html
```

**Run tests for a specific package**:
```bash
go test ./pkg/cipher/... -v -count=1
go test ./pkg/hash/... -v -count=1
go test ./pkg/mac/... -v -count=1
# ... etc for each package
```

### 3.3 Performance Benchmarks (MANDATORY)

Every package **MUST** include `Benchmark_*` functions in `_test.go` files.

**Run all benchmarks**:
```bash
go test ./pkg/... ./lib/... -bench=. -benchmem -count=1
```

**Run benchmarks for a specific package**:
```bash
go test ./pkg/hash/... -bench=. -benchmem -count=1
go test ./pkg/cipher/... -bench=. -benchmem -count=1
```

**Required benchmarks per package**:
- `BenchmarkDigest_SHA256` — hash throughput
- `BenchmarkEncrypt_AES256GCM` — encryption throughput
- `BenchmarkMac_HMACSHA256` — MAC computation
- `BenchmarkKDF_HKDF` — key derivation
- `BenchmarkSign_Ed25519` — signing throughput
- `BenchmarkVerify_Ed25519` — verification throughput
- (etc. for each algorithm)

### 3.4 Integration Tests

**Run integration tests** (tests that cross package boundaries):
```bash
go test ./pkg/... ./lib/... -run Integration -v -count=1
```

### 3.5 FIPS Mode Validation

**Run tests in FIPS-only mode**:
```bash
KRYPTON_MODE=fips_only go test ./pkg/... ./lib/... -v -count=1
```

### 3.6 Race Condition Detection

**Run with race detector**:
```bash
go test ./pkg/... ./lib/... -race -count=1
```

### 3.7 Static Analysis

**Run vet**:
```bash
go vet ./pkg/... ./lib/...
```

**Run staticcheck** (if available):
```bash
staticcheck ./pkg/... ./lib/...
```

---

## 4. Security Requirements

### 4.1 Constant-Time Operations

All MAC and signature verification **MUST** use constant-time comparison:
- `mac_verify`: Uses `crypto/subtle.ConstantTimeCompare`
- `password_verify`: Uses `golang.org/x/crypto/bcrypt.CompareHashAndPassword` (constant-time)
- All AEAD tag verification: Handled by Go's `crypto/cipher` AEAD interface

### 4.2 Nonce Generation

- All nonces are generated via `crypto/rand` (CSPRNG)
- DRBG (SP 800-90A) is available via `lib/drbg` for deterministic nonce generation
- Callers **CANNOT** supply their own nonces — nonces are always generated internally

### 4.3 Key Handling

- Keys are passed as `[]byte` — callers are responsible for secure key storage
- Private keys in PEM format are parsed via `crypto/x509`
- Raw hex/base64 keys are decoded via `encoding/hex` and `encoding/base64`

### 4.4 Mode Immutability

Once `config.Init()` is called, the mode **CANNOT** be changed. This prevents downgrade attacks.

---

## 5. Performance Requirements

### 5.1 Target Benchmarks

| Operation | Target | Notes |
|-----------|--------|-------|
| SHA-256 | > 500 MB/s | Single core |
| AES-256-GCM encrypt | > 1 GB/s | Single core, AES-NI |
| HMAC-SHA256 | > 400 MB/s | Single core |
| Ed25519 sign | > 50,000 ops/s | Single core |
| Ed25519 verify | > 20,000 ops/s | Single core |
| RSA-PSS-4096 sign | > 1,000 ops/s | Single core |
| RSA-PSS-4096 verify | > 10,000 ops/s | Single core |
| Argon2id | Configurable | Memory-hard, min 32MB |

### 5.2 Memory Safety

- No `unsafe` package usage
- All buffers are Go-managed
- Sensitive data should be zeroed after use (best effort)

---

## 6. Library Dependencies

### 6.1 Standard Library (Preferred)

All algorithms优先使用 Go 标准库实现：
- `crypto/aes`, `crypto/cipher`, `crypto/hmac`, `crypto/sha256`, `crypto/sha512`
- `crypto/ecdsa`, `crypto/ed25519`, `crypto/elliptic`, `crypto/rsa`
- `crypto/rand`, `crypto/subtle`, `crypto/x509`, `crypto/pem`
- `encoding/hex`, `encoding/base64`, `encoding/json`

### 6.2 golang.org/x/crypto (Required)

- `golang.org/x/crypto/sha3` — SHA-3 and SHAKE
- `golang.org/x/crypto/chacha20poly1305` — ChaCha20-Poly1305
- `golang.org/x/crypto/argon2` — Argon2id
- `golang.org/x/crypto/bcrypt` — bcrypt password hashing
- `golang.org/x/crypto/pbkdf2` — PBKDF2
- `golang.org/x/crypto/scrypt` — scrypt
- `golang.org/x/crypto/hkdf` — HKDF
- `golang.org/x/crypto/ecdh` — ECDH (P-256, P-384, X25519)

### 6.3 No Other External Dependencies

The library has **zero** external dependencies beyond `golang.org/x/crypto`. This minimizes supply chain risk.

---

## 7. Example Usage

### 7.1 Example Directory Structure

```
example/
├── digest/           # Hash/digest examples
├── mac/              # MAC computation examples
├── encrypt/          # Symmetric encryption examples
├── keygen/           # Key generation examples
├── sign/             # Digital signature examples
├── kdf/              # Key derivation examples
├── fpe/              # Format-preserving encryption examples
└── cli/              # Full CLI example
```

### 7.2 Running Examples

```bash
go run example/digest/main.go
go run example/encrypt/main.go
go run example/sign/main.go
# etc.
```

---

## 8. CLI Usage

```bash
# Build
go build -o krypton .

# Hash digest
./krypton digest SHA-256 "hello world"

# MAC computation
./krypton mac HMAC-SHA256 "7365637265742d6b6579" "hello world"

# Encryption
./krypton encrypt AES-256-GCM "000102030405060708090a0b0c0d0e0f" "hello" "context"

# Help
./krypton help
```

---

## 9. Compliance Checklist

- [x] All 17 function families implemented
- [x] All classical algorithms from spec/features.md supported
- [x] Weak/deprecated algorithms explicitly disabled
- [x] Unit tests for all packages (100% package coverage)
- [x] Race condition detection passes (`go test -race`)
- [x] Static analysis passes (`go vet`)
- [x] No external dependencies beyond `golang.org/x/crypto`
- [x] Internal packages isolated in `lib/`
- [x] Public API in `pkg/*` only
- [x] CLI entry point in `main.go`
- [x] Example directory created
- [ ] NIST CAVP test vector validation (all algorithms)
- [ ] Performance benchmarks for all algorithms
- [ ] Integration tests across packages
- [ ] FIPS 140-2 compliance documentation
- [ ] Security audit by third party

---

## 10. Version History

| Date | Version | Description |
|------|---------|-------------|
| 2026-06-06 | 0.1.0 | Initial implementation of all 17 families |
| 2026-06-06 | 0.2.0 | Package restructure, import path fix, test coverage |
| 2026-06-07 | 0.3.0 | Moved internal packages to `lib/`, removed FF3-1, created architecture.md, added example directory |
