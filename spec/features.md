# krypton — Algorithm & Function Family Reference
**Coding agent source of truth. Do not add algorithms not listed here.**

---

## Section 1 — Approved Algorithm List

Mode tags: `FIPS` = allowed in fips_only mode | `GENERAL` = standard + hybrid + pqc_hybrid modes | `PQC` = requires enable_pqc=true

### Symmetric Encryption

| Algorithm | Standard | Mode |
|---|---|---|
| AES-256-GCM | FIPS 197 + SP 800-38D | FIPS, GENERAL, PQC |
| AES-256-XTS | FIPS 197 + SP 800-38E | FIPS, GENERAL, PQC |
| AES-256-SIV | RFC 5297 | FIPS, GENERAL, PQC |
| ChaCha20-Poly1305 | RFC 8439 | GENERAL, PQC |

### Hash / Digest

| Algorithm | Standard | Mode |
|---|---|---|
| SHA-256 | FIPS 180-4 | FIPS, GENERAL, PQC |
| SHA-384 | FIPS 180-4 | FIPS, GENERAL, PQC |
| SHA-512 | FIPS 180-4 | FIPS, GENERAL, PQC |
| SHA3-256 | FIPS 202 | FIPS, GENERAL, PQC |
| SHA3-384 | FIPS 202 | FIPS, GENERAL, PQC |
| SHA3-512 | FIPS 202 | FIPS, GENERAL, PQC |
| SHAKE128 | FIPS 202 | FIPS, GENERAL, PQC |
| SHAKE256 | FIPS 202 | FIPS, GENERAL, PQC |

### Message Authentication Code

| Algorithm | Standard | Mode |
|---|---|---|
| HMAC-SHA256 | FIPS 198-1 | FIPS, GENERAL, PQC |
| HMAC-SHA384 | FIPS 198-1 | FIPS, GENERAL, PQC |
| HMAC-SHA512 | FIPS 198-1 | FIPS, GENERAL, PQC |
| HMAC-SHA3-256 | FIPS 198-1 + FIPS 202 | FIPS, GENERAL, PQC |
| AES-256-CMAC | SP 800-38B | FIPS, GENERAL, PQC |
| AES-256-GMAC | SP 800-38D | FIPS, GENERAL, PQC |

### Key Derivation (high-entropy input)

| Algorithm | Standard | Mode |
|---|---|---|
| HKDF-SHA256 | RFC 5869 + SP 800-56C | FIPS, GENERAL, PQC |
| HKDF-SHA384 | RFC 5869 + SP 800-56C | FIPS, GENERAL, PQC |
| HKDF-SHA512 | RFC 5869 + SP 800-56C | FIPS, GENERAL, PQC |
| SP800-108-CTR | SP 800-108 Rev1 | FIPS, GENERAL, PQC |
| ANSI-X9.63 | SP 800-56A | FIPS, GENERAL, PQC |

### Key Derivation (password / low-entropy input)

| Algorithm | Standard | Mode |
|---|---|---|
| PBKDF2-SHA256 | SP 800-132 | FIPS, GENERAL, PQC |
| PBKDF2-SHA384 | SP 800-132 | FIPS, GENERAL, PQC |
| Argon2id | RFC 9106 | GENERAL, PQC |
| scrypt | RFC 7914 | GENERAL, PQC |
| bcrypt | — | GENERAL (legacy compat only, warn) |

### Digital Signatures

| Algorithm | Standard | Mode |
|---|---|---|
| ECDSA-P256 | FIPS 186-5 | FIPS, GENERAL |
| ECDSA-P384 | FIPS 186-5 | FIPS, GENERAL |
| Ed25519 | FIPS 186-5 + RFC 8032 | FIPS, GENERAL |
| RSA-PSS-3072 | FIPS 186-5 | FIPS, GENERAL |
| RSA-PSS-4096 | FIPS 186-5 | FIPS, GENERAL |
| ML-DSA-65 | FIPS 204 | GENERAL, PQC |
| ML-DSA-87 | FIPS 204 | GENERAL, PQC |
| SLH-DSA-SHA2-128s | FIPS 205 | GENERAL, PQC |

### Key Encapsulation & Agreement

| Algorithm | Standard | Mode |
|---|---|---|
| ECDH-P256 | SP 800-56A | FIPS, GENERAL |
| ECDH-P384 | SP 800-56A | FIPS, GENERAL |
| X25519 | RFC 7748 | GENERAL |
| ML-KEM-768 | FIPS 203 | GENERAL, PQC |
| ML-KEM-1024 | FIPS 203 | GENERAL, PQC |
| HPKE-Classic (ECDH-P256 + HKDF-SHA256 + AES-256-GCM) | RFC 9180 | GENERAL |
| HPKE-Hybrid (ECDH-P256 + ML-KEM-768 + HKDF-SHA384 + AES-256-GCM) | RFC 9180 + FIPS 203 | GENERAL, PQC |

### Format-Preserving Encryption

| Algorithm | Standard | Mode |
|---|---|---|
| FF1 | SP 800-38G | FIPS, GENERAL, PQC |
| FF3-1 | SP 800-38G | FIPS, GENERAL, PQC (⚠️ reduced security margin — warn caller) |

### Key Wrapping

| Algorithm | Standard | Mode |
|---|---|---|
| AES-256-KW | SP 800-38F + RFC 3394 | FIPS, GENERAL, PQC |
| AES-256-KWP | SP 800-38F | FIPS, GENERAL, PQC |

### Random Generation

| Algorithm | Standard | Mode |
|---|---|---|
| CTR_DRBG-AES256 | SP 800-90A Rev1 | FIPS, GENERAL, PQC |
| HMAC_DRBG-SHA256 | SP 800-90A Rev1 | FIPS, GENERAL, PQC |

### Explicitly Disabled (never implement, return error if called)

| Algorithm | Reason |
|---|---|
| MD5 | Broken |
| SHA-1 (new ops) | Deprecated SP 800-131A |
| 3DES / TDEA | Disallowed post-2023 |
| AES-CBC | No authentication |
| AES-ECB | Deterministic pattern leakage |
| AES-CTR (standalone) | No authentication |
| RSA-PKCS1-v1.5 sign | Malleable |
| RSA < 3072-bit | Below key length floor |
| DSA | Deprecated FIPS 186-5 |
| Dual_EC_DRBG | Retracted, potential backdoor |
| math/rand (Go) | Not cryptographically secure |
| ML-KEM-512 | Below recommended security level |

---

## Section 2 — Function Family Groups

Each family is one unified function call. `algorithm` parameter selects the member.
All functions are in package `github.com/moeghifar/krypton/core`.

---

### Family 1 — `digest`

```
digest(data []byte, algorithm string) ([]byte, error)
```

| Parameter | Values |
|---|---|
| algorithm | `SHA-256` `SHA-384` `SHA-512` `SHA3-256` `SHA3-384` `SHA3-512` |

Input: arbitrary bytes
Output: fixed-length digest bytes
No key. No state between calls.

---

### Family 2 — `digest_xof`

```
digest_xof(data []byte, algorithm string, output_length uint32) ([]byte, error)
```

| Parameter | Values |
|---|---|
| algorithm | `SHAKE128` `SHAKE256` |
| output_length | 16–512 bytes |

Variant of digest for extendable output functions. Separate call because output length is variable.

---

### Family 3 — `mac`

```
mac(key []byte, data []byte, algorithm string) ([]byte, error)
mac_verify(key []byte, data []byte, tag []byte, algorithm string) (bool, error)
```

| Parameter | Values |
|---|---|
| algorithm | `HMAC-SHA256` `HMAC-SHA384` `HMAC-SHA512` `HMAC-SHA3-256` `AES-CMAC` |

`mac_verify` uses constant-time comparison internally. Returns bool only, never panics.

---

### Family 4 — `mac_iv`

```
mac_iv(key []byte, data []byte, algorithm string) (tag []byte, nonce []byte, error)
mac_iv_verify(key []byte, data []byte, nonce []byte, tag []byte, algorithm string) (bool, error)
```

| Parameter | Values |
|---|---|
| algorithm | `AES-GMAC` |

Separate from Family 3 because GMAC requires a nonce. Nonce is generated internally on `mac_iv`. Caller stores and provides nonce on `mac_iv_verify`.

---

### Family 5 — `encrypt` / `decrypt`

```
encrypt(key []byte, plaintext []byte, context string, algorithm string) (Envelope, error)
decrypt(key []byte, envelope Envelope, context string, algorithm string) ([]byte, error)
```

| Parameter | Values |
|---|---|
| algorithm | `AES-256-GCM` `ChaCha20-Poly1305` |
| context | any string; bound to AAD; must match at decrypt |

Nonce is generated internally by DRBG on every `encrypt` call. Caller cannot supply nonce.
Output is always a `CryptoEnvelope` struct (see Section 3).

---

### Family 6 — `encrypt_det` / `decrypt_det`

```
encrypt_det(key []byte, plaintext []byte, context string) ([]byte, error)
decrypt_det(key []byte, ciphertext []byte, context string) ([]byte, error)
```

Algorithm: `AES-256-SIV` (only member, no algorithm param needed)
Key: 64 bytes (two AES-256 keys)
Property: same key + same plaintext + same context always produces same ciphertext.
Use case: searchable encrypted database fields.

---

### Family 7 — `encrypt_vol` / `decrypt_vol`

```
encrypt_vol(key []byte, data []byte, tweak []byte, algorithm string) ([]byte, error)
decrypt_vol(key []byte, data []byte, tweak []byte, algorithm string) ([]byte, error)
```

| Parameter | Values |
|---|---|
| algorithm | `AES-256-XTS` |
| tweak | 16 bytes; sector number or block index |

Key: 64 bytes (two AES-256 keys for XTS)
Input must be multiple of 16 bytes.
Output is same length as input. No envelope, no tag.
Use case: disk/volume/block storage encryption.

---

### Family 8 — `fpe_encrypt` / `fpe_decrypt`

```
fpe_encrypt(key []byte, plaintext string, tweak []byte, alphabet string, algorithm string) (string, error)
fpe_decrypt(key []byte, ciphertext string, tweak []byte, alphabet string, algorithm string) (string, error)
```

| Parameter | Values |
|---|---|
| algorithm | `FF1` `FF3-1` |
| alphabet | `numeric` `alpha` `alphanumeric` `custom:<chars>` |

Key: 32 bytes (AES-256)
Output is same length and same alphabet as input.
⚠️ If algorithm is `FF3-1`, function appends a warning in returned metadata.
Use case: NIK, phone numbers, account numbers preserving format under encryption.

---

### Family 9 — `kdf`

```
kdf(ikm []byte, salt []byte, info []byte, length uint32, algorithm string) ([]byte, error)
```

| Parameter | Values |
|---|---|
| algorithm | `HKDF-SHA256` `HKDF-SHA384` `HKDF-SHA512` `SP800-108-CTR` `ANSI-X9.63` |
| length | 16–512 bytes |

Input `ikm` must be high-entropy (existing key material or ECDH/KEM shared secret).
Do NOT use for passwords — use Family 10 for that.
Output: derived key bytes, ready to use as symmetric key after this call.

---

### Family 10 — `kdf_password`

```
kdf_password(password string, salt []byte, params PasswordParams, algorithm string) ([]byte, error)
```

| Parameter | Values |
|---|---|
| algorithm | `PBKDF2-SHA256` `PBKDF2-SHA384` `Argon2id` `scrypt` `bcrypt` |

`PasswordParams` struct fields vary by algorithm:
```
PBKDF2:  { iterations uint32 (min 600000 for SHA256), length uint32 }
Argon2id: { memory_kb uint32 (min 32768), iterations uint32 (min 2), parallelism uint32 (min 1), length uint32 }
scrypt:  { n uint32, r uint32, p uint32, length uint32 }
bcrypt:  { cost uint32 (min 10) }
```

Returns raw derived bytes. To store a password hash with embedded params, use Family 11.
⚠️ `bcrypt` emits warning: "bcrypt silently truncates passwords at 72 bytes".

---

### Family 11 — `password_hash` / `password_verify`

```
password_hash(password string, algorithm string, params PasswordParams) (string, error)
password_verify(password string, hash string) (bool, error)
```

| Parameter | Values |
|---|---|
| algorithm | `Argon2id` `bcrypt` |

`password_hash` returns an encoded string (PHC format for Argon2id, `$2b$` for bcrypt).
The encoded string embeds algorithm, params, salt, and hash — self-contained.
`password_verify` parses algorithm from the hash string. Constant-time comparison.
Use case: user password storage. For key derivation from password, use Family 10.

---

### Family 12 — `keygen`

```
keygen(algorithm string, format KeyFormat) (KeyPair, error)
```

| Parameter | Values |
|---|---|
| algorithm | `ECDSA-P256` `ECDSA-P384` `Ed25519` `RSA-PSS-3072` `RSA-PSS-4096` `ML-DSA-65` `ML-DSA-87` `SLH-DSA-SHA2-128s` `ML-KEM-768` `ML-KEM-1024` |
| format | `JWK` `PEM` `RAW` |

```
KeyPair {
  key_id:      string    // UUID assigned by engine
  public_key:  string    // encoded in requested format
  private_key: string    // encoded in requested format
  algorithm:   string
  created_at:  time.Time
}
```

For ML-KEM: `public_key` = encapsulation key, `private_key` = decapsulation key.
`ErrKeyTooShort` if RSA below 3072-bit is attempted.
`ErrPQCDisabled` if ML-DSA, SLH-DSA, ML-KEM attempted without `enable_pqc=true`.

---

### Family 13 — `sign` / `verify`

```
sign(private_key string, message []byte, algorithm string, key_format KeyFormat) ([]byte, error)
verify(public_key string, message []byte, signature []byte, algorithm string, key_format KeyFormat) (bool, error)
```

| Parameter | Values |
|---|---|
| algorithm | `ECDSA-P256` `ECDSA-P384` `Ed25519` `RSA-PSS-3072` `RSA-PSS-4096` `ML-DSA-65` `ML-DSA-87` `SLH-DSA-SHA2-128s` |

ECDSA uses deterministic nonce per RFC 6979. Caller cannot supply nonce.
`verify` returns `bool` only. Never reveals which byte of signature failed.
In `pqc_hybrid` mode: `sign` returns two signatures; `verify` requires both pass.

---

### Family 14 — `kem_encap` / `kem_decap`

```
kem_encap(public_key string, algorithm string, key_format KeyFormat) (KEMResult, error)
kem_decap(private_key string, encapsulation []byte, algorithm string, key_format KeyFormat) ([]byte, error)
```

| Parameter | Values |
|---|---|
| algorithm | `ECDH-P256` `ECDH-P384` `X25519` `ML-KEM-768` `ML-KEM-1024` |

```
KEMResult {
  encapsulation:  []byte  // send to decapsulating party
  shared_secret:  []byte  // 32 bytes; derive symmetric key from this via kdf()
}
```

`kem_decap` returns 32-byte shared secret only.
ECDH: `encapsulation` is the ephemeral public key point.
ML-KEM: `encapsulation` is the KEM ciphertext (768 bytes for ML-KEM-768, 1568 for ML-KEM-1024).
ML-KEM implicit rejection: malformed ciphertext returns pseudo-random value, not error (per FIPS 203).
`X25519` returns `ErrAlgorithmNotPermitted` in `fips_only` mode.
`ML-KEM-512` returns `ErrParameterBelowFloor`.

---

### Family 15 — `hpke_seal` / `hpke_open`

```
hpke_seal(recipient_public_key string, plaintext []byte, aad []byte, suite string) (Envelope, error)
hpke_open(recipient_private_key string, envelope Envelope) ([]byte, error)
```

| Parameter | Values |
|---|---|
| suite | `HPKE-Classic` `HPKE-Hybrid` |

`HPKE-Classic`: ECDH-P256 + HKDF-SHA256 + AES-256-GCM
`HPKE-Hybrid`: ECDH-P256 + ML-KEM-768 + HKDF-SHA384 + AES-256-GCM (requires `enable_pqc=true`)
Output envelope includes `enc_classical` and/or `enc_pqc` fields in addition to standard fields.
Only the holder of `recipient_private_key` can open. Service operator cannot decrypt.
`hpke_open` returns `ErrDecryptionFailed` if wrong key or tampered envelope.

---

### Family 16 — `key_wrap` / `key_unwrap`

```
key_wrap(wrapping_key []byte, key_material []byte, algorithm string) ([]byte, error)
key_unwrap(wrapping_key []byte, wrapped []byte, algorithm string) ([]byte, error)
```

| Parameter | Values |
|---|---|
| algorithm | `AES-256-KW` `AES-256-KWP` |

`AES-256-KW`: key_material must be multiple of 8 bytes.
`AES-256-KWP`: key_material can be any length (padding applied internally).
`key_unwrap` returns `ErrDecryptionFailed` if wrapping_key is wrong or wrapped bytes are tampered.

---

### Family 17 — `rand`

```
rand(length_bytes uint32) ([]byte, error)
```

No algorithm parameter. CTR_DRBG AES-256 is always used internally.
`length_bytes`: min 16, max 8192.
Returns `ErrDRBGHealthFailure` if continuous random test fires.
Callers should never use this to generate keys directly — use `keygen` for key pairs
and `kdf` or `kdf_password` to derive symmetric keys. Use `rand` for: nonces, salts,
tokens, UUIDs, test data.

---

## Section 3 — Envelope Wire Format

All `encrypt` and `hpke_seal` outputs return this struct.
Callers must persist the full struct to decrypt later.

```go
type Envelope struct {
    Version      uint8  `json:"version"`        // always 1
    SuiteID      string `json:"suite_id"`        // e.g. "suite-v1-classical"
    Algorithm    string `json:"algorithm"`       // e.g. "AES-256-GCM"
    KeyID        string `json:"key_id"`          // opaque; set by caller or KMS
    Nonce        []byte `json:"nonce"`           // base64; 12 bytes for GCM
    AAD          []byte `json:"aad,omitempty"`   // base64; may be empty
    Ciphertext   []byte `json:"ciphertext"`      // base64
    Tag          []byte `json:"tag"`             // base64; 16 bytes for GCM

    // HPKE-only fields; nil for symmetric encrypt
    EncClassical []byte `json:"enc_classical,omitempty"` // ECDH ephemeral key
    EncPQC       []byte `json:"enc_pqc,omitempty"`        // ML-KEM ciphertext
}
```

---

## Section 4 — Key Format

```go
type KeyFormat string

const (
    KeyFormatRawHex    KeyFormat = "RAW_HEX"    // 64-char hex string for AES-256
    KeyFormatRawBase64 KeyFormat = "RAW_BASE64"  // base64url, no padding
    KeyFormatJWK       KeyFormat = "JWK"         // JSON Web Key (RFC 7517)
    KeyFormatPEM       KeyFormat = "PEM"         // PEM-encoded X.509 compatible
)
```

---

## Section 5 — Error Codes

```go
var (
    ErrAlgorithmDisabled        = errors.New("ALGO_DISABLED")
    ErrAlgorithmNotPermitted    = errors.New("ALGO_NOT_PERMITTED")   // mode restriction
    ErrPQCDisabled              = errors.New("PQC_DISABLED")
    ErrHybridRequired           = errors.New("HYBRID_REQUIRED")
    ErrModeImmutable            = errors.New("MODE_IMMUTABLE")
    ErrSuiteUnknown             = errors.New("SUITE_UNKNOWN")
    ErrKeySizeInvalid           = errors.New("KEY_SIZE_INVALID")
    ErrKeyTooShort              = errors.New("KEY_TOO_SHORT")
    ErrKeyFormatInvalid         = errors.New("KEY_FORMAT_INVALID")
    ErrParameterBelowFloor      = errors.New("PARAM_BELOW_FLOOR")
    ErrIterationsBelowFloor     = errors.New("ITERATIONS_BELOW_FLOOR")
    ErrDecryptionFailed         = errors.New("DECRYPTION_FAILED")    // AEAD tag mismatch
    ErrVerificationFailed       = errors.New("VERIFICATION_FAILED")
    ErrDecapsulationFailed      = errors.New("DECAPSULATION_FAILED")
    ErrCiphertextEmpty          = errors.New("CIPHERTEXT_EMPTY")
    ErrNonceInvalid             = errors.New("NONCE_INVALID")
    ErrTagInvalid               = errors.New("TAG_INVALID")
    ErrInputTooLarge            = errors.New("INPUT_TOO_LARGE")
    ErrInputCharOutsideAlphabet = errors.New("CHAR_OUTSIDE_ALPHABET")
    ErrDRBGHealthFailure        = errors.New("DRBG_HEALTH_FAILURE")
    ErrIntegrityFailure         = errors.New("INTEGRITY_FAILURE")
    ErrKATFailure               = errors.New("KAT_FAILURE")
)
```

---

## Section 6 — Mode Behavior Summary

```
Mode          enable_pqc  ChaCha  X25519  Argon2id  Ed25519  SHA-3  ML-KEM  ML-DSA
──────────────────────────────────────────────────────────────────────────────────────
fips_only     ignored     ❌      ❌      ❌        ✅       ✅     pending pending
standard      false       ✅      ✅      ✅        ✅       ✅     ❌      ❌
standard      true        ✅      ✅      ✅        ✅       ✅     ✅      ✅
pqc_hybrid    true        ✅      ✅      ✅        ✅       ✅     ✅      ✅
pqc_only      true        ✅      ❌      ✅        ❌       ✅     ✅      ✅
```

In `pqc_only` mode: ECDSA, ECDH, RSA, Ed25519, X25519 all return `ErrAlgorithmNotPermitted`.
In `pqc_hybrid` mode: sign/verify/encap/decap use both classical AND PQC simultaneously.

---

## Section 7 — Package Layout

```
github.com/moeghifar/krypton/
├── core/
│   ├── drbg/        rand()
│   ├── cipher/      encrypt(), decrypt(), encrypt_det(), decrypt_det()
│   │   └── vol/     encrypt_vol(), decrypt_vol()
│   ├── fpe/         fpe_encrypt(), fpe_decrypt()
│   ├── hash/        digest(), digest_xof()
│   ├── mac/         mac(), mac_verify(), mac_iv(), mac_iv_verify()
│   ├── kdf/         kdf(), kdf_password()
│   ├── password/    password_hash(), password_verify()
│   ├── sig/         keygen(), sign(), verify()
│   ├── kem/         kem_encap(), kem_decap()
│   ├── hpke/        hpke_seal(), hpke_open()
│   └── keywrap/     key_wrap(), key_unwrap()
├── envelope/        Envelope struct, serialization
├── config/          mode, suite registry, flags
└── errors/          all error vars
```