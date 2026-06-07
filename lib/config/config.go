// Copyright 2026 M Ghiyast Farisi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package config manages the cryptographic mode and algorithm registry for krypton.
// Mode determines which algorithms are permitted. Once set, mode is immutable.
package config

import (
	"sync"

	cerr "github.com/moeghifar/krypton/lib/errors"
)

// Mode represents the cryptographic operating mode.
type Mode string

const (
	// ModeFIPSOnly allows only FIPS-approved algorithms (no ChaCha, no X25519, no Argon2id).
	ModeFIPSOnly Mode = "fips_only"

	// ModeStandard allows standard algorithms; PQC optional via EnablePQC.
	ModeStandard Mode = "standard"

	// ModePQCHybrid requires PQC and uses hybrid classical+PQC for sign/kem.
	ModePQCHybrid Mode = "pqc_hybrid"

	// ModePQCOnly allows only PQC algorithms (no classical ECDSA/ECDH/RSA/Ed25519/X25519).
	ModePQCOnly Mode = "pqc_only"
)

// Config holds the global cryptographic configuration.
// Once initialized, mode and EnablePQC are immutable.
type Config struct {
	mu           sync.RWMutex
	mode         Mode
	enablePQC    bool
	initialized  bool
	fipsOnly     bool // true if mode is fips_only
}

// Global config instance.
var globalConfig = &Config{}

// Init initializes the global configuration. Can only be called once.
// Returns ErrModeImmutable if called after initialization.
func Init(mode Mode, enablePQC bool) error {
	globalConfig.mu.Lock()
	defer globalConfig.mu.Unlock()

	if globalConfig.initialized {
		return cerr.ErrModeImmutable
	}

	// Validate mode
	switch mode {
	case ModeFIPSOnly, ModeStandard, ModePQCHybrid, ModePQCOnly:
	default:
		return cerr.ErrSuiteUnknown
	}

	// Validate PQC requirements
	if mode == ModePQCHybrid || mode == ModePQCOnly {
		if !enablePQC {
			return cerr.ErrPQCDisabled
		}
	}
	if mode == ModeFIPSOnly {
		// PQC not available in fips_only mode per spec
		enablePQC = false
	}

	globalConfig.mode = mode
	globalConfig.enablePQC = enablePQC
	globalConfig.fipsOnly = (mode == ModeFIPSOnly)
	globalConfig.initialized = true
	return nil
}

// GetMode returns the current mode.
func GetMode() Mode {
	globalConfig.mu.RLock()
	defer globalConfig.mu.RUnlock()
	return globalConfig.mode
}

// IsPQCEnabled returns whether PQC algorithms are enabled.
func IsPQCEnabled() bool {
	globalConfig.mu.RLock()
	defer globalConfig.mu.RUnlock()
	return globalConfig.enablePQC
}

// IsFIPSOnly returns whether we're in fips_only mode.
func IsFIPSOnly() bool {
	globalConfig.mu.RLock()
	defer globalConfig.mu.RUnlock()
	return globalConfig.fipsOnly
}

// IsInitialized returns whether config has been initialized.
func IsInitialized() bool {
	globalConfig.mu.RLock()
	defer globalConfig.mu.RUnlock()
	return globalConfig.initialized
}

// AlgorithmPermitted checks if an algorithm is permitted in the current mode.
// Returns ErrAlgorithmNotPermitted if not allowed.
func AlgorithmPermitted(algorithm string) error {
	globalConfig.mu.RLock()
	defer globalConfig.mu.RUnlock()

	if !globalConfig.initialized {
		// Default to standard mode with PQC disabled if not initialized
		return checkAlgorithmStandard(algorithm, false)
	}

	switch globalConfig.mode {
	case ModeFIPSOnly:
		return checkAlgorithmFIPSOnly(algorithm)
	case ModeStandard:
		return checkAlgorithmStandard(algorithm, globalConfig.enablePQC)
	case ModePQCHybrid:
		return checkAlgorithmPQCHybrid(algorithm)
	case ModePQCOnly:
		return checkAlgorithmPQCOnly(algorithm)
	}
	return cerr.ErrAlgorithmNotPermitted
}

// checkAlgorithmFIPSOnly checks algorithm against FIPS-only mode.
// Per spec table: FIPS allows AES-GCM, AES-XTS, AES-SIV, SHA-2/3, SHAKE, HMAC-SHA2/3, AES-CMAC/GMAC,
// HKDF, SP800-108, ANSI-X9.63, PBKDF2, ECDSA-P256/384, Ed25519, RSA-PSS-3072/4096, ECDH-P256/384,
// AES-KW/KWP, CTR_DRBG, HMAC_DRBG.
// NOT allowed: ChaCha20-Poly1305, X25519, Argon2id, scrypt, bcrypt, ML-KEM, ML-DSA, SLH-DSA, HPKE-Hybrid.
func checkAlgorithmFIPSOnly(algo string) error {
	// Symmetric encryption
	switch algo {
	case "AES-256-GCM", "AES-256-XTS", "AES-256-SIV":
		return nil
	case "ChaCha20-Poly1305":
		return cerr.ErrAlgorithmNotPermitted
	}

	// Hash/Digest
	switch algo {
	case "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256":
		return nil
	}

	// MAC
	switch algo {
	case "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512", "HMAC-SHA3-256", "AES-CMAC", "AES-GMAC":
		return nil
	}

	// KDF (high entropy)
	switch algo {
	case "HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512", "SP800-108-CTR", "ANSI-X9.63":
		return nil
	}

	// KDF (password)
	switch algo {
	case "PBKDF2-SHA256", "PBKDF2-SHA384":
		return nil
	case "Argon2id", "scrypt", "bcrypt":
		return cerr.ErrAlgorithmNotPermitted
	}

	// Signatures
	switch algo {
	case "ECDSA-P256", "ECDSA-P384", "Ed25519", "RSA-PSS-3072", "RSA-PSS-4096":
		return nil
	case "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s":
		return cerr.ErrAlgorithmNotPermitted // PQC not in FIPS-only yet
	}

	// KEM
	switch algo {
	case "ECDH-P256", "ECDH-P384":
		return nil
	case "X25519", "ML-KEM-768", "ML-KEM-1024":
		return cerr.ErrAlgorithmNotPermitted
	}

	// HPKE
	switch algo {
	case "HPKE-Classic":
		return nil
	case "HPKE-Hybrid":
		return cerr.ErrAlgorithmNotPermitted
	}

	// Key Wrap
	switch algo {
	case "AES-256-KW", "AES-256-KWP":
		return nil
	}

	// FPE
	switch algo {
	case "FF1":
		return nil
	}

	// DRBG
	switch algo {
	case "CTR_DRBG-AES256", "HMAC_DRBG-SHA256":
		return nil
	}

	return cerr.ErrAlgorithmNotPermitted
}

// checkAlgorithmStandard checks algorithm against standard mode.
func checkAlgorithmStandard(algo string, enablePQC bool) error {
	// Symmetric encryption
	switch algo {
	case "AES-256-GCM", "AES-256-XTS", "AES-256-SIV", "ChaCha20-Poly1305":
		return nil
	}

	// Hash/Digest
	switch algo {
	case "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256":
		return nil
	}

	// MAC
	switch algo {
	case "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512", "HMAC-SHA3-256", "AES-CMAC", "AES-GMAC":
		return nil
	}

	// KDF (high entropy)
	switch algo {
	case "HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512", "SP800-108-CTR", "ANSI-X9.63":
		return nil
	}

	// KDF (password)
	switch algo {
	case "PBKDF2-SHA256", "PBKDF2-SHA384", "Argon2id", "scrypt":
		return nil
	case "bcrypt":
		return nil // legacy compat, warning emitted elsewhere
	}

	// Signatures
	switch algo {
	case "ECDSA-P256", "ECDSA-P384", "Ed25519", "RSA-PSS-3072", "RSA-PSS-4096":
		return nil
	case "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s":
		if enablePQC {
			return nil
		}
		return cerr.ErrPQCDisabled
	}

	// KEM
	switch algo {
	case "ECDH-P256", "ECDH-P384", "X25519":
		return nil
	case "ML-KEM-768", "ML-KEM-1024":
		if enablePQC {
			return nil
		}
		return cerr.ErrPQCDisabled
	case "ML-KEM-512":
		return cerr.ErrParameterBelowFloor
	}

	// HPKE
	switch algo {
	case "HPKE-Classic":
		return nil
	case "HPKE-Hybrid":
		if enablePQC {
			return nil
		}
		return cerr.ErrPQCDisabled
	}

	// Key Wrap
	switch algo {
	case "AES-256-KW", "AES-256-KWP":
		return nil
	}

	// FPE
	switch algo {
	case "FF1":
		return nil
	}

	// DRBG
	switch algo {
	case "CTR_DRBG-AES256", "HMAC_DRBG-SHA256":
		return nil
	}

	return cerr.ErrAlgorithmNotPermitted
}

// checkAlgorithmPQCHybrid checks algorithm against pqc_hybrid mode (requires enable_pqc=true).
func checkAlgorithmPQCHybrid(algo string) error {
	// In pqc_hybrid mode, both classical and PQC are used simultaneously for sign/kem
	// All standard algorithms allowed + PQC
	return checkAlgorithmStandard(algo, true)
}

// checkAlgorithmPQCOnly checks algorithm against pqc_only mode (requires enable_pqc=true).
// In pqc_only mode: ECDSA, ECDH, RSA, Ed25519, X25519 all return ErrAlgorithmNotPermitted.
func checkAlgorithmPQCOnly(algo string) error {
	// Symmetric encryption
	switch algo {
	case "AES-256-GCM", "AES-256-XTS", "AES-256-SIV", "ChaCha20-Poly1305":
		return nil
	}

	// Hash/Digest
	switch algo {
	case "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256":
		return nil
	}

	// MAC
	switch algo {
	case "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512", "HMAC-SHA3-256", "AES-CMAC", "AES-GMAC":
		return nil
	}

	// KDF (high entropy)
	switch algo {
	case "HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512", "SP800-108-CTR", "ANSI-X9.63":
		return nil
	}

	// KDF (password)
	switch algo {
	case "PBKDF2-SHA256", "PBKDF2-SHA384", "Argon2id", "scrypt":
		return nil
	case "bcrypt":
		return nil
	}

	// Signatures - ONLY PQC allowed
	switch algo {
	case "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s":
		return nil
	case "ECDSA-P256", "ECDSA-P384", "Ed25519", "RSA-PSS-3072", "RSA-PSS-4096":
		return cerr.ErrAlgorithmNotPermitted
	}

	// KEM - ONLY PQC allowed
	switch algo {
	case "ML-KEM-768", "ML-KEM-1024":
		return nil
	case "ECDH-P256", "ECDH-P384", "X25519":
		return cerr.ErrAlgorithmNotPermitted
	case "ML-KEM-512":
		return cerr.ErrParameterBelowFloor
	}

	// HPKE - ONLY Hybrid allowed
	switch algo {
	case "HPKE-Hybrid":
		return nil
	case "HPKE-Classic":
		return cerr.ErrAlgorithmNotPermitted
	}

	// Key Wrap
	switch algo {
	case "AES-256-KW", "AES-256-KWP":
		return nil
	}

	// FPE
	switch algo {
	case "FF1":
		return nil
	}

	// DRBG
	switch algo {
	case "CTR_DRBG-AES256", "HMAC_DRBG-SHA256":
		return nil
	}

	return cerr.ErrAlgorithmNotPermitted
}

// RequireHybrid returns true if the current mode requires hybrid classical+PQC operations.
func RequireHybrid() bool {
	globalConfig.mu.RLock()
	defer globalConfig.mu.RUnlock()
	return globalConfig.mode == ModePQCHybrid
}

// ResetForTesting resets the global config (only for testing).
func ResetForTesting() {
	globalConfig.mu.Lock()
	defer globalConfig.mu.Unlock()
	globalConfig.mode = ""
	globalConfig.enablePQC = false
	globalConfig.initialized = false
	globalConfig.fipsOnly = false
}