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

package config

import (
	"testing"

	cerr "github.com/moeghifar/krypton/lib/errors"
)

// reset ensures each subtest starts from a clean slate.
func reset(t *testing.T) {
	t.Helper()
	ResetForTesting()
}

func TestInitAllModes(t *testing.T) {
	tests := []struct {
		name       string
		mode       Mode
		enablePQC  bool
		wantErr    error
		wantMode   Mode
		wantPQC    bool
		wantFIPS   bool
	}{
		{
			name:      "fips_only without PQC",
			mode:      ModeFIPSOnly,
			enablePQC: false,
			wantErr:   nil,
			wantMode:  ModeFIPSOnly,
			wantPQC:   false,
			wantFIPS:  true,
		},
		{
			name:      "standard without PQC",
			mode:      ModeStandard,
			enablePQC: false,
			wantErr:   nil,
			wantMode:  ModeStandard,
			wantPQC:   false,
			wantFIPS:  false,
		},
		{
			name:      "standard with PQC",
			mode:      ModeStandard,
			enablePQC: true,
			wantErr:   nil,
			wantMode:  ModeStandard,
			wantPQC:   true,
			wantFIPS:  false,
		},
		{
			name:      "pqc_hybrid with PQC",
			mode:      ModePQCHybrid,
			enablePQC: true,
			wantErr:   nil,
			wantMode:  ModePQCHybrid,
			wantPQC:   true,
			wantFIPS:  false,
		},
		{
			name:      "pqc_only with PQC",
			mode:      ModePQCOnly,
			enablePQC: true,
			wantErr:   nil,
			wantMode:  ModePQCOnly,
			wantPQC:   true,
			wantFIPS:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reset(t)

			err := Init(tc.mode, tc.enablePQC)
			if err != tc.wantErr {
				t.Fatalf("Init(%q, %v) error = %v, want %v", tc.mode, tc.enablePQC, err, tc.wantErr)
			}
			if err != nil {
				return
			}

			if got := GetMode(); got != tc.wantMode {
				t.Errorf("GetMode() = %q, want %q", got, tc.wantMode)
			}
			if got := IsPQCEnabled(); got != tc.wantPQC {
				t.Errorf("IsPQCEnabled() = %v, want %v", got, tc.wantPQC)
			}
			if got := IsFIPSOnly(); got != tc.wantFIPS {
				t.Errorf("IsFIPSOnly() = %v, want %v", got, tc.wantFIPS)
			}
			if got := IsInitialized(); !got {
				t.Errorf("IsInitialized() = false, want true")
			}
		})
	}
}

func TestInitValidation(t *testing.T) {
	t.Run("pqc_hybrid without enable_pqc fails", func(t *testing.T) {
		reset(t)
		err := Init(ModePQCHybrid, false)
		if err != cerr.ErrPQCDisabled {
			t.Fatalf("Init(ModePQCHybrid, false) error = %v, want ErrPQCDisabled", err)
		}
		if IsInitialized() {
			t.Error("expected IsInitialized() = false after failed init")
		}
	})

	t.Run("pqc_only without enable_pqc fails", func(t *testing.T) {
		reset(t)
		err := Init(ModePQCOnly, false)
		if err != cerr.ErrPQCDisabled {
			t.Fatalf("Init(ModePQCOnly, false) error = %v, want ErrPQCDisabled", err)
		}
		if IsInitialized() {
			t.Error("expected IsInitialized() = false after failed init")
		}
	})

	t.Run("unknown mode fails", func(t *testing.T) {
		reset(t)
		err := Init(Mode("unknown_mode"), false)
		if err != cerr.ErrSuiteUnknown {
			t.Fatalf("Init(unknown_mode, false) error = %v, want ErrSuiteUnknown", err)
		}
		if IsInitialized() {
			t.Error("expected IsInitialized() = false after failed init")
		}
	})

	t.Run("fips_only forces PQC off even if enable_pqc=true", func(t *testing.T) {
		reset(t)
		if err := Init(ModeFIPSOnly, true); err != nil {
			t.Fatalf("Init(ModeFIPSOnly, true) unexpected error: %v", err)
		}
		if IsPQCEnabled() {
			t.Error("fips_only should force IsPQCEnabled() = false even with enable_pqc=true")
		}
		if !IsFIPSOnly() {
			t.Error("expected IsFIPSOnly() = true")
		}
	})
}

func TestErrModeImmutable(t *testing.T) {
	reset(t)

	if err := Init(ModeStandard, false); err != nil {
		t.Fatalf("first Init failed: %v", err)
	}

	err := Init(ModeFIPSOnly, false)
	if err != cerr.ErrModeImmutable {
		t.Fatalf("second Init error = %v, want ErrModeImmutable", err)
	}

	// Mode should remain what was first set.
	if got := GetMode(); got != ModeStandard {
		t.Errorf("GetMode() = %q, want %q (mode should be unchanged)", got, ModeStandard)
	}
}

func TestIsInitialized(t *testing.T) {
	t.Run("false before init", func(t *testing.T) {
		reset(t)
		if IsInitialized() {
			t.Error("expected IsInitialized() = false before Init")
		}
	})

	t.Run("true after successful init", func(t *testing.T) {
		reset(t)
		if err := Init(ModeStandard, false); err != nil {
			t.Fatal(err)
		}
		if !IsInitialized() {
			t.Error("expected IsInitialized() = true after Init")
		}
	})

	t.Run("unset after reset", func(t *testing.T) {
		reset(t)
		if err := Init(ModeStandard, false); err != nil {
			t.Fatal(err)
		}
		ResetForTesting()
		if IsInitialized() {
			t.Error("expected IsInitialized() = false after ResetForTesting")
		}
	})
}

func TestResetForTesting(t *testing.T) {
	reset(t)
	if err := Init(ModeStandard, true); err != nil {
		t.Fatal(err)
	}

	ResetForTesting()

	if IsInitialized() {
		t.Error("IsInitialized() = true, want false after reset")
	}
	if IsPQCEnabled() {
		t.Error("IsPQCEnabled() = true, want false after reset")
	}
	if IsFIPSOnly() {
		t.Error("IsFIPSOnly() = true, want false after reset")
	}
	if got := GetMode(); got != "" {
		t.Errorf("GetMode() = %q, want empty after reset", got)
	}

	// Must be re-initializable after reset.
	if err := Init(ModeFIPSOnly, false); err != nil {
		t.Fatalf("re-init after reset failed: %v", err)
	}
	if GetMode() != ModeFIPSOnly {
		t.Errorf("GetMode() = %q, want ModeFIPSOnly after re-init", GetMode())
	}
}

// ---------------------------------------------------------------------------
// AlgorithmPermitted — Section 6 algorithm table
// ---------------------------------------------------------------------------

// allowedFIPSOnly enumerates every algorithm permitted in fips_only mode.
var allowedFIPSOnly = []string{
	// Symmetric
	"AES-256-GCM", "AES-256-XTS", "AES-256-SIV",
	// Hash
	"SHA-256", "SHA-384", "SHA-512",
	"SHA3-256", "SHA3-384", "SHA3-512",
	"SHAKE128", "SHAKE256",
	// MAC
	"HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512", "HMAC-SHA3-256",
	"AES-CMAC", "AES-GMAC",
	// KDF (high-entropy)
	"HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512",
	"SP800-108-CTR", "ANSI-X9.63",
	// KDF (password)
	"PBKDF2-SHA256", "PBKDF2-SHA384",
	// Signatures
	"ECDSA-P256", "ECDSA-P384", "Ed25519",
	"RSA-PSS-3072", "RSA-PSS-4096",
	// KEM
	"ECDH-P256", "ECDH-P384",
	// HPKE
	"HPKE-Classic",
	// Key Wrap
	"AES-256-KW", "AES-256-KWP",
	// FPE
	// DRBG
	"CTR_DRBG-AES256", "HMAC_DRBG-SHA256",
}

var disallowedFIPSOnly = []string{
	// Not FIPS-approved symmetric
	"ChaCha20-Poly1305",
	// Password KDFs not in FIPS
	"Argon2id", "scrypt", "bcrypt",
	// PQC signatures
	"ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s",
	// PQC + non-FIPS KEMs
	"X25519", "ML-KEM-768", "ML-KEM-1024",
	// HPKE Hybrid (PQC)
	"HPKE-Hybrid",
}

var disallowedStandard = []string{
	// ML-KEM-512 is below the security floor
	"ML-KEM-512",
}

var allowedStandardWithPQC = []string{
	"ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s",
	"ML-KEM-768", "ML-KEM-1024",
	"HPKE-Hybrid",
}

var disallowedStandardWithoutPQC = allowedStandardWithPQC

var disallowedPQCOnly = []string{
	// Classical signatures
	"ECDSA-P256", "ECDSA-P384", "Ed25519",
	"RSA-PSS-3072", "RSA-PSS-4096",
	// Classical KEMs
	"ECDH-P256", "ECDH-P384", "X25519",
	// Classic HPKE
	"HPKE-Classic",
}

var allowedPQCOnly = []string{
	// Symmetric (mode-agnostic)
	"AES-256-GCM", "ChaCha20-Poly1305",
	// Hash
	"SHA-256", "SHA3-256", "SHAKE128",
	// MAC
	"HMAC-SHA256", "AES-CMAC",
	// KDF (high)
	"HKDF-SHA256", "SP800-108-CTR",
	// KDF (password)
	"PBKDF2-SHA256", "Argon2id", "scrypt",
	// PQC Signatures
	"ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s",
	// PQC KEM
	"ML-KEM-768", "ML-KEM-1024",
	// HPKE Hybrid
	"HPKE-Hybrid",
	// Key Wrap
	"AES-256-KW",
	// FPE
	"FF1",
	// DRBG
	"CTR_DRBG-AES256",
}

func TestAlgorithmPermitted_FIPSOnly(t *testing.T) {
	reset(t)
	if err := Init(ModeFIPSOnly, false); err != nil {
		t.Fatal(err)
	}

	for _, algo := range allowedFIPSOnly {
		t.Run("allow/"+algo, func(t *testing.T) {
			if err := AlgorithmPermitted(algo); err != nil {
				t.Errorf("AlgorithmPermitted(%q) = %v, want nil", algo, err)
			}
		})
	}
	for _, algo := range disallowedFIPSOnly {
		t.Run("deny/"+algo, func(t *testing.T) {
			if err := AlgorithmPermitted(algo); err != cerr.ErrAlgorithmNotPermitted {
				t.Errorf("AlgorithmPermitted(%q) = %v, want ErrAlgorithmNotPermitted", algo, err)
			}
		})
	}
}

func TestAlgorithmPermitted_Standard(t *testing.T) {
	t.Run("without_pqc", func(t *testing.T) {
		reset(t)
		if err := Init(ModeStandard, false); err != nil {
			t.Fatal(err)
		}

		// Everything that fips_only allows is also allowed, plus ChaCha/X25519/Argon2id/scrypt.
		extraAllowed := []string{
			"ChaCha20-Poly1305", "X25519", "Argon2id", "scrypt", "bcrypt",
		}
		for _, algo := range extraAllowed {
			t.Run("allow/"+algo, func(t *testing.T) {
				if err := AlgorithmPermitted(algo); err != nil {
					t.Errorf("AlgorithmPermitted(%q) = %v, want nil", algo, err)
				}
			})
		}

		// PQC-specific algorithms must be denied when PQC is off.
		for _, algo := range disallowedStandardWithoutPQC {
			t.Run("deny/"+algo, func(t *testing.T) {
				if err := AlgorithmPermitted(algo); err != cerr.ErrPQCDisabled {
					t.Errorf("AlgorithmPermitted(%q) = %v, want ErrPQCDisabled", algo, err)
				}
			})
		}

		// ML-KEM-512 below the floor regardless of PQC flag.
		t.Run("below_floor/ML-KEM-512", func(t *testing.T) {
			if err := AlgorithmPermitted("ML-KEM-512"); err != cerr.ErrParameterBelowFloor {
				t.Errorf("got %v, want ErrParameterBelowFloor", err)
			}
		})
	})

	t.Run("with_pqc", func(t *testing.T) {
		reset(t)
		if err := Init(ModeStandard, true); err != nil {
			t.Fatal(err)
		}

		for _, algo := range allowedStandardWithPQC {
			t.Run("allow/"+algo, func(t *testing.T) {
				if err := AlgorithmPermitted(algo); err != nil {
					t.Errorf("AlgorithmPermitted(%q) = %v, want nil", algo, err)
				}
			})
		}

		t.Run("below_floor/ML-KEM-512", func(t *testing.T) {
			if err := AlgorithmPermitted("ML-KEM-512"); err != cerr.ErrParameterBelowFloor {
				t.Errorf("got %v, want ErrParameterBelowFloor", err)
			}
		})
	})
}

func TestAlgorithmPermitted_PQCHybrid(t *testing.T) {
	reset(t)
	if err := Init(ModePQCHybrid, true); err != nil {
		t.Fatal(err)
	}

	// Everything standard-with-pqc allows is also allowed in pqc_hybrid (hybrid delegates to standard with pqc=true).
	for _, algo := range append(allowedFIPSOnly, "ChaCha20-Poly1305", "X25519", "Argon2id", "scrypt", "bcrypt") {
		t.Run("allow/classical/"+algo, func(t *testing.T) {
			if err := AlgorithmPermitted(algo); err != nil {
				t.Errorf("AlgorithmPermitted(%q) = %v, want nil", algo, err)
			}
		})
	}
	for _, algo := range allowedStandardWithPQC {
		t.Run("allow/pqc/"+algo, func(t *testing.T) {
			if err := AlgorithmPermitted(algo); err != nil {
				t.Errorf("AlgorithmPermitted(%q) = %v, want nil", algo, err)
			}
		})
	}

	t.Run("below_floor/ML-KEM-512", func(t *testing.T) {
		if err := AlgorithmPermitted("ML-KEM-512"); err != cerr.ErrParameterBelowFloor {
			t.Errorf("got %v, want ErrParameterBelowFloor", err)
		}
	})

	t.Run("unknown_algo", func(t *testing.T) {
		if err := AlgorithmPermitted("totally-unknown-algo"); err != cerr.ErrAlgorithmNotPermitted {
			t.Errorf("got %v, want ErrAlgorithmNotPermitted", err)
		}
	})
}

func TestAlgorithmPermitted_PQCOnly(t *testing.T) {
	reset(t)
	if err := Init(ModePQCOnly, true); err != nil {
		t.Fatal(err)
	}

	for _, algo := range allowedPQCOnly {
		t.Run("allow/"+algo, func(t *testing.T) {
			if err := AlgorithmPermitted(algo); err != nil {
				t.Errorf("AlgorithmPermitted(%q) = %v, want nil", algo, err)
			}
		})
	}
	for _, algo := range disallowedPQCOnly {
		t.Run("deny/"+algo, func(t *testing.T) {
			if err := AlgorithmPermitted(algo); err != cerr.ErrAlgorithmNotPermitted {
				t.Errorf("AlgorithmPermitted(%q) = %v, want ErrAlgorithmNotPermitted", algo, err)
			}
		})
	}
	t.Run("below_floor/ML-KEM-512", func(t *testing.T) {
		if err := AlgorithmPermitted("ML-KEM-512"); err != cerr.ErrParameterBelowFloor {
			t.Errorf("got %v, want ErrParameterBelowFloor", err)
		}
	})
}

func TestAlgorithmPermitted_Uninitialized(t *testing.T) {
	reset(t)
	// Uninitialized config should fall back to standard-without-PQC behavior.
	if err := AlgorithmPermitted("AES-256-GCM"); err != nil {
		t.Errorf("AES-256-GCM should be permitted by default, got %v", err)
	}
	if err := AlgorithmPermitted("ChaCha20-Poly1305"); err != nil {
		t.Errorf("ChaCha20-Poly1305 should be permitted by default, got %v", err)
	}
	if err := AlgorithmPermitted("ML-KEM-768"); err != cerr.ErrPQCDisabled {
		t.Errorf("ML-KEM-768 should return ErrPQCDisabled when uninitialized, got %v", err)
	}
}

func TestRequireHybrid(t *testing.T) {
	tests := []struct {
		name      string
		mode      Mode
		enablePQC bool
		want      bool
	}{
		{"fips_only", ModeFIPSOnly, false, false},
		{"standard", ModeStandard, false, false},
		{"standard_pqc", ModeStandard, true, false},
		{"pqc_hybrid", ModePQCHybrid, true, true},
		{"pqc_only", ModePQCOnly, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reset(t)
			if err := Init(tc.mode, tc.enablePQC); err != nil {
				t.Fatal(err)
			}
			if got := RequireHybrid(); got != tc.want {
				t.Errorf("RequireHybrid() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestModeBehavior_AlgorithmMatrix(t *testing.T) {
	// Full mode x algorithm cross-product matrix ensuring the documented behavior:
	//   fips_only blocks ChaCha/X25519/Argon2id
	//   pqc_only blocks classical sigs/KEMs
	//   pqc_hybrid allows everything in standard+PQC
	reset(t)

	type entry struct {
		algo     string
		fips     bool
		std      bool
		stdPQC   bool
		hybrid   bool
		pqcOnly  bool
	}

	matrix := []entry{
		// Symmetric
		{"AES-256-GCM", true, true, true, true, true},
		{"AES-256-XTS", true, true, true, true, true},
		{"ChaCha20-Poly1305", false, true, true, true, true},
		// Hash
		{"SHA-256", true, true, true, true, true},
		{"SHA3-512", true, true, true, true, true},
		// Password KDF
		{"Argon2id", false, true, true, true, true},
		{"bcrypt", false, true, true, true, true},
		// Classical signatures
		{"ECDSA-P256", true, true, true, true, false},
		{"Ed25519", true, true, true, true, false},
		{"RSA-PSS-4096", true, true, true, true, false},
		// PQC signatures
		{"ML-DSA-65", false, false, true, true, true},
		{"SLH-DSA-SHA2-128s", false, false, true, true, true},
		// Classical KEM
		{"ECDH-P384", true, true, true, true, false},
		{"X25519", false, true, true, true, false},
		// PQC KEM
		{"ML-KEM-768", false, false, true, true, true},
		// HPKE
		{"HPKE-Classic", true, true, true, true, false},
		{"HPKE-Hybrid", false, false, true, true, true},
	}

	run := func(mode Mode, enablePQC bool) func(*testing.T) {
		return func(t *testing.T) {
			reset(t)
			if err := Init(mode, enablePQC); err != nil {
				t.Fatalf("Init(%q, %v) failed: %v", mode, enablePQC, err)
			}
			for _, e := range matrix {
				permitted := AlgorithmPermitted(e.algo) == nil
				t.Run(e.algo, func(t *testing.T) {
					var want bool
					switch mode {
					case ModeFIPSOnly:
						want = e.fips
					case ModeStandard:
						if enablePQC {
							want = e.stdPQC
						} else {
							want = e.std
						}
					case ModePQCHybrid:
						want = e.hybrid
					case ModePQCOnly:
						want = e.pqcOnly
					}
					if permitted != want {
						t.Errorf("mode=%s PQC=%v AlgorithmPermitted(%q)=%v, want permitted=%v",
							mode, enablePQC, e.algo, permitted, want)
					}
				})
			}
		}
	}

	t.Run("fips_only", run(ModeFIPSOnly, false))
	t.Run("standard", run(ModeStandard, false))
	t.Run("standard_pqc", run(ModeStandard, true))
	t.Run("pqc_hybrid", run(ModePQCHybrid, true))
	t.Run("pqc_only", run(ModePQCOnly, true))
}

func TestInvalidModeString(t *testing.T) {
	// A blank Mode is not a valid initialized mode — it should not be reachable
	// via Init, but via AlgorithmPermitted when uninitialized it should fall
	// through to the default uninitialized behavior.
	reset(t)
	if err := Init(Mode(""), false); err != cerr.ErrSuiteUnknown {
		t.Errorf("Init with empty mode: got %v, want ErrSuiteUnknown", err)
	}
}
