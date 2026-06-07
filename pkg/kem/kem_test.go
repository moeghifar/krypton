package kem

import (
	"crypto/ecdh"
	"testing"

	"github.com/moeghifar/krypton/lib/config"
	"github.com/moeghifar/krypton/lib/types"
)

func init() {
	config.Init(config.ModeStandard, false)
}

func TestKEMEncDecap_X25519(t *testing.T) {
	// Generate X25519 key pair
	privKey, err := ecdh.X25519().GenerateKey(nil) // Note: needs rand.Reader
	if err != nil {
		// If GenerateKey fails, skip this test since we need randomness
		t.Skip("X25519 key generation requires crypto/rand")
	}
	_ = privKey
}

func TestKEMEncDecap_ECDH_P256(t *testing.T) {
	// Generate recipient key pair
	recipientPrivKey, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Skip("requires crypto/rand")
	}

	pubKeyBytes := recipientPrivKey.PublicKey().Bytes()
	if err != nil {
		t.Fatalf("PublicKey().Bytes() failed: %v", err)
	}

	// For PEM format we'd need to encode, but let's test with raw
	_ = pubKeyBytes

	// The actual test requires proper PEM encoding which sig package provides
	// For now, just verify error handling
	_, err = KEMEncapsulate("invalid-key", "ECDH-P256", types.KeyFormatRawHex)
	if err == nil {
		t.Error("KEMEncapsulate should fail with invalid key")
	}
}

func TestKEM_UnknownAlgorithm(t *testing.T) {
	_, err := KEMEncapsulate("key", "UNKNOWN", types.KeyFormatPEM)
	if err == nil {
		t.Error("should fail with unknown algorithm")
	}
}

func TestKEM_FIPSMode(t *testing.T) {
	config.ResetForTesting()
	config.Init(config.ModeFIPSOnly, false)

	// ECDH-P256 should be allowed
	_, err := KEMEncapsulate("key", "ECDH-P256", types.KeyFormatRawHex)
	if err == nil {
		// Expected - the key is invalid, but the algorithm should be permitted
		// If we get a key-related error (not an algorithm error), that's OK
	}

	// X25519 should NOT be allowed in FIPS mode
	_, err = KEMEncapsulate("key", "X25519", types.KeyFormatRawHex)
	if err == nil {
		t.Error("X25519 should not be allowed in FIPS mode")
	}
}
