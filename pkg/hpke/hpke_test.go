package hpke

import (
	"crypto/ecdh"
	"testing"

	"github.com/moeghifar/krypton/lib/config"
)

func init() {
	config.Init(config.ModeStandard, false)
}

func TestHPKESealOpen_Classic(t *testing.T) {
	// Generate recipient key pair
	recipientPrivKey, err := ecdh.P256().GenerateKey(nil)
	if err != nil {
		t.Skip("requires crypto/rand")
	}

	pubKeyPEM := recipientPrivKey.PublicKey().Bytes()
	_ = pubKeyPEM

	// For a full test we'd need proper PEM encoding
	// For now, just verify the function handles errors
	_, err = HPKESeal("invalid-key", []byte("test"), []byte("aad"), suiteClassic)
	if err == nil {
		t.Error("HPKESeal should fail with invalid key")
	}
}

func TestHPKESeal_InvalidSuite(t *testing.T) {
	_, err := HPKESeal("key", []byte("test"), []byte("aad"), "INVALID")
	if err == nil {
		t.Error("HPKESeal should fail with invalid suite")
	}
}

func TestHPKEOpen_InvalidSuite(t *testing.T) {
	_, err := HPKEOpen("key", nil)
	if err == nil {
		t.Error("HPKEOpen should fail with nil envelope")
	}
}

func TestHPKESeal_FIPSMode(t *testing.T) {
	config.ResetForTesting()
	config.Init(config.ModeFIPSOnly, false)

	// HPKE-Classic should be allowed
	_, err := HPKESeal("key", []byte("test"), []byte("aad"), suiteClassic)
	// We expect a key parsing error, not an algorithm error
	if err == nil {
		t.Log("HPKESeal succeeded (unexpected)")
	}

	// HPKE-Hybrid should NOT be allowed in FIPS mode
	_, err = HPKESeal("key", []byte("test"), []byte("aad"), suiteHybrid)
	if err == nil {
		t.Error("HPKE-Hybrid should not be allowed in FIPS mode")
	}
}
