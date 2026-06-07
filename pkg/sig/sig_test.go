package sig

import (
	"testing"

	"github.com/moeghifar/krypton/lib/config"
)

func init() {
	config.Init(config.ModeStandard, false)
}

func TestKeyGen_ECDSA_P256(t *testing.T) {
	kp, err := KeyGen("ECDSA-P256", KeyFormatPEM)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	if kp.Algorithm != "ECDSA-P256" {
		t.Errorf("algorithm: got %s, want ECDSA-P256", kp.Algorithm)
	}
	if kp.PublicKey == "" {
		t.Error("public key is empty")
	}
	if kp.PrivateKey == "" {
		t.Error("private key is empty")
	}
}

func TestSignVerify_ECDSA_P256(t *testing.T) {
	kp, err := KeyGen("ECDSA-P256", KeyFormatPEM)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	message := []byte("test message for ECDSA-P256")
	sig, err := Sign(kp.PrivateKey, message, "ECDSA-P256", KeyFormatPEM)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	ok, err := Verify(kp.PublicKey, message, sig, "ECDSA-P256", KeyFormatPEM)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Error("Verify returned false for valid signature")
	}

	// Wrong message
	ok, err = Verify(kp.PublicKey, []byte("wrong message"), sig, "ECDSA-P256", KeyFormatPEM)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if ok {
		t.Error("Verify returned true for wrong message")
	}
}

func TestKeyGen_ECDSA_P384(t *testing.T) {
	kp, err := KeyGen("ECDSA-P384", KeyFormatPEM)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	message := []byte("test message for ECDSA-P384")
	sig, err := Sign(kp.PrivateKey, message, "ECDSA-P384", KeyFormatPEM)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	ok, err := Verify(kp.PublicKey, message, sig, "ECDSA-P384", KeyFormatPEM)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Error("Verify returned false for valid signature")
	}
}

func TestKeyGen_Ed25519(t *testing.T) {
	kp, err := KeyGen("Ed25519", KeyFormatPEM)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	if kp.Algorithm != "Ed25519" {
		t.Errorf("algorithm: got %s, want Ed25519", kp.Algorithm)
	}

	message := []byte("test message for Ed25519")
	sig, err := Sign(kp.PrivateKey, message, "Ed25519", KeyFormatPEM)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	ok, err := Verify(kp.PublicKey, message, sig, "Ed25519", KeyFormatPEM)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Error("Verify returned false for valid Ed25519 signature")
	}
}

func TestSignVerify_Ed25519_HEX(t *testing.T) {
	kp, err := KeyGen("Ed25519", KeyFormatRawHex)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	message := []byte("hex-encoded keys test")
	sig, err := Sign(kp.PrivateKey, message, "Ed25519", KeyFormatRawHex)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	ok, err := Verify(kp.PublicKey, message, sig, "Ed25519", KeyFormatRawHex)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Error("Verify returned false for valid signature")
	}
}

func TestKeyGen_RSA_PSS_3072(t *testing.T) {
	kp, err := KeyGen("RSA-PSS-3072", KeyFormatPEM)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	message := []byte("test message for RSA-PSS-3072")
	sig, err := Sign(kp.PrivateKey, message, "RSA-PSS-3072", KeyFormatPEM)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	ok, err := Verify(kp.PublicKey, message, sig, "RSA-PSS-3072", KeyFormatPEM)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Error("Verify returned false for valid RSA-PSS signature")
	}
}

func TestKeyGen_RSA_PSS_4096(t *testing.T) {
	kp, err := KeyGen("RSA-PSS-4096", KeyFormatPEM)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	message := []byte("test message")
	sig, err := Sign(kp.PrivateKey, message, "RSA-PSS-4096", KeyFormatPEM)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	ok, err := Verify(kp.PublicKey, message, sig, "RSA-PSS-4096", KeyFormatPEM)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Error("Verify returned false for valid RSA-PSS-4096 signature")
	}
}

func TestKeyGen_FIPSMode(t *testing.T) {
	config.ResetForTesting()
	config.Init(config.ModeFIPSOnly, false)

	// ECDSA-P256 should be allowed
	_, err := KeyGen("ECDSA-P256", KeyFormatPEM)
	if err != nil {
		t.Errorf("ECDSA-P256 should be allowed in FIPS mode: %v", err)
	}

	// Ed25519 should be allowed
	_, err = KeyGen("Ed25519", KeyFormatPEM)
	if err != nil {
		t.Errorf("Ed25519 should be allowed in FIPS mode: %v", err)
	}
}

func TestKeyGen_InvalidAlgorithm(t *testing.T) {
	_, err := KeyGen("INVALID", KeyFormatPEM)
	if err == nil {
		t.Error("KeyGen should fail with invalid algorithm")
	}
}
