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

// Package hpke implements Family 15: hpke_seal(), hpke_open().
// HPKE-Classic: ECDH-P256 + HKDF-SHA256 + AES-256-GCM
// HPKE-Hybrid: ECDH-P256 + ML-KEM-768 + HKDF-SHA384 + AES-256-GCM (requires enable_pqc=true)
package hpke

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"hash"

	"github.com/moeghifar/krypton/lib/config"
	"github.com/moeghifar/krypton/pkg/cipher"
	"github.com/moeghifar/krypton/pkg/kdf"
	"github.com/moeghifar/krypton/lib/envelope"
	cerr "github.com/moeghifar/krypton/lib/errors"
)

const (
	suiteClassic = "HPKE-Classic"
	suiteHybrid  = "HPKE-Hybrid"

	hpkeVersion = "HPKE-v1"

	// Suite IDs (RFC 9180 Section 5.1)
	suiteIDHKDFSHA256 = "HKDF-SHA256"
	suiteIDHKDFSHA384 = "HKDF-SHA384"
	suiteIDAES256GCM  = "AES-256-GCM"
)

// HPKEConfig holds the suite configuration.
type HPKEConfig struct {
	KEM  string
	KDF  string
	AEAD string
}

var (
	classicConfig = HPKEConfig{KEM: "ECDH-P256", KDF: "HKDF-SHA256", AEAD: "AES-256-GCM"}
	hybridConfig  = HPKEConfig{KEM: "ECDH-P256+ML-KEM-768", KDF: "HKDF-SHA384", AEAD: "AES-256-GCM"}
)

// HPKESeal seals a plaintext for the recipient.
// Family 15: hpke_seal(recipient_public_key string, plaintext []byte, aad []byte, suite string) (Envelope, error)
func HPKESeal(recipientPublicKey string, plaintext []byte, aad []byte, suite string) (*envelope.Envelope, error) {
	if err := config.AlgorithmPermitted(suite); err != nil {
		return nil, err
	}

	switch suite {
	case suiteClassic:
		return hpkeSealClassic(recipientPublicKey, plaintext, aad)
	case suiteHybrid:
		return nil, cerr.ErrPQCDisabled // ML-KEM not yet implemented
	default:
		return nil, cerr.ErrSuiteUnknown
	}
}

// HPKEOpen opens a sealed envelope.
// Family 15: hpke_open(recipient_private_key string, envelope Envelope) ([]byte, error)
func HPKEOpen(recipientPrivateKey string, env *envelope.Envelope) ([]byte, error) {
	if env == nil {
		return nil, cerr.ErrDecryptionFailed
	}
	suite := env.SuiteID
	switch suite {
	case envelope.SuiteClassical:
		return hpkeOpenClassic(recipientPrivateKey, env)
	case envelope.SuitePQCHybrid:
		return nil, cerr.ErrPQCDisabled
	default:
		return nil, cerr.ErrSuiteUnknown
	}
}

// --- HPKE-Classic: ECDH-P256 + HKDF-SHA256 + AES-256-GCM ---

func hpkeSealClassic(recipientPublicKeyPEM string, plaintext []byte, aad []byte) (*envelope.Envelope, error) {
	// Generate ephemeral key pair
	ephemeralPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	ephemeralPubKey := ephemeralPrivKey.PublicKey().Bytes()
	if err != nil {
		return nil, err
	}

	// Parse recipient public key
	recipientPubKey, err := parseHPKEPublicKey(recipientPublicKeyPEM)
	if err != nil {
		return nil, err
	}

	// DH: shared_secret = ECDH(ephemeral_priv, recipient_pub)
	sharedSecret, err := ephemeralPrivKey.ECDH(recipientPubKey)
	if err != nil {
		return nil, err
	}

	// Key schedule
	// kem_context = enc || pkRm
	// shared_secret = ExtractAndExpand(shared_secret, kem_context)
	info := buildInfo(aad)
	key, err := kdf.KDF(sharedSecret, nil, info, 32, "HKDF-SHA256")
	if err != nil {
		return nil, err
	}

	// Encrypt with AES-256-GCM
	env, err := cipher.Encrypt(key, plaintext, string(aad), "AES-256-GCM")
	if err != nil {
		return nil, err
	}

	// Add HPKE-specific fields
	env.SuiteID = envelope.SuiteClassical
	env.EncClassical = base64Raw(ephemeralPubKey)

	return env, nil
}

func hpkeOpenClassic(recipientPrivateKeyPEM string, env *envelope.Envelope) ([]byte, error) {
	// Parse recipient private key
	recipientPrivKey, err := parseHPKEPrivateKey(recipientPrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	// Parse ephemeral public key from envelope
	encClassical, err := env.DecodeEncClassical()
	if err != nil {
		return nil, err
	}

	ephemeralPubKey, err := ecdh.P256().NewPublicKey(encClassical)
	if err != nil {
		return nil, cerr.ErrDecryptionFailed
	}

	// DH: shared_secret = ECDH(recipient_priv, ephemeral_pub)
	sharedSecret, err := recipientPrivKey.ECDH(ephemeralPubKey)
	if err != nil {
		return nil, cerr.ErrDecryptionFailed
	}

	// Key schedule
	aadBytes, _ := env.DecodeAAD()
	info := buildInfo(aadBytes)
	key, err := kdf.KDF(sharedSecret, nil, info, 32, "HKDF-SHA256")
	if err != nil {
		return nil, err
	}

	// Decrypt
	return cipher.Decrypt(key, env, string(aadBytes), "AES-256-GCM")
}

func parseHPKEPublicKey(keyStr string) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode([]byte(keyStr))
	if block == nil {
		return nil, cerr.ErrKeyFormatInvalid
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		rawKey := ecdsaPublicKeyToUncompressed(p)
		if rawKey == nil {
			return nil, cerr.ErrKeyFormatInvalid
		}
		return ecdh.P256().NewPublicKey(rawKey)
	case *ecdh.PublicKey:
		return p, nil
	default:
		return nil, cerr.ErrKeyFormatInvalid
	}
}

func parseHPKEPrivateKey(keyStr string) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyStr))
	if block == nil {
		return nil, cerr.ErrKeyFormatInvalid
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdhPriv, ok := priv.(*ecdh.PrivateKey)
	if !ok {
		return nil, cerr.ErrKeyFormatInvalid
	}
	return ecdhPriv, nil
}

// ecdsaPublicKeyToUncompressed serializes an ECDSA public key to uncompressed format.
func ecdsaPublicKeyToUncompressed(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	curveSize := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := leftPad(pub.X.Bytes(), curveSize)
	yBytes := leftPad(pub.Y.Bytes(), curveSize)
	return append([]byte{0x04}, append(xBytes, yBytes...)...)
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

func buildInfo(aad []byte) []byte {
	// HPKE info = "HPKE-v1" || suite_id || aad
	info := []byte(hpkeVersion)
	info = append(info, []byte("KEM")...)
	info = append(info, byte(0x00)) // DHKEM(P-256, HKDF-SHA256)
	info = append(info, byte(0x10))
	info = append(info, aad...)
	return info
}

func base64Raw(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

// suppress unused imports
var _ = sha256.New
var _ = sha512.New
var _ hash.Hash
