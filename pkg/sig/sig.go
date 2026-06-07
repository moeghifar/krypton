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

// Package sig implements Families 12 and 13.
// Family 12: keygen() — key pair generation for multiple algorithms.
// Family 13: sign(), verify() — digital signatures.
package sig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/moeghifar/krypton/lib/config"
	cerr "github.com/moeghifar/krypton/lib/errors"
	"github.com/moeghifar/krypton/lib/types"
)

// KeyPair represents a generated key pair.
type KeyPair = types.KeyPair

// KeyFormat represents the encoding format for keys.
type KeyFormat = types.KeyFormat

const (
	KeyFormatRawHex    KeyFormat = types.KeyFormatRawHex
	KeyFormatRawBase64 KeyFormat = types.KeyFormatRawBase64
	KeyFormatJWK       KeyFormat = types.KeyFormatJWK
	KeyFormatPEM       KeyFormat = types.KeyFormatPEM
)

// ecdsaPublicKeyToUncompressed serializes an ECDSA public key to uncompressed format (0x04 || X || Y).
func ecdsaPublicKeyToUncompressed(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	curveSize := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := leftPadBytes(pub.X.Bytes(), curveSize)
	yBytes := leftPadBytes(pub.Y.Bytes(), curveSize)
	return append([]byte{0x04}, append(xBytes, yBytes...)...)
}

// ecdsaPrivateKeyToRaw serializes an ECDSA private key to raw bytes.
func ecdsaPrivateKeyToRaw(priv *ecdsa.PrivateKey) []byte {
	if priv == nil || priv.D == nil {
		return nil
	}
	curveSize := (priv.Curve.Params().BitSize + 7) / 8
	return leftPadBytes(priv.D.Bytes(), curveSize)
}

// rawToECDSAPublicKey parses raw uncompressed bytes into an ECDSA public key.
func rawToECDSAPublicKey(curve elliptic.Curve, raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) < 1 || raw[0] != 0x04 {
		return nil, cerr.ErrKeyFormatInvalid
	}
	curveSize := (curve.Params().BitSize + 7) / 8
	expectedLen := 1 + 2*curveSize
	if len(raw) != expectedLen {
		return nil, cerr.ErrKeySizeInvalid
	}
	x := new(big.Int).SetBytes(raw[1 : 1+curveSize])
	y := new(big.Int).SetBytes(raw[1+curveSize:])
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// rsaPrivateKeyToRaw serializes an RSA private key's D value to raw bytes.
func rsaPrivateKeyToRaw(priv *rsa.PrivateKey) []byte {
	if priv == nil || priv.D == nil {
		return nil
	}
	return priv.D.Bytes()
}

// rawToECDSAPrivateKey parses raw bytes into an ECDSA private key.
func rawToECDSAPrivateKey(curve elliptic.Curve, raw []byte) (*ecdsa.PrivateKey, error) {
	curveSize := (curve.Params().BitSize + 7) / 8
	if len(raw) != curveSize {
		return nil, cerr.ErrKeySizeInvalid
	}
	d := new(big.Int).SetBytes(raw)
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = d
	return priv, nil
}

func leftPadBytes(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// KeyGen generates a key pair for the specified algorithm.
// Family 12: keygen(algorithm string, format KeyFormat) (KeyPair, error)
func KeyGen(algorithm string, format KeyFormat) (KeyPair, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return KeyPair{}, err
	}

	kp := KeyPair{
		Algorithm: algorithm,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	switch algorithm {
	case "ECDSA-P256":
		return keygenECDSA(algorithm, format, elliptic.P256(), kp)
	case "ECDSA-P384":
		return keygenECDSA(algorithm, format, elliptic.P384(), kp)
	case "Ed25519":
		return keygenEd25519(algorithm, format, kp)
	case "RSA-PSS-3072":
		return keygenRSA(algorithm, format, 3072, kp)
	case "RSA-PSS-4096":
		return keygenRSA(algorithm, format, 4096, kp)
	case "ML-DSA-65", "ML-DSA-87":
		return KeyPair{}, cerr.ErrPQCDisabled
	case "SLH-DSA-SHA2-128s":
		return KeyPair{}, cerr.ErrPQCDisabled
	case "ML-KEM-768", "ML-KEM-1024":
		return KeyPair{}, cerr.ErrPQCDisabled
	default:
		return KeyPair{}, cerr.ErrAlgorithmNotPermitted
	}
}

// Sign signs a message using the private key.
// Family 13: sign(private_key string, message []byte, algorithm string, key_format KeyFormat) ([]byte, error)
func Sign(privateKeyStr string, message []byte, algorithm string, keyFormat KeyFormat) ([]byte, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return nil, err
	}

	switch algorithm {
	case "ECDSA-P256", "ECDSA-P384":
		return signECDSA(privateKeyStr, message, keyFormat)
	case "Ed25519":
		return signEd25519(privateKeyStr, message, keyFormat)
	case "RSA-PSS-3072", "RSA-PSS-4096":
		return signRSA(privateKeyStr, message, keyFormat)
	case "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s":
		return nil, cerr.ErrPQCDisabled
	default:
		return nil, cerr.ErrAlgorithmNotPermitted
	}
}

// Verify verifies a signature.
// Family 13: verify(public_key string, message []byte, signature []byte, algorithm string, key_format KeyFormat) (bool, error)
func Verify(publicKeyStr string, message []byte, signature []byte, algorithm string, keyFormat KeyFormat) (bool, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return false, err
	}

	switch algorithm {
	case "ECDSA-P256", "ECDSA-P384":
		return verifyECDSA(publicKeyStr, message, signature, keyFormat)
	case "Ed25519":
		return verifyEd25519(publicKeyStr, message, signature, keyFormat)
	case "RSA-PSS-3072", "RSA-PSS-4096":
		return verifyRSA(publicKeyStr, message, signature, keyFormat)
	case "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s":
		return false, cerr.ErrPQCDisabled
	default:
		return false, cerr.ErrAlgorithmNotPermitted
	}
}

// --- ECDSA ---

func keygenECDSA(algorithm string, format KeyFormat, curve elliptic.Curve, kp KeyPair) (KeyPair, error) {
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return encodeKeyPair(&privKey.PublicKey, privKey, algorithm, format, kp)
}

func signECDSA(privateKeyStr string, message []byte, keyFormat KeyFormat) ([]byte, error) {
	privKey, err := parseECPrivateKey(privateKeyStr, keyFormat)
	if err != nil {
		return nil, err
	}
	hash := crypto.SHA256.New()
	hash.Write(message)
	digest := hash.Sum(nil)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func verifyECDSA(publicKeyStr string, message []byte, signature []byte, keyFormat KeyFormat) (bool, error) {
	pubKey, err := parseECPublicKey(publicKeyStr, keyFormat)
	if err != nil {
		return false, err
	}
	hash := crypto.SHA256.New()
	hash.Write(message)
	digest := hash.Sum(nil)
	return ecdsa.VerifyASN1(pubKey, digest, signature), nil
}

// --- Ed25519 ---

func keygenEd25519(algorithm string, format KeyFormat, kp KeyPair) (KeyPair, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return encodeEd25519KeyPair(pubKey, privKey, algorithm, format, kp)
}

func signEd25519(privateKeyStr string, message []byte, keyFormat KeyFormat) ([]byte, error) {
	privKey, err := parseEd25519PrivateKey(privateKeyStr, keyFormat)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(privKey, message), nil
}

func verifyEd25519(publicKeyStr string, message []byte, signature []byte, keyFormat KeyFormat) (bool, error) {
	pubKey, err := parseEd25519PublicKey(publicKeyStr, keyFormat)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(pubKey, message, signature), nil
}

// --- RSA-PSS ---

func keygenRSA(algorithm string, format KeyFormat, bits int, kp KeyPair) (KeyPair, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return KeyPair{}, err
	}
	return encodeRSAKeyPair(&privKey.PublicKey, privKey, algorithm, format, kp)
}

func signRSA(privateKeyStr string, message []byte, keyFormat KeyFormat) ([]byte, error) {
	privKey, err := parseRSAPrivateKey(privateKeyStr, keyFormat)
	if err != nil {
		return nil, err
	}
	hash := crypto.SHA256.New()
	hash.Write(message)
	digest := hash.Sum(nil)
	return rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, digest, nil)
}

func verifyRSA(publicKeyStr string, message []byte, signature []byte, keyFormat KeyFormat) (bool, error) {
	pubKey, err := parseRSAPublicKey(publicKeyStr, keyFormat)
	if err != nil {
		return false, err
	}
	hash := crypto.SHA256.New()
	hash.Write(message)
	digest := hash.Sum(nil)
	err = rsa.VerifyPSS(pubKey, crypto.SHA256, digest, signature, nil)
	return err == nil, nil
}

// --- Key encoding helpers ---

func encodeKeyPair(pubKey *ecdsa.PublicKey, privKey *ecdsa.PrivateKey, algorithm string, format KeyFormat, kp KeyPair) (KeyPair, error) {
	switch format {
	case KeyFormatPEM:
		privBytes, err := x509.MarshalECPrivateKey(privKey)
		if err != nil {
			return KeyPair{}, err
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return KeyPair{}, err
		}
		kp.PrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}))
		kp.PublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
	case KeyFormatRawHex:
		kp.PrivateKey = hex.EncodeToString(ecdsaPrivateKeyToRaw(privKey))
		kp.PublicKey = hex.EncodeToString(ecdsaPublicKeyToUncompressed(pubKey))
	case KeyFormatRawBase64:
		kp.PrivateKey = base64Raw(ecdsaPrivateKeyToRaw(privKey))
		kp.PublicKey = base64Raw(ecdsaPublicKeyToUncompressed(pubKey))
	case KeyFormatJWK:
		pubUncompressed := ecdsaPublicKeyToUncompressed(pubKey)
		if pubUncompressed == nil {
			return KeyPair{}, cerr.ErrKeyFormatInvalid
		}
		xBytes := leftPadBytes(pubUncompressed[1:1+(len(pubUncompressed)-1)/2], (pubKey.Params().BitSize+7)/8)
		yBytes := leftPadBytes(pubUncompressed[1+(len(pubUncompressed)-1)/2:], (pubKey.Params().BitSize+7)/8)
		jwkPriv := map[string]string{
			"kty": "EC",
			"crv": curveName(privKey.Curve),
			"d":   base64RawURL(ecdsaPrivateKeyToRaw(privKey)),
			"x":   base64RawURL(xBytes),
			"y":   base64RawURL(yBytes),
		}
		jwkPub := map[string]string{
			"kty": "EC",
			"crv": curveName(pubKey.Curve),
			"x":   base64RawURL(xBytes),
			"y":   base64RawURL(yBytes),
		}
		privJSON, _ := json.Marshal(jwkPriv)
		pubJSON, _ := json.Marshal(jwkPub)
		kp.PrivateKey = string(privJSON)
		kp.PublicKey = string(pubJSON)
	default:
		return KeyPair{}, cerr.ErrKeyFormatInvalid
	}
	return kp, nil
}

func encodeEd25519KeyPair(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey, algorithm string, format KeyFormat, kp KeyPair) (KeyPair, error) {
	switch format {
	case KeyFormatPEM:
		privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return KeyPair{}, err
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return KeyPair{}, err
		}
		kp.PrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}))
		kp.PublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
	case KeyFormatRawHex:
		kp.PrivateKey = hex.EncodeToString(privKey)
		kp.PublicKey = hex.EncodeToString(pubKey)
	case KeyFormatRawBase64:
		kp.PrivateKey = base64Raw(privKey)
		kp.PublicKey = base64Raw(pubKey)
	case KeyFormatJWK:
		jwkPriv := map[string]string{
			"kty": "OKP",
			"crv": "Ed25519",
			"d":   base64RawURL(privKey),
			"x":   base64RawURL(pubKey),
		}
		jwkPub := map[string]string{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64RawURL(pubKey),
		}
		privJSON, _ := json.Marshal(jwkPriv)
		pubJSON, _ := json.Marshal(jwkPub)
		kp.PrivateKey = string(privJSON)
		kp.PublicKey = string(pubJSON)
	default:
		return KeyPair{}, cerr.ErrKeyFormatInvalid
	}
	return kp, nil
}

func encodeRSAKeyPair(pubKey *rsa.PublicKey, privKey *rsa.PrivateKey, algorithm string, format KeyFormat, kp KeyPair) (KeyPair, error) {
	switch format {
	case KeyFormatPEM:
		privBytes := x509.MarshalPKCS1PrivateKey(privKey)
		pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return KeyPair{}, err
		}
		kp.PrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}))
		kp.PublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
	case KeyFormatRawHex:
		kp.PrivateKey = hex.EncodeToString(rsaPrivateKeyToRaw(privKey))
		kp.PublicKey = fmt.Sprintf("%x.%x", pubKey.N.Bytes(), []byte{byte(pubKey.E >> 24), byte(pubKey.E >> 16), byte(pubKey.E >> 8), byte(pubKey.E)})
	case KeyFormatRawBase64:
		kp.PrivateKey = base64Raw(rsaPrivateKeyToRaw(privKey))
		kp.PublicKey = base64Raw(pubKey.N.Bytes())
	case KeyFormatJWK:
		jwkPub := map[string]string{
			"kty": "RSA",
			"n":   base64RawURL(pubKey.N.Bytes()),
			"e":   base64RawURL([]byte{byte(pubKey.E >> 24), byte(pubKey.E >> 16), byte(pubKey.E >> 8), byte(pubKey.E)}),
		}
		pubJSON, _ := json.Marshal(jwkPub)
		kp.PublicKey = string(pubJSON)
		kp.PrivateKey = base64Raw(rsaPrivateKeyToRaw(privKey))
	default:
		return KeyPair{}, cerr.ErrKeyFormatInvalid
	}
	return kp, nil
}

// --- Key parsing helpers ---

func parseECPrivateKey(keyStr string, format KeyFormat) (*ecdsa.PrivateKey, error) {
	switch format {
	case KeyFormatPEM:
		block, _ := pem.Decode([]byte(keyStr))
		if block == nil {
			return nil, cerr.ErrKeyFormatInvalid
		}
		return x509.ParseECPrivateKey(block.Bytes)
	case KeyFormatRawHex:
		raw, err := hex.DecodeString(keyStr)
		if err != nil {
			return nil, cerr.ErrKeyFormatInvalid
		}
		// Need to determine curve from key size
		switch len(raw) {
		case 32:
			return rawToECDSAPrivateKey(elliptic.P256(), raw)
		case 48:
			return rawToECDSAPrivateKey(elliptic.P384(), raw)
		default:
			return nil, cerr.ErrKeySizeInvalid
		}
	default:
		return nil, cerr.ErrKeyFormatInvalid
	}
}

func parseECPublicKey(keyStr string, format KeyFormat) (*ecdsa.PublicKey, error) {
	switch format {
	case KeyFormatPEM:
		block, _ := pem.Decode([]byte(keyStr))
		if block == nil {
			return nil, cerr.ErrKeyFormatInvalid
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, cerr.ErrKeyFormatInvalid
		}
		return ecPub, nil
	case KeyFormatRawHex:
		raw, err := hex.DecodeString(keyStr)
		if err != nil {
			return nil, cerr.ErrKeyFormatInvalid
		}
		switch len(raw) {
		case 65: // P-256 uncompressed
			return rawToECDSAPublicKey(elliptic.P256(), raw)
		case 97: // P-384 uncompressed
			return rawToECDSAPublicKey(elliptic.P384(), raw)
		default:
			return nil, cerr.ErrKeySizeInvalid
		}
	default:
		return nil, cerr.ErrKeyFormatInvalid
	}
}

func parseEd25519PrivateKey(keyStr string, format KeyFormat) (ed25519.PrivateKey, error) {
	switch format {
	case KeyFormatPEM:
		block, _ := pem.Decode([]byte(keyStr))
		if block == nil {
			return nil, cerr.ErrKeyFormatInvalid
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, cerr.ErrKeyFormatInvalid
		}
		return edKey, nil
	case KeyFormatRawHex:
		b, err := hex.DecodeString(keyStr)
		if err != nil {
			return nil, cerr.ErrKeyFormatInvalid
		}
		if len(b) != ed25519.PrivateKeySize {
			return nil, cerr.ErrKeySizeInvalid
		}
		return ed25519.PrivateKey(b), nil
	default:
		return nil, cerr.ErrKeyFormatInvalid
	}
}

func parseEd25519PublicKey(keyStr string, format KeyFormat) (ed25519.PublicKey, error) {
	switch format {
	case KeyFormatPEM:
		block, _ := pem.Decode([]byte(keyStr))
		if block == nil {
			return nil, cerr.ErrKeyFormatInvalid
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, cerr.ErrKeyFormatInvalid
		}
		return edPub, nil
	case KeyFormatRawHex:
		b, err := hex.DecodeString(keyStr)
		if err != nil {
			return nil, cerr.ErrKeyFormatInvalid
		}
		if len(b) != ed25519.PublicKeySize {
			return nil, cerr.ErrKeySizeInvalid
		}
		return ed25519.PublicKey(b), nil
	default:
		return nil, cerr.ErrKeyFormatInvalid
	}
}

func parseRSAPrivateKey(keyStr string, format KeyFormat) (*rsa.PrivateKey, error) {
	switch format {
	case KeyFormatPEM:
		block, _ := pem.Decode([]byte(keyStr))
		if block == nil {
			return nil, cerr.ErrKeyFormatInvalid
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, cerr.ErrKeyFormatInvalid
	}
}

func parseRSAPublicKey(keyStr string, format KeyFormat) (*rsa.PublicKey, error) {
	switch format {
	case KeyFormatPEM:
		block, _ := pem.Decode([]byte(keyStr))
		if block == nil {
			return nil, cerr.ErrKeyFormatInvalid
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, cerr.ErrKeyFormatInvalid
		}
		return rsaPub, nil
	default:
		return nil, cerr.ErrKeyFormatInvalid
	}
}

// --- Utility functions ---

func curveName(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return "unknown"
	}
}

func base64Raw(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

func base64RawURL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
