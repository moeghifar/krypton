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

// Package kem implements Family 14: kem_encap(), kem_decap().
// Supports ECDH-P256, ECDH-P384, X25519.
package kem

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"

	"github.com/moeghifar/krypton/lib/config"
	cerr "github.com/moeghifar/krypton/lib/errors"
	"github.com/moeghifar/krypton/lib/types"
)

// KEMResult holds the output of key encapsulation.
type KEMResult = types.KEMResult

// KEMEncapsulate generates a shared secret and encapsulation using the public key.
func KEMEncapsulate(publicKeyStr string, algorithm string, keyFormat types.KeyFormat) (KEMResult, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return KEMResult{}, err
	}

	switch algorithm {
	case "ECDH-P256":
		return ecdhEncap(ecdh.P256(), publicKeyStr, keyFormat)
	case "ECDH-P384":
		return ecdhEncap(ecdh.P384(), publicKeyStr, keyFormat)
	case "X25519":
		return x25519Encap(publicKeyStr, keyFormat)
	case "ML-KEM-768", "ML-KEM-1024":
		return KEMResult{}, cerr.ErrPQCDisabled
	default:
		return KEMResult{}, cerr.ErrAlgorithmNotPermitted
	}
}

// KEMDecapsulate recovers the shared secret from the encapsulation using the private key.
func KEMDecapsulate(privateKeyStr string, encapsulation []byte, algorithm string, keyFormat types.KeyFormat) ([]byte, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return nil, err
	}

	switch algorithm {
	case "ECDH-P256":
		return ecdhDecap(ecdh.P256(), privateKeyStr, encapsulation, keyFormat)
	case "ECDH-P384":
		return ecdhDecap(ecdh.P384(), privateKeyStr, encapsulation, keyFormat)
	case "X25519":
		return x25519Decap(privateKeyStr, encapsulation, keyFormat)
	case "ML-KEM-768", "ML-KEM-1024":
		return nil, cerr.ErrPQCDisabled
	default:
		return nil, cerr.ErrAlgorithmNotPermitted
	}
}

// --- ECDH (P-256, P-384) ---

func ecdhEncap(curve ecdh.Curve, publicKeyStr string, keyFormat types.KeyFormat) (KEMResult, error) {
	pubKey, err := parseECDHPublicKey(publicKeyStr, keyFormat, curve)
	if err != nil {
		return KEMResult{}, err
	}

	ephemeralPrivKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return KEMResult{}, err
	}

	sharedSecret, err := ephemeralPrivKey.ECDH(pubKey)
	if err != nil {
		return KEMResult{}, err
	}

	ephemeralPubBytes := ephemeralPrivKey.PublicKey().Bytes()

	ss := make([]byte, 32)
	copy(ss, sharedSecret)

	return KEMResult{
		Encapsulation: ephemeralPubBytes,
		SharedSecret:  ss,
	}, nil
}

func ecdhDecap(curve ecdh.Curve, privateKeyStr string, encapsulation []byte, keyFormat types.KeyFormat) ([]byte, error) {
	privKey, err := parseECDHPrivateKey(privateKeyStr, keyFormat, curve)
	if err != nil {
		return nil, err
	}

	ephemeralPub, err := curve.NewPublicKey(encapsulation)
	if err != nil {
		return nil, cerr.ErrDecapsulationFailed
	}

	sharedSecret, err := privKey.ECDH(ephemeralPub)
	if err != nil {
		return nil, cerr.ErrDecapsulationFailed
	}

	return sharedSecret, nil
}

// ecdsaPublicKeyToUncompressed serializes an ECDSA public key to uncompressed format (0x04 || X || Y).
func ecdsaPublicKeyToUncompressed(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	curveSize := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := leftPad(pub.X.Bytes(), curveSize)
	yBytes := leftPad(pub.Y.Bytes(), curveSize)
	// 0x04 prefix for uncompressed point
	return append([]byte{0x04}, append(xBytes, yBytes...)...)
}

// ecdsaPrivateKeyToRaw serializes an ECDSA private key to raw bytes.
func ecdsaPrivateKeyToRaw(priv *ecdsa.PrivateKey) []byte {
	if priv == nil || priv.D == nil {
		return nil
	}
	curveSize := (priv.Curve.Params().BitSize + 7) / 8
	return leftPad(priv.D.Bytes(), curveSize)
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
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

func parseECDHPublicKey(keyStr string, keyFormat types.KeyFormat, curve ecdh.Curve) (*ecdh.PublicKey, error) {
	var rawKey []byte
	switch keyFormat {
	case types.KeyFormatPEM:
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
			rawKey = ecdsaPublicKeyToUncompressed(p)
			if rawKey == nil {
				return nil, cerr.ErrKeyFormatInvalid
			}
		case *ecdh.PublicKey:
			rawKey = p.Bytes()
		default:
			return nil, cerr.ErrKeyFormatInvalid
		}
	case types.KeyFormatRawHex:
		var err error
		rawKey, err = hex.DecodeString(keyStr)
		if err != nil {
			return nil, cerr.ErrKeyFormatInvalid
		}
	default:
		return nil, cerr.ErrKeyFormatInvalid
	}
	return curve.NewPublicKey(rawKey)
}

func parseECDHPrivateKey(keyStr string, keyFormat types.KeyFormat, curve ecdh.Curve) (*ecdh.PrivateKey, error) {
	var rawKey []byte
	switch keyFormat {
	case types.KeyFormatPEM:
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
	case types.KeyFormatRawHex:
		var err error
		rawKey, err = hex.DecodeString(keyStr)
		if err != nil {
			return nil, cerr.ErrKeyFormatInvalid
		}
		return curve.NewPrivateKey(rawKey)
	default:
		return nil, cerr.ErrKeyFormatInvalid
	}
}

// --- X25519 ---

func x25519Encap(publicKeyStr string, keyFormat types.KeyFormat) (KEMResult, error) {
	pubKey, err := parseECDHPublicKey(publicKeyStr, keyFormat, ecdh.X25519())
	if err != nil {
		return KEMResult{}, err
	}

	ephemeralPrivKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KEMResult{}, err
	}

	sharedSecret, err := ephemeralPrivKey.ECDH(pubKey)
	if err != nil {
		return KEMResult{}, err
	}

	ephemeralPubBytes := ephemeralPrivKey.PublicKey().Bytes()

	ss := make([]byte, 32)
	copy(ss, sharedSecret)

	return KEMResult{
		Encapsulation: ephemeralPubBytes,
		SharedSecret:  ss,
	}, nil
}

func x25519Decap(privateKeyStr string, encapsulation []byte, keyFormat types.KeyFormat) ([]byte, error) {
	privKey, err := parseECDHPrivateKey(privateKeyStr, keyFormat, ecdh.X25519())
	if err != nil {
		return nil, err
	}

	ephemeralPub, err := ecdh.X25519().NewPublicKey(encapsulation)
	if err != nil {
		return nil, cerr.ErrDecapsulationFailed
	}

	sharedSecret, err := privKey.ECDH(ephemeralPub)
	if err != nil {
		return nil, cerr.ErrDecapsulationFailed
	}

	return sharedSecret, nil
}
