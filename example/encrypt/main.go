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

// Package main demonstrates symmetric encryption (Family 5 and Family 6).
//
// Usage:
//
//	go run example/encrypt/main.go
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/moeghifar/krypton/lib/config"
	"github.com/moeghifar/krypton/pkg/cipher"
)

func main() {
	if err := config.Init(config.ModeStandard, false); err != nil {
		log.Fatal(err)
	}

	// Family 5: encrypt / decrypt (AES-256-GCM, ChaCha20-Poly1305)
	fmt.Println("=== Family 5: encrypt / decrypt ===")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	plaintext := []byte("Hello, World! This is a secret message.")
	context := "example-context"

	for _, algo := range []string{"AES-256-GCM", "ChaCha20-Poly1305"} {
		env, err := cipher.Encrypt(key, plaintext, context, algo)
		if err != nil {
			log.Printf("%s encrypt error: %v", algo, err)
			continue
		}
		decrypted, err := cipher.Decrypt(key, env, context, algo)
		if err != nil {
			log.Printf("%s decrypt error: %v", algo, err)
			continue
		}
		fmt.Printf("%-20s: plaintext=%q decrypted=%q match=%v\n",
			algo, string(plaintext), string(decrypted), string(decrypted) == string(plaintext))
	}

	// Family 6: encrypt_det / decrypt_det (AES-256-SIV)
	fmt.Println("\n=== Family 6: encrypt_det / decrypt_det (AES-256-SIV) ===")
	sivKey := make([]byte, 64)
	for i := range sivKey {
		sivKey[i] = byte(i + 1)
	}
	detPlaintext := []byte("deterministic encryption test")
	detContext := "siv-context"

	ct, err := cipher.EncryptDet(sivKey, detPlaintext, detContext)
	if err != nil {
		log.Printf("SIV encrypt error: %v", err)
	} else {
		dec, err := cipher.DecryptDet(sivKey, ct, detContext)
		if err != nil {
			log.Printf("SIV decrypt error: %v", err)
		} else {
			fmt.Printf("AES-256-SIV: plaintext=%q decrypted=%q match=%v\n",
				string(detPlaintext), string(dec), string(dec) == string(detPlaintext))
		}
		// Deterministic: same input = same output
		ct2, _ := cipher.EncryptDet(sivKey, detPlaintext, detContext)
		fmt.Printf("Deterministic: ct1==ct2: %v\n", hex.EncodeToString(ct) == hex.EncodeToString(ct2))
	}
}
