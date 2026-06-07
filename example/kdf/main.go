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

// Package main demonstrates key derivation (Family 9 and Family 10).
//
// Usage:
//
//	go run example/kdf/main.go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/moeghifar/krypton/lib/config"
	"github.com/moeghifar/krypton/pkg/kdf"
	// kdf.PasswordParams is defined in the kdf package
)

func main() {
	if err := config.Init(config.ModeStandard, false); err != nil {
		log.Fatal(err)
	}

	// Family 9: kdf — high-entropy key derivation
	fmt.Println("=== Family 9: kdf (high-entropy input) ===")
	ikm := make([]byte, 32)
	rand.Read(ikm)
	salt := make([]byte, 32)
	rand.Read(salt)
	info := []byte("key-derivation-context")

	for _, algo := range []string{"HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512", "SP800-108-CTR", "ANSI-X9.63"} {
		derived, err := kdf.KDF(ikm, salt, info, 32, algo)
		if err != nil {
			log.Printf("%s error: %v", algo, err)
			continue
		}
		fmt.Printf("%-16s: derived=%s\n", algo, hex.EncodeToString(derived)[:32]+"...")
	}

	// Family 10: kdf_password — password-based key derivation
	fmt.Println("\n=== Family 10: kdf_password (low-entropy input) ===")
	password := "my-secure-password"
	salt10 := make([]byte, 32)
	rand.Read(salt10)

	// PBKDF2
	params := kdf.PasswordParams{Iterations: 600000, Length: 32}
	derived, err := kdf.KDFPassword(password, salt10, params, "PBKDF2-SHA256")
	if err != nil {
		log.Printf("PBKDF2 error: %v", err)
	} else {
		fmt.Printf("%-16s: derived=%s\n", "PBKDF2-SHA256", hex.EncodeToString(derived)[:32]+"...")
	}

	// Argon2id
	argonParams := kdf.PasswordParams{MemoryKB: 65536, Iterations: 2, Parallelism: 1, Length: 32}
	derived, err = kdf.KDFPassword(password, salt10, argonParams, "Argon2id")
	if err != nil {
		log.Printf("Argon2id error: %v", err)
	} else {
		fmt.Printf("%-16s: derived=%s\n", "Argon2id", hex.EncodeToString(derived)[:32]+"...")
	}
}
