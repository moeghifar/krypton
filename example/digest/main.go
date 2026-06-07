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

// Package main demonstrates hash digest usage (Family 1 and Family 2).
//
// Usage:
//
//	go run example/digest/main.go
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/moeghifar/krypton/lib/config"
	"github.com/moeghifar/krypton/pkg/hash"
)

func main() {
	if err := config.Init(config.ModeStandard, false); err != nil {
		log.Fatal(err)
	}

	data := []byte("Hello, World!")

	// Family 1: digest — fixed-output hash functions
	fmt.Println("=== Family 1: digest ===")
	for _, algo := range []string{"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"} {
		digest, err := hash.Digest(data, algo)
		if err != nil {
			log.Printf("%s error: %v", algo, err)
			continue
		}
		fmt.Printf("%-12s: %s\n", algo, hex.EncodeToString(digest))
	}

	// Family 2: digest_xof — extendable-output functions
	fmt.Println("\n=== Family 2: digest_xof ===")
	for _, algo := range []string{"SHAKE128", "SHAKE256"} {
		xof, err := hash.DigestXOF(data, algo, 32)
		if err != nil {
			log.Printf("%s error: %v", algo, err)
			continue
		}
		fmt.Printf("%-12s: %s\n", algo, hex.EncodeToString(xof))
	}

	// Verify determinism
	d1, _ := hash.Digest(data, "SHA-256")
	d2, _ := hash.Digest(data, "SHA-256")
	fmt.Printf("\nDeterminism check: %v\n", hash.ConstantTimeCompare(d1, d2))
}
