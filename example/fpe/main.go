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

// Package main demonstrates format-preserving encryption (Family 8).
//
// Usage:
//
//	go run example/fpe/main.go
package main

import (
	"fmt"
	"log"

	"github.com/moeghifar/krypton/lib/config"
	"github.com/moeghifar/krypton/pkg/fpe"
)

func main() {
	if err := config.Init(config.ModeStandard, false); err != nil {
		log.Fatal(err)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	tweak := []byte("test-tweak")

	// FF1 — numeric alphabet (e.g., credit card numbers, NIK)
	fmt.Println("=== Family 8: fpe_encrypt / fpe_decrypt (FF1) ===")
	plaintext := "12345678901234567890"
	ct, err := fpe.FPEEncrypt(key, plaintext, tweak, "numeric", "FF1")
	if err != nil {
		log.Printf("FF1 encrypt error: %v", err)
	} else {
		pt, err := fpe.FPEDecrypt(key, ct, tweak, "numeric", "FF1")
		if err != nil {
			log.Printf("FF1 decrypt error: %v", err)
		} else {
			fmt.Printf("Numeric:  %s -> %s -> %s (match=%v)\n", plaintext, ct, pt, pt == plaintext)
		}
	}

	// FF1 — custom alphabet (e.g., uppercase letters)
	alphaFace := "FACE"
	ct2, err := fpe.FPEEncrypt(key, alphaFace, tweak, "custom:ABCDEFGHIJKLMNOPQRSTUVWXYZ", "FF1")
	if err != nil {
		log.Printf("FF1 custom encrypt error: %v", err)
	} else {
		pt2, err := fpe.FPEDecrypt(key, ct2, tweak, "custom:ABCDEFGHIJKLMNOPQRSTUVWXYZ", "FF1")
		if err != nil {
			log.Printf("FF1 custom decrypt error: %v", err)
		} else {
			fmt.Printf("Custom:   %s -> %s -> %s (match=%v)\n", alphaFace, ct2, pt2, pt2 == alphaFace)
		}
	}
}
