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

// Package main demonstrates MAC computation (Family 3 and Family 4).
//
// Usage:
//
//	go run example/mac/main.go
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/moeghifar/krypton/lib/config"
	"github.com/moeghifar/krypton/pkg/mac"
)

func main() {
	if err := config.Init(config.ModeStandard, false); err != nil {
		log.Fatal(err)
	}

	key := []byte("super-secret-key-32bytes-long!!")
	data := []byte("Hello, World!")

	// Family 3: mac / mac_verify
	fmt.Println("=== Family 3: mac / mac_verify ===")
	for _, algo := range []string{"HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512", "AES-CMAC"} {
		tag, err := mac.Mac(key, data, algo)
		if err != nil {
			log.Printf("%s error: %v", algo, err)
			continue
		}
		valid, _ := mac.MacVerify(key, data, tag, algo)
		fmt.Printf("%-12s: tag=%s valid=%v\n", algo, hex.EncodeToString(tag)[:16]+"...", valid)
	}

	// Family 4: mac_iv / mac_iv_verify (AES-GMAC)
	fmt.Println("\n=== Family 4: mac_iv / mac_iv_verify (AES-GMAC) ===")
	gcmKey := make([]byte, 32)
	copy(gcmKey, key)
	tag, nonce, err := mac.MacIV(gcmKey, data, "AES-GMAC")
	if err != nil {
		log.Printf("AES-GMAC error: %v", err)
	} else {
		valid, _ := mac.MacIVVerify(gcmKey, data, nonce, tag, "AES-GMAC")
		fmt.Printf("AES-GMAC: tag=%s nonce=%s valid=%v\n",
			hex.EncodeToString(tag)[:16]+"...", hex.EncodeToString(nonce), valid)
	}
}
