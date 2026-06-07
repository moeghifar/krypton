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

// Package main demonstrates digital signatures (Family 12 and Family 13).
//
// Usage:
//
//	go run example/sign/main.go
package main

import (
	"fmt"
	"log"

	"github.com/moeghifar/krypton/lib/config"
	"github.com/moeghifar/krypton/pkg/sig"
	"github.com/moeghifar/krypton/lib/types"
)

func main() {
	if err := config.Init(config.ModeStandard, false); err != nil {
		log.Fatal(err)
	}

	message := []byte("Hello, World! This message will be signed.")

	// Family 12: keygen — generate key pairs
	// Family 13: sign / verify — digital signatures
	fmt.Println("=== Families 12 & 13: keygen / sign / verify ===")
	for _, algo := range []string{"Ed25519", "ECDSA-P256", "ECDSA-P384", "RSA-PSS-3072"} {
		kp, err := sig.KeyGen(algo, types.KeyFormatPEM)
		if err != nil {
			log.Printf("%s keygen error: %v", algo, err)
			continue
		}
		signature, err := sig.Sign(kp.PrivateKey, message, algo, types.KeyFormatPEM)
		if err != nil {
			log.Printf("%s sign error: %v", algo, err)
			continue
		}
		valid, err := sig.Verify(kp.PublicKey, message, signature, algo, types.KeyFormatPEM)
		if err != nil {
			log.Printf("%s verify error: %v", algo, err)
			continue
		}
		fmt.Printf("%-16s: sig_len=%d valid=%v key_id=%s\n", algo, len(signature), valid, kp.KeyID)
	}
}
