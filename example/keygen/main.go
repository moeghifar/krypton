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

// Package main demonstrates key pair generation (Family 12).
//
// Usage:
//
//	go run example/keygen/main.go
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

	fmt.Println("=== Family 12: keygen ===")
	for _, algo := range []string{"Ed25519", "ECDSA-P256", "ECDSA-P384", "RSA-PSS-3072", "RSA-PSS-4096"} {
		kp, err := sig.KeyGen(algo, types.KeyFormatPEM)
		if err != nil {
			log.Printf("%s keygen error: %v", algo, err)
			continue
		}
		pubLen := len(kp.PublicKey)
		privLen := len(kp.PrivateKey)
		fmt.Printf("%-16s: pub=%d priv=%d key_id=%s created=%s\n",
			algo, pubLen, privLen, kp.KeyID, kp.CreatedAt)
	}
}
