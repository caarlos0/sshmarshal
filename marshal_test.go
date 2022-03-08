// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sshmarshal

import (
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"

	"github.com/caarlos0/sshmarshal/testdata"
	. "golang.org/x/crypto/ssh"
)

var testPrivateKeys map[string]interface{}

func init() {
	n := len(testdata.PEMBytes)
	testPrivateKeys = make(map[string]interface{}, n)

	for t, k := range testdata.PEMBytes {
		var err error
		testPrivateKeys[t], err = ParseRawPrivateKey(k)
		if err != nil {
			panic(fmt.Sprintf("Unable to parse test key %s: %v", t, err))
		}
	}
}

func TestMarshalPrivateKey(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"rsa-openssh-format"},
		{"ed25519"},
		{"p256-openssh-format"},
		{"p384-openssh-format"},
		{"p521-openssh-format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected, ok := testPrivateKeys[tt.name]
			if !ok {
				t.Fatalf("cannot find key %s", tt.name)
			}

			block, err := MarshalPrivateKey(expected, "test@golang.org")
			if err != nil {
				t.Fatalf("cannot marshal %s: %v", tt.name, err)
			}

			key, err := ParseRawPrivateKey(pem.EncodeToMemory(block))
			if err != nil {
				t.Fatalf("cannot parse %s: %v", tt.name, err)
			}

			if !reflect.DeepEqual(expected, key) {
				t.Errorf("unexpected marshaled key %s", tt.name)
			}
		})
	}
}

func TestMarshalPrivateKeyWithPassphrase(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"rsa-openssh-format"},
		{"ed25519"},
		{"p256-openssh-format"},
		{"p384-openssh-format"},
		{"p521-openssh-format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected, ok := testPrivateKeys[tt.name]
			if !ok {
				t.Fatalf("cannot find key %s", tt.name)
			}

			block, err := MarshalPrivateKeyWithPassphrase(expected, "test@golang.org", []byte("test-passphrase"))
			if err != nil {
				t.Fatalf("cannot marshal %s: %v", tt.name, err)
			}

			key, err := ParseRawPrivateKeyWithPassphrase(pem.EncodeToMemory(block), []byte("test-passphrase"))
			if err != nil {
				t.Fatalf("cannot parse %s: %v", tt.name, err)
			}

			if !reflect.DeepEqual(expected, key) {
				t.Errorf("unexpected marshaled key %s", tt.name)
			}
		})
	}
}
