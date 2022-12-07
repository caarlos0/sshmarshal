// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sshmarshal

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/caarlos0/sshmarshal/internal/bcrypt_pbkdf"
	. "golang.org/x/crypto/ssh"
)

// MarshalPrivateKey returns a PEM block with the private key serialized in the
// OpenSSH format.
func MarshalPrivateKey(key crypto.PrivateKey, comment string) (*pem.Block, error) {
	return marshalOpenSSHPrivateKey(key, comment, unencryptedOpenSSHMarshaler)
}

// MarshalPrivateKeyWithPassphrase returns a PEM block holding the encrypted
// private key serialized in the OpenSSH format.
func MarshalPrivateKeyWithPassphrase(key crypto.PrivateKey, comment string, passphrase []byte) (*pem.Block, error) {
	return marshalOpenSSHPrivateKey(key, comment, passphraseProtectedOpenSSHMarshaler(passphrase))
}

func unencryptedOpenSSHMarshaler(privKeyBlock []byte) ([]byte, string, string, string, error) {
	key := generateOpenSSHPadding(privKeyBlock, 8)
	return key, "none", "none", "", nil
}

func passphraseProtectedOpenSSHMarshaler(passphrase []byte) openSSHEncryptFunc {
	return func(privKeyBlock []byte) ([]byte, string, string, string, error) {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, "", "", "", err
		}

		opts := struct {
			Salt   []byte
			Rounds uint32
		}{salt, 16}

		// Derive key to encrypt the private key block.
		k, err := bcrypt_pbkdf.Key(passphrase, salt, int(opts.Rounds), 32+aes.BlockSize)
		if err != nil {
			return nil, "", "", "", err
		}

		// Add padding matching the block size of AES.
		keyBlock := generateOpenSSHPadding(privKeyBlock, aes.BlockSize)

		// Encrypt the private key using the derived secret.

		dst := make([]byte, len(keyBlock))
		key, iv := k[:32], k[32:]
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, "", "", "", err
		}

		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(dst, keyBlock)

		return dst, "aes256-ctr", "bcrypt", string(Marshal(opts)), nil
	}
}

const privateKeyAuthMagic = "openssh-key-v1\x00"

type openSSHEncryptFunc func(privKeyBlock []byte) (protectedKeyBlock []byte, cipherName, kdfName, kdfOptions string, err error)

type openSSHEncryptedPrivateKey struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
}

type openSSHPrivateKey struct {
	Check1  uint32
	Check2  uint32
	Keytype string
	Rest    []byte `ssh:"rest"`
}

type openSSHRSAPrivateKey struct {
	N       *big.Int
	E       *big.Int
	D       *big.Int
	Iqmp    *big.Int
	P       *big.Int
	Q       *big.Int
	Comment string
	Pad     []byte `ssh:"rest"`
}

type openSSHEd25519PrivateKey struct {
	Pub     []byte
	Priv    []byte
	Comment string
	Pad     []byte `ssh:"rest"`
}

type openSSHECDSAPrivateKey struct {
	Curve   string
	Pub     []byte
	D       *big.Int
	Comment string
	Pad     []byte `ssh:"rest"`
}

func marshalOpenSSHPrivateKey(key crypto.PrivateKey, comment string, encrypt openSSHEncryptFunc) (*pem.Block, error) {
	var w openSSHEncryptedPrivateKey
	var pk1 openSSHPrivateKey

	// Random check bytes.
	var check uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &check); err != nil {
		return nil, err
	}

	pk1.Check1 = check
	pk1.Check2 = check
	w.NumKeys = 1

	// Use a []byte directly on ed25519 keys.
	if k, ok := key.(*ed25519.PrivateKey); ok {
		key = *k
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		E := new(big.Int).SetInt64(int64(k.PublicKey.E))
		// Marshal public key:
		// E and N are in reversed order in the public and private key.
		pubKey := struct {
			KeyType string
			E       *big.Int
			N       *big.Int
		}{
			KeyAlgoRSA,
			E, k.PublicKey.N,
		}
		w.PubKey = Marshal(pubKey)

		// Marshal private key.
		key := openSSHRSAPrivateKey{
			N:       k.PublicKey.N,
			E:       E,
			D:       k.D,
			Iqmp:    k.Precomputed.Qinv,
			P:       k.Primes[0],
			Q:       k.Primes[1],
			Comment: comment,
		}
		pk1.Keytype = KeyAlgoRSA
		pk1.Rest = Marshal(key)
	case ed25519.PrivateKey:
		pub := make([]byte, ed25519.PublicKeySize)
		priv := make([]byte, ed25519.PrivateKeySize)
		copy(pub, k[32:])
		copy(priv, k)

		// Marshal public key.
		pubKey := struct {
			KeyType string
			Pub     []byte
		}{
			KeyAlgoED25519, pub,
		}
		w.PubKey = Marshal(pubKey)

		// Marshal private key.
		key := openSSHEd25519PrivateKey{
			Pub:     pub,
			Priv:    priv,
			Comment: comment,
		}
		pk1.Keytype = KeyAlgoED25519
		pk1.Rest = Marshal(key)
	case *ecdsa.PrivateKey:
		var curve, keyType string
		switch name := k.Curve.Params().Name; name {
		case "P-256":
			curve = "nistp256"
			keyType = KeyAlgoECDSA256
		case "P-384":
			curve = "nistp384"
			keyType = KeyAlgoECDSA384
		case "P-521":
			curve = "nistp521"
			keyType = KeyAlgoECDSA521
		default:
			return nil, errors.New("ssh: unhandled elliptic curve " + name)
		}

		pub := elliptic.Marshal(k.Curve, k.PublicKey.X, k.PublicKey.Y)

		// Marshal public key.
		pubKey := struct {
			KeyType string
			Curve   string
			Pub     []byte
		}{
			keyType, curve, pub,
		}
		w.PubKey = Marshal(pubKey)

		// Marshal private key.
		key := openSSHECDSAPrivateKey{
			Curve:   curve,
			Pub:     pub,
			D:       k.D,
			Comment: comment,
		}
		pk1.Keytype = keyType
		pk1.Rest = Marshal(key)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}

	var err error
	// Add padding and encrypt the key if necessary.
	w.PrivKeyBlock, w.CipherName, w.KdfName, w.KdfOpts, err = encrypt(Marshal(pk1))
	if err != nil {
		return nil, err
	}

	b := Marshal(w)
	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: append([]byte(privateKeyAuthMagic), b...),
	}
	return block, nil
}

func generateOpenSSHPadding(block []byte, blockSize int) []byte {
	for i, l := 0, len(block); (l+i)%blockSize != 0; i++ {
		block = append(block, byte(i+1))
	}
	return block
}
