package awskms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
	"testing"
	"time"

	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestDecrypterRSA(t *testing.T) {
	client, aliases := testKMSClient(t)

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	decrypter, err := NewDecrypter(ctx, client, aliases.RSAEncryptDecrypt)
	if err != nil {
		t.Fatalf("error creating decrypter: %v", err)
	}

	pubKey, ok := decrypter.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not RSA key, it is a %T", decrypter.Public())
	}

	message := []byte(`hello this is a message`)

	for _, tc := range []struct {
		Name    string
		Hash    hash.Hash
		Options crypto.DecrypterOpts
	}{
		{
			Name:    "Nil opts",
			Hash:    sha1.New(),
			Options: nil,
		},
		{
			Name: "Options",
			Hash: sha256.New(),
			Options: &DecrypterOpts{
				Context:             ctx,
				EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256,
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			ciphertext, err := rsa.EncryptOAEP(tc.Hash, rand.Reader, pubKey, message, []byte(""))
			if err != nil {
				t.Fatalf("error encrypting message: %v", err)
			}

			plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, tc.Options)
			if err != nil {
				t.Fatalf("failed to decrypt message: %v", err)
			}

			if string(message) != string(plaintext) {
				t.Fatalf("got: %s, want: %s", string(plaintext), string(message))
			}
		})
	}
}
