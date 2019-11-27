package awskms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"flag"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

var (
	decryptionKeyID string
)

func init() {
	flag.StringVar(&decryptionKeyID, "decryption-key-id", "", "KMS key ID to run tests against")
}

func TestDecrypterE2E(t *testing.T) {
	if decryptionKeyID == "" {
		t.Skip("-decryption-key-id not set")
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	sess := session.Must(session.NewSession())
	kmscli := kms.New(sess)

	message := []byte(`this is some message`)

	d, err := NewDecrypter(ctx, kmscli, decryptionKeyID)
	if err != nil {
		t.Fatalf("error creating decrypter: %v", err)
	}

	rsaPub, ok := d.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not RSA, it is: %T", d.Public())
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, message, []byte(""))
	if err != nil {
		t.Fatalf("error encrypting message: %v", err)
	}

	plaintext, err := d.Decrypt(rand.Reader, ciphertext, &DecrypterOpts{})
	if err != nil {
		t.Fatalf("failed to decrypt message: %v", err)
	}

	if string(message) != string(plaintext) {
		t.Fatalf("got: %s, want: %s", string(plaintext), string(message))
	}
}
