package awskms

import (
	"context"
	"crypto"
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
	signingKeyID string
)

func init() {
	flag.StringVar(&signingKeyID, "signing-key-id", "", "KMS key ID to run tests against (RSA)")
}

func TestSignerE2E(t *testing.T) {
	if signingKeyID == "" {
		t.Skip("-signing-key-id flag not set")
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	sess := session.Must(session.NewSession())
	kmscli := kms.New(sess)

	s, err := NewSigner(ctx, kmscli, signingKeyID)
	if err != nil {
		t.Fatalf("failed to set up signer: %v", err)
	}

	message := []byte(`hello this is a message`)
	hash := sha256.Sum256(message)

	t.Log("PKCS1 v1.5")

	sig, err := s.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("error signing message: %v", err)
	}

	rsaPub, ok := s.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not RSA key, it is a %T", s.Public())
	}

	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sig); err != nil {
		t.Fatalf("error verifying message with public key: %v", err)
	}

	t.Log("PSS")

	pssOpts := &rsa.PSSOptions{Hash: crypto.SHA256}

	sig, err = s.Sign(rand.Reader, hash[:], pssOpts)
	if err != nil {
		t.Fatalf("error signing message: %v", err)
	}

	rsaPub, ok = s.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not RSA key, it is a %T", s.Public())
	}

	if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, hash[:], sig, pssOpts); err != nil {
		t.Fatalf("error verifying message with public key: %v", err)
	}
}
