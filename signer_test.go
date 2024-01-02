package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
	"time"
)

func TestSignerRSA(t *testing.T) {
	client, aliases := testKMSClient(t)

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	signer, err := NewSigner(ctx, client, aliases.RSASignVerify)
	if err != nil {
		t.Fatalf("failed to set up signer: %v", err)
	}

	pubKey, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not RSA key, it is a %T", signer.Public())
	}

	message := []byte(`hello this is a message`)
	hash := sha256.Sum256(message)

	for _, tc := range []struct {
		Name    string
		Options crypto.SignerOpts
		Verify  func(pub *rsa.PublicKey, sig []byte) error
	}{
		{
			Name:    "RSA PKCS1 v1.5, unwrapped options",
			Options: crypto.SHA256,
			Verify: func(pub *rsa.PublicKey, sig []byte) error {
				return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig)
			},
		},
		{
			Name: "RSA PKCS1 v1.5, wrapped options",
			Options: &SignerOpts{
				Context: ctx,
				Options: crypto.SHA256,
			},
			Verify: func(pub *rsa.PublicKey, sig []byte) error {
				return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig)
			},
		},
		{
			Name: "RSA PSS, unwrapped options",
			Options: &rsa.PSSOptions{
				Hash: crypto.SHA256,
			},
			Verify: func(pub *rsa.PublicKey, sig []byte) error {
				return rsa.VerifyPSS(pub, crypto.SHA256, hash[:], sig, &rsa.PSSOptions{
					Hash: crypto.SHA256,
				})
			},
		},
		{
			Name: "RSA PSS, wrapped options",
			Options: &SignerOpts{
				Context: ctx,
				Options: &rsa.PSSOptions{
					Hash: crypto.SHA256,
				},
			},
			Verify: func(pub *rsa.PublicKey, sig []byte) error {
				return rsa.VerifyPSS(pub, crypto.SHA256, hash[:], sig, &rsa.PSSOptions{
					Hash: crypto.SHA256,
				})
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			sig, err := signer.Sign(rand.Reader, hash[:], tc.Options)
			if err != nil {
				t.Fatalf("error signing message: %v", err)
			}

			if err := tc.Verify(pubKey, sig); err != nil {
				t.Fatalf("error verifying message with public key: %v", err)

			}
		})
	}
}

func TestSignerECDSA(t *testing.T) {
	client, aliases := testKMSClient(t)

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	signer, err := NewSigner(ctx, client, aliases.ECSignVerify)
	if err != nil {
		t.Fatalf("failed to set up signer: %v", err)
	}

	pubKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not ECDSA key, it is a %T", signer.Public())
	}

	message := []byte(`hello this is a message`)
	hash := sha256.Sum256(message)

	for _, tc := range []struct {
		Name    string
		Options crypto.SignerOpts
	}{
		{
			Name:    "ECDSA",
			Options: crypto.SHA256,
		},
		{
			Name: "ECDSA, wrapped options",
			Options: &SignerOpts{
				Context: ctx,
				Options: crypto.SHA256,
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			sig, err := signer.Sign(rand.Reader, hash[:], tc.Options)
			if err != nil {
				t.Fatalf("error signing message: %v", err)
			}

			valid := ecdsa.VerifyASN1(pubKey, hash[:], sig)
			if !valid {
				t.Fatal("signature is not valid")
			}
		})
	}
}

func TestExtractKeyID(t *testing.T) {
	arn := "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

	keyID, err := extractKeyID(arn)
	if err != nil {
		t.Fatalf("error extracting key ID: %v", err)
	}

	if got, want := keyID, "1234abcd-12ab-34cd-56ef-1234567890ab"; got != want {
		t.Fatalf("got: %s, want: %s", got, want)
	}
}
