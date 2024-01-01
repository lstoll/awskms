package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var _ KMSClient = (*kms.Client)(nil)

type KMSClient interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

func parsePublicKey(publicKey []byte) (crypto.PublicKey, error) {
	pubk, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	switch pubk.(type) {
	case *rsa.PublicKey:
		return pubk, nil
	case *ecdsa.PublicKey:
		return pubk, nil
	default:
		return nil, fmt.Errorf("public key is of unhandled type: %T", pubk)
	}
}
