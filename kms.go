package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

func getPublicKey(ctx context.Context, kmssvc kmsiface.KMSAPI, keyID string) (crypto.PublicKey, error) {
	pkresp, err := kmssvc.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key for %s: %w", keyID, err)
	}

	pubk, err := x509.ParsePKIXPublicKey(pkresp.PublicKey)
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
