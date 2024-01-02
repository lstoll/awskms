package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"

	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var _ KMSClient = (*kms.Client)(nil)

// KMSClient describes the KMS operations this module requires, this will
// normally be satisfied by the aws-sdk-go-v2 *kms.Client
type KMSClient interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// KeyInfo contains information about the underlying KMS key.
type KeyInfo struct {
	// ID contains the ID of the key.
	ID string
	// ARN contains the AWS Resource Name for the KMS key
	ARN string
	// Alias contains the key alias that was used to retrieve the key, if it was
	// retrieve by an alias. Otherwise, it will be empty. The alias/ prefix is
	// stripped.
	Alias string
}

// parsePubKeyResp loads the public key and the KeyInfo from the response
func parsePubKeyResp(reqID string, resp *kms.GetPublicKeyOutput) (crypto.PublicKey, KeyInfo, error) {
	pub, err := parsePublicKey(resp.PublicKey)
	if err != nil {
		return nil, KeyInfo{}, err
	}

	// this KeyId field is always the ARN. Naming in KMS is fun.
	targetKeyID, err := extractKeyID(*resp.KeyId)
	if err != nil {
		return nil, KeyInfo{}, err
	}

	var alias string
	if strings.HasPrefix(reqID, "alias/") {
		alias = strings.TrimPrefix(reqID, "alias/")
	}

	return pub, KeyInfo{
		ARN:   *resp.KeyId,
		ID:    targetKeyID,
		Alias: alias,
	}, err
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

func extractKeyID(arn string) (string, error) {
	parn, err := awsarn.Parse(arn)
	if err != nil {
		return "", fmt.Errorf("parsing arn %s: %w", arn, err)
	}
	arnSegments := strings.Split(arn, ":")
	if len(arnSegments) != 6 {
		return "", fmt.Errorf("unexpected number of ARN segments: %s", arn)
	}

	targetKeyID := parn.Resource
	if !strings.HasPrefix(targetKeyID, "key/") {
		return "", fmt.Errorf("unexpected key ID format: %s", targetKeyID)
	}

	return strings.TrimPrefix(targetKeyID, "key/"), nil
}
