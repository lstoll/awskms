package awskms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"

	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

var _ crypto.Signer = (*Signer)(nil)

// Signer is a crypto.Signer that uses a AWS KMS backed key. It should be
// initialized via NewSigner
type Signer struct {
	kms         KMSClient
	keyID       string
	targetKeyID string
	public      crypto.PublicKey
	// hashm maps the given crypto.hash to the alg for the KMS side. it will
	// depend on the key type
	hashm map[crypto.Hash]kmstypes.SigningAlgorithmSpec
	// psshashm explicitly maps hashes to their pss type. this is because we
	// offer this as an opt-in for RSA keys
	psshashm map[crypto.Hash]kmstypes.SigningAlgorithmSpec
}

// NewSigner will configure a new Signer using the given KMS client, bound to
// the given key. This requires successful connectivity to the KMS service, to
// retrieve the public key.
func NewSigner(ctx context.Context, kmssvc KMSClient, keyID string) (*Signer, error) {
	pkresp, err := kmssvc.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key for %s: %w", keyID, err)
	}

	if pkresp.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("key usage must be %s, not %s", kmstypes.KeyUsageTypeSignVerify, pkresp.KeyUsage)
	}

	pub, err := parsePublicKey(pkresp.PublicKey)
	if err != nil {
		return nil, err
	}

	targetKeyID, err := extractKeyID(*pkresp.KeyId)
	if err != nil {
		return nil, err
	}

	s := &Signer{
		kms:         kmssvc,
		keyID:       keyID,
		targetKeyID: targetKeyID,
		public:      pub,
	}

	if err := s.setSigningHashes(pkresp.SigningAlgorithms); err != nil {
		return nil, err
	}

	return s, nil
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

// KeyID returns the resource ID of the AWS KMS key.
func (s *Signer) KeyID() string {
	return s.targetKeyID
}

// Public returns the public key corresponding to the opaque,
// private key.
func (s *Signer) Public() crypto.PublicKey {
	return s.public
}

// SignerOpts implements crypto.SignerOpts for this Signer. It can wrap a Base
// set of options, as per the Sign method docs.
type SignerOpts struct {
	// Context to use for remote calls.
	Context context.Context
	// Options to use to select algorithm etc. This can not be nil.
	Options crypto.SignerOpts
}

// HashFunc is unused - we need this to implement crypto.SignerOpts, but we will
// use either the Base's SignerOpts, or treat it like no opts were passed.
func (s *SignerOpts) HashFunc() crypto.Hash {
	panic("should not be called")
}

// Sign signs digest with the private key. By default, for an RSA key a PKCS#1
// v1.5 signature, and for an EC key a DER-serialised, ASN.1 signature structure
// will be returned. If the passed options are a *rsa.PSSOptions, the RSA key
// will return a PSS signature. If a *SignerOpts is passed, the Base options
// will be treated as if they were passed directly.
//
// Hash is required, as must correspond to a hash the KMS service supports.
//
// rand is unused.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	var (
		ctx = context.Background()
		hm  map[crypto.Hash]kmstypes.SigningAlgorithmSpec
	)

	if so, ok := opts.(*SignerOpts); ok {
		if so.Context != nil {
			ctx = so.Context
		}
		if so.Options == nil {
			return nil, fmt.Errorf("the Options field on SignerOpts can not be nil")
		}
		opts = so.Options
	}

	switch opts.(type) {
	case *rsa.PSSOptions:
		if len(s.psshashm) < 1 {
			return nil, fmt.Errorf("key does not support pss")
		}
		hm = s.psshashm
	default:
		hm = s.hashm
	}

	alg, ok := hm[opts.HashFunc()]
	if !ok {
		return nil, fmt.Errorf("hash %v not supported", opts.HashFunc())
	}

	sresp, err := s.kms.Sign(ctx, &kms.SignInput{
		KeyId:            &s.keyID,
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: alg,
		Message:          digest,
	})
	if err != nil {
		return nil, fmt.Errorf("sign operation failed: %w", err)
	}

	return sresp.Signature, nil
}

func (s *Signer) setSigningHashes(algorithms []kmstypes.SigningAlgorithmSpec) error {
	var ecdsa, pss, pkcs15 = make(map[crypto.Hash]kmstypes.SigningAlgorithmSpec), make(map[crypto.Hash]kmstypes.SigningAlgorithmSpec), make(map[crypto.Hash]kmstypes.SigningAlgorithmSpec)

	for _, a := range algorithms {
		switch a {
		case kmstypes.SigningAlgorithmSpecRsassaPssSha256:
			pss[crypto.SHA256] = kmstypes.SigningAlgorithmSpecRsassaPssSha256
		case kmstypes.SigningAlgorithmSpecRsassaPssSha384:
			pss[crypto.SHA384] = kmstypes.SigningAlgorithmSpecRsassaPssSha384
		case kmstypes.SigningAlgorithmSpecRsassaPssSha512:
			pss[crypto.SHA512] = kmstypes.SigningAlgorithmSpecRsassaPssSha512
		case kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
			pkcs15[crypto.SHA256] = kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256
		case kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
			pkcs15[crypto.SHA384] = kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384
		case kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
			pkcs15[crypto.SHA512] = kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512
		case kmstypes.SigningAlgorithmSpecEcdsaSha256:
			ecdsa[crypto.SHA256] = kmstypes.SigningAlgorithmSpecEcdsaSha256
		case kmstypes.SigningAlgorithmSpecEcdsaSha384:
			ecdsa[crypto.SHA384] = kmstypes.SigningAlgorithmSpecEcdsaSha384
		case kmstypes.SigningAlgorithmSpecEcdsaSha512:
			ecdsa[crypto.SHA512] = kmstypes.SigningAlgorithmSpecEcdsaSha512
		}
	}

	// always set the pss hashes, to handle the user explicitly opting in
	s.psshashm = pss

	// set up the defaults
	if len(ecdsa) > 0 {
		s.hashm = ecdsa
		return nil
	}
	if len(pkcs15) > 0 {
		s.hashm = pkcs15
		return nil
	}
	if len(pss) > 0 {
		s.hashm = pss
		return nil
	}

	return fmt.Errorf("no valid signing hashes found for key %s", s.keyID)
}
