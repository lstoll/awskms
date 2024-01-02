package awskms

import (
	"context"
	"crypto"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

var _ crypto.Decrypter = (*Decrypter)(nil)

// Decrypter implents a crypto.Decrypter that uses a RSA key stored in AWS
// It should be initialized via NewDecrypter
type Decrypter struct {
	kms    KMSClient
	keyID  string
	public crypto.PublicKey
}

// NewDecrypter will configure a new decrypter using the given KMS client, bound
// to the given key. This requires successful connectivity to the KMS service, to
// retrieve the public key.
func NewDecrypter(ctx context.Context, kmssvc KMSClient, keyID string) (*Decrypter, error) {
	pkresp, err := kmssvc.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key for %s: %w", keyID, err)
	}

	if pkresp.KeyUsage != kmstypes.KeyUsageTypeEncryptDecrypt {
		return nil, fmt.Errorf("key usage must be %s, not %s", kmstypes.KeyUsageTypeSignVerify, pkresp.KeyUsage)
	}

	pub, err := parsePublicKey(pkresp.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Decrypter{
		kms:    kmssvc,
		keyID:  keyID,
		public: pub,
	}, nil
}

// Public returns the public key corresponding to the opaque,
// private key.
func (d *Decrypter) Public() crypto.PublicKey {
	return d.public
}

// DecrypterOpts implements crypto.DecrypterOpts for this Decrypter
type DecrypterOpts struct {
	// Context sets the context for remote calls.
	Context context.Context
	// EncryptionAlgorithm indicates the encryption algorithm that was used.
	// If not set, defaults to types.EncryptionAlgorithmSpecRsaesOaepSha1
	EncryptionAlgorithm kmstypes.EncryptionAlgorithmSpec
}

// Decrypt decrypts msg. A *DecrypterOpts can be passed to customize the
// algorithm in use. If opts are nil, EncryptionAlgorithmOaepSha256 will be
// used.
func (d *Decrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	var (
		ctx = context.Background()
		alg = kmstypes.EncryptionAlgorithmSpecRsaesOaepSha1
	)

	if do, ok := opts.(*DecrypterOpts); ok {
		if do.Context != nil {
			ctx = do.Context
		}
		if do.EncryptionAlgorithm != "" {
			alg = do.EncryptionAlgorithm
		}
	}

	dresp, err := d.kms.Decrypt(ctx, &kms.DecryptInput{
		KeyId:               &d.keyID,
		CiphertextBlob:      msg,
		EncryptionAlgorithm: alg,
	})
	if err != nil {
		return nil, fmt.Errorf("decrypt operation failed: %w", err)
	}

	return dresp.Plaintext, nil
}
