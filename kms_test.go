package awskms

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type testKeys struct {
	ECSignVerifyAlias      string
	RSASignVerifyAlias     string
	RSAEncryptDecryptAlias string

	// these are only wired up for local-kms usage
	ECSignVerifyARN      string
	RSASignVerifyARN     string
	RSAEncryptDecryptARN string
}

func testKMSClient(t *testing.T) (*kms.Client, testKeys) {
	t.Helper()

	if os.Getenv("TEST_KMS") == "" && os.Getenv("TEST_LOCAL_KMS") == "" {
		t.Skip("TEST_KMS or TEST_LOCAL_KMS not set, skipping")
	}

	keys := testKeys{
		ECSignVerifyAlias:      os.Getenv("TEST_KMS_ALIAS_EC_SIGN_VERIFY"),
		RSASignVerifyAlias:     os.Getenv("TEST_KMS_ALIAS_RSA_SIGN_VERIFY"),
		RSAEncryptDecryptAlias: os.Getenv("TEST_KMS_ALIAS_RSA_ENCRYPT_DECRYPT"),
	}

	kmsOpts := []func(*kms.Options){}
	awscfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		t.Fatalf("loading default aws config: %v", err)
	}

	if os.Getenv("TEST_LOCAL_KMS") != "" {
		kmsAddr := "http://localhost:8087" // run-local-kms/github actions default
		if addr := os.Getenv("TEST_LOCAL_KMS_ADDR"); addr != "" {
			kmsAddr = addr
		}
		kmsOpts = append(kmsOpts, func(o *kms.Options) {
			o.BaseEndpoint = &kmsAddr
		})

		awscfg.Region = "us-east-2"
		awscfg.Credentials = credentials.NewStaticCredentialsProvider("AKIA11111111", "2222222222222", "")

		keys.ECSignVerifyAlias = "alias/ec_sign_verify"
		keys.RSASignVerifyAlias = "alias/rsa_sign_verify"
		keys.RSAEncryptDecryptAlias = "alias/rsa_encrypt_decrypt"

		keys.ECSignVerifyARN = "arn:aws:kms:eu-west-2:111122223333:key/3aa0759e-169c-4de4-bb74-38b02b319e9d"
		keys.RSASignVerifyARN = "arn:aws:kms:eu-west-2:111122223333:key/cd7b6e4a-154a-4fb8-b013-63bb43c48cd8"
		keys.RSAEncryptDecryptARN = "arn:aws:kms:eu-west-2:111122223333:key/a1d398f5-2b1c-40d5-82f4-bb97696d6975"
	}

	kmsClient := kms.NewFromConfig(awscfg, kmsOpts...)

	return kmsClient, keys
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
