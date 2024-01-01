package awskms

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type testAliases struct {
	ECSignVerify      string
	RSASignVerify     string
	RSAEncryptDecrypt string
}

func testKMSClient(t *testing.T) (*kms.Client, testAliases) {
	t.Helper()

	if os.Getenv("TEST_KMS") == "" && os.Getenv("TEST_LOCAL_KMS") == "" {
		t.Skip("TEST_KMS or TEST_LOCAL_KMS not set, skipping")
	}

	aliases := testAliases{
		ECSignVerify:      os.Getenv("TEST_KMS_ALIAS_EC_SIGN_VERIFY"),
		RSASignVerify:     os.Getenv("TEST_KMS_ALIAS_RSA_SIGN_VERIFY"),
		RSAEncryptDecrypt: os.Getenv("TEST_KMS_ALIAS_RSA_ENCRYPT_DECRYPT"),
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

		aliases.ECSignVerify = "alias/ec_sign_verify"
		aliases.RSASignVerify = "alias/rsa_sign_verify"
		aliases.RSAEncryptDecrypt = "alias/rsa_encrypt_decrypt"
	}

	kmsClient := kms.NewFromConfig(awscfg, kmsOpts...)

	return kmsClient, aliases
}
