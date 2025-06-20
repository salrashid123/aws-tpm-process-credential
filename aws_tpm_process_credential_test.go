package awstpmcredential

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/stretchr/testify/require"
)

var ()

func loadKey(rwr transport.TPM, persistentHandle uint, keyFilePath string) (tpm2.TPMHandle, tpm2.TPM2BName, func(), error) {

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	awsSecret := os.Getenv("AWS_SECRET_ACCESS_KEY")

	hmacSensitive := []byte("AWS4" + awsSecret)

	sv := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, sv)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	privHash := crypto.SHA256.New()
	_, err = privHash.Write(sv)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	_, err = privHash.Write(hmacSensitive)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	hmacTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
						&tpm2.TPMSSchemeHMAC{
							HashAlg: tpm2.TPMAlgSHA256,
						}),
				},
			}),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BDigest{
				Buffer: privHash.Sum(nil),
			},
		),
	}

	sens2B := tpm2.Marshal(tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgKeyedHash,
		SeedValue: tpm2.TPM2BDigest{
			Buffer: sv,
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BSensitiveData{Buffer: hmacSensitive},
		),
	})

	l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	importResponse, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectPublic: tpm2.New2B(hmacTemplate),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	hmacKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  tpm2.New2B(hmacTemplate),
		InPrivate: importResponse.OutPrivate,
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: primaryKey.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: hmacKey.ObjectHandle,
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	closer := func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hmacKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}

	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: hmacKey.ObjectHandle,
			Name:   pub.Name,
		},
		PersistentHandle: tpm2.TPMHandle(persistentHandle),
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	tkf := &keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		EmptyAuth: true,
		Parent:    primaryKey.ObjectHandle,
		Pubkey:    tpm2.New2B(hmacTemplate),
		Privkey:   importResponse.OutPrivate,
	}
	b := new(bytes.Buffer)
	err = keyfile.Encode(b, tkf)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	err = os.WriteFile(keyFilePath, b.Bytes(), 0644)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	return hmacKey.ObjectHandle, pub.Name, closer, nil
}
func TestPersistentHandleCredentials(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008001
	_, _, closer, err := loadKey(rwr, uint(persistentHandle), filePath)
	require.NoError(t, err)
	defer closer()

	awsKey := os.Getenv("AWS_ACCESS_KEY_ID")
	testAccountArn := os.Getenv("AWS_ACCOUNT_ARN")
	awsRegion := os.Getenv("AWS_DEFAULT_REGION")
	awsSessionName := os.Getenv("AWS_ROLE_SESSION_NAME")
	awsRoleARN := os.Getenv("AWS_ROLE_ARN")

	resp, err := NewAWSTPMCredential(&AWSTPMConfig{
		TPMCloser:        tpmDevice,
		PersistentHandle: uint(persistentHandle),
		Duration:         3600,
		AWSAccessKeyID:   awsKey,
		AWSRoleArn:       awsRoleARN,
		AWSRegion:        awsRegion,
		AWSSessionName:   awsSessionName,
	})
	require.NoError(t, err)

	t.Setenv("AWS_ACCESS_KEY_ID", resp.AccessKeyId)
	t.Setenv("AWS_SECRET_ACCESS_KEY", resp.SecretAccessKey)
	t.Setenv("AWS_SESSION_TOKEN", resp.SessionToken)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	require.NoError(t, err)

	stssvc := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.Region = awsRegion
	})

	stsresp, err := stssvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	require.NoError(t, err)

	require.Equal(t, testAccountArn, aws.ToString(stsresp.Arn))
}

func TestKeyFileCredentials(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008001
	_, _, closer, err := loadKey(rwr, uint(persistentHandle), filePath)
	require.NoError(t, err)
	defer closer()

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	closer()

	_, err = tpm2.FlushContext{
		FlushHandle: primaryKey.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	awsKey := os.Getenv("AWS_ACCESS_KEY_ID")
	testAccountArn := os.Getenv("AWS_ACCOUNT_ARN")
	awsRegion := os.Getenv("AWS_DEFAULT_REGION")
	awsSessionName := os.Getenv("AWS_ROLE_SESSION_NAME")
	awsRoleARN := os.Getenv("AWS_ROLE_ARN")

	resp, err := NewAWSTPMCredential(&AWSTPMConfig{
		TPMCloser:      tpmDevice,
		CredentialFile: filePath,
		Duration:       3600,
		AWSAccessKeyID: awsKey,
		AWSRoleArn:     awsRoleARN,
		AWSRegion:      awsRegion,
		AWSSessionName: awsSessionName,
	})
	require.NoError(t, err)

	t.Setenv("AWS_ACCESS_KEY_ID", resp.AccessKeyId)
	t.Setenv("AWS_SECRET_ACCESS_KEY", resp.SecretAccessKey)
	t.Setenv("AWS_SESSION_TOKEN", resp.SessionToken)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	require.NoError(t, err)

	stssvc := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.Region = awsRegion
	})

	stsresp, err := stssvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	require.NoError(t, err)

	require.Equal(t, testAccountArn, aws.ToString(stsresp.Arn))
}

func TestToken(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008001
	_, _, closer, err := loadKey(rwr, uint(persistentHandle), filePath)
	require.NoError(t, err)
	defer closer()

	awsKey := os.Getenv("AWS_ACCESS_KEY_ID")
	testAccountArn := os.Getenv("AWS_ACCOUNT_ARN")
	awsRegion := os.Getenv("AWS_DEFAULT_REGION")
	awsSessionName := os.Getenv("AWS_ROLE_SESSION_NAME")
	awsRoleARN := os.Getenv("AWS_ROLE_ARN")

	resp, err := NewAWSTPMCredential(&AWSTPMConfig{
		TPMCloser:        tpmDevice,
		PersistentHandle: uint(persistentHandle),
		Duration:         3600,
		AWSAccessKeyID:   awsKey,
		AWSRoleArn:       awsRoleARN,
		AWSRegion:        awsRegion,
		AWSSessionName:   awsSessionName,
		AssumeRole:       false,
	})
	require.NoError(t, err)

	t.Setenv("AWS_ACCESS_KEY_ID", resp.AccessKeyId)
	t.Setenv("AWS_SECRET_ACCESS_KEY", resp.SecretAccessKey)
	t.Setenv("AWS_SESSION_TOKEN", resp.SessionToken)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	require.NoError(t, err)

	stssvc := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.Region = awsRegion
	})

	stsresp, err := stssvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	require.NoError(t, err)

	require.Equal(t, testAccountArn, aws.ToString(stsresp.Arn))
}

func TestAssumeRole(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008001
	_, _, closer, err := loadKey(rwr, uint(persistentHandle), filePath)
	require.NoError(t, err)
	defer closer()

	awsKey := os.Getenv("AWS_ACCESS_KEY_ID")
	testAccountArn := os.Getenv("AWS_ROLE_SESSION_ARN")
	awsRegion := os.Getenv("AWS_DEFAULT_REGION")
	awsSessionName := os.Getenv("AWS_ROLE_SESSION_NAME")
	awsRoleARN := os.Getenv("AWS_ROLE_ARN")

	resp, err := NewAWSTPMCredential(&AWSTPMConfig{
		TPMCloser:        tpmDevice,
		PersistentHandle: uint(persistentHandle),
		Duration:         3600,
		AWSAccessKeyID:   awsKey,
		AWSRoleArn:       awsRoleARN,
		AWSRegion:        awsRegion,
		AWSSessionName:   awsSessionName,
		AssumeRole:       true,
	})
	require.NoError(t, err)

	t.Setenv("AWS_ACCESS_KEY_ID", resp.AccessKeyId)
	t.Setenv("AWS_SECRET_ACCESS_KEY", resp.SecretAccessKey)
	t.Setenv("AWS_SESSION_TOKEN", resp.SessionToken)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	require.NoError(t, err)

	stssvc := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.Region = awsRegion
	})

	stsresp, err := stssvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	require.NoError(t, err)

	require.Equal(t, testAccountArn, aws.ToString(stsresp.Arn))
}
