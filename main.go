package main

import (
	"context"
	"encoding/json"
	"time"

	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	keyfile "github.com/foxboron/go-tpm-keyfiles"

	"strings"

	"flag"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/uuid"

	hmaccred "github.com/salrashid123/aws_hmac/tpm"
	hmacsigner "github.com/salrashid123/aws_hmac/tpm/signer"
)

const ()

// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
type processCredentialsResponse struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

const (
	RFC3339 = "2006-01-02T15:04:05Z07:00"
)

type credConfig struct {
	flTPMPath          string
	flPersistentHandle uint
	flAWSAccessKeyID   string
	flCredentialFile   string
	flAWSRoleArn       string
	flAWSRegion        string
	flDuration         uint64
	flTimeout          uint
	flAWSSessionName   string
	flAssumeRole       bool
}

var (
	cfg = &credConfig{}

	// // this is the H2 template that is compatible with openssl:
	// printf '\x00\x00' > unique.dat
	// tpm2_createprimary -C o -G ecc \
	//   -g sha256  -c primary.ctx \
	//   -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

	ECCSRK_H2_Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
			},
		),
	}
)

func main() {
	//ctx := context.Background()	flag.Parse	var err error
	flag.StringVar(&cfg.flTPMPath, "tpm-path", "/dev/tpm0", "Path to the TPM Object")
	flag.UintVar(&cfg.flPersistentHandle, "persistentHandle", 0x81008003, "Handle value")
	flag.StringVar(&cfg.flCredentialFile, "credential-file", "", "Encrypted Credential")
	flag.Uint64Var(&cfg.flDuration, "duration", uint64(3600), "Duration value")
	flag.StringVar(&cfg.flAWSRoleArn, "aws-arn", "", "AWS ARN Value")
	flag.StringVar(&cfg.flAWSRegion, "aws-region", "", "AWS Region")
	flag.BoolVar(&cfg.flAssumeRole, "assumeRole", false, "Assume Role")
	flag.StringVar(&cfg.flAWSAccessKeyID, "aws-access-key-id", "", "(required) AWS access key id")
	flag.UintVar(&cfg.flTimeout, "timeout", 2, "(optional) timeout (default 2s)")
	flag.StringVar(&cfg.flAWSSessionName, "aws-session-name", fmt.Sprintf("gcp-%s", uuid.New().String()), "AWS SessionName")

	flag.Parse()

	argError := func(s string, v ...interface{}) {
		//flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Invalid Argument error: "+s, v...)
		os.Exit(1)
	}

	if cfg.flAWSAccessKeyID == "" || cfg.flAWSRegion == "" {
		argError("-aws-access-key-id --aws-region cannot be null")
	}

	if cfg.flAssumeRole && cfg.flAWSSessionName == "" {
		argError("-aws-session-name cannot be null if --flAssumeRole=true")
	}

	if cfg.flPersistentHandle == 0 && cfg.flCredentialFile == "" {
		argError("either -credential-file or persistentHandle")
	}

	rwc, err := tpmutil.OpenTPM(cfg.flTPMPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Can't open TPM %s: %v", cfg.flTPMPath, err)
		os.Exit(1)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			if strings.Contains(err.Error(), "file already closed") {
				os.Exit(0)
			}
			fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Can't close TPM (may already be closed earlier) %s: %v", cfg.flTPMPath, err)
			os.Exit(1)
		}
	}()

	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	var keyHandle tpm2.TPMHandle

	if cfg.flPersistentHandle != 0 {
		keyHandle = tpm2.TPMHandle(cfg.flPersistentHandle)
	} else if cfg.flCredentialFile == "" {

		c, err := os.ReadFile(cfg.flCredentialFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: error reading encrypted credential file %s: %v", cfg.flCredentialFile, err)
			os.Exit(1)
		}
		key, err := keyfile.Decode(c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: error decoding credential file %s: %v", cfg.flCredentialFile, err)
			os.Exit(1)
		}

		// now load the key using the H2 template
		// specify its parent directly
		primaryKey, err := tpm2.CreatePrimary{
			PrimaryHandle: key.Parent,
			InPublic:      tpm2.New2B(ECCSRK_H2_Template),
		}.Execute(rwr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: error creating H2 primary key %v", err)
			os.Exit(1)
		}
		// now the actual key can get loaded from that parent
		hmacKey, err := tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: primaryKey.ObjectHandle,
				Name:   tpm2.TPM2BName(primaryKey.Name),
				Auth:   tpm2.PasswordAuth([]byte("")),
			},
			InPublic:  key.Pubkey,
			InPrivate: key.Privkey,
		}.Execute(rwr)

		if err != nil {
			fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: error loading hmac key %v", err)
			os.Exit(1)
		}
		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: hmacKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()
		keyHandle = hmacKey.ObjectHandle

	} else {
		fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: either -credential-file or persistentHandle")
		os.Exit(1)
	}

	pub, err := tpm2.ReadPublic{
		ObjectHandle: keyHandle,
	}.Execute(rwr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Error creating tpm2.Public TPM %s: %v", cfg.flTPMPath, err)
		os.Exit(1)
	}

	tpmSigner, err := hmacsigner.NewTPMSigner(&hmacsigner.TPMSignerConfig{
		TPMConfig: hmacsigner.TPMConfig{
			TPMDevice: rwc,
			AuthHandle: tpm2.AuthHandle{
				Handle: keyHandle,
				Name:   pub.Name,
				Auth:   tpm2.PasswordAuth(nil),
			},
		},
		AccessKeyID: cfg.flAWSAccessKeyID,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Error creating signer open TPM %s: %v", cfg.flTPMPath, err)
		os.Exit(1)
	}

	var hc *hmaccred.TPMCredentialsProvider

	if cfg.flAssumeRole {
		hc, err = hmaccred.NewAWSTPMCredentials(hmaccred.TPMProvider{
			AssumeRoleInput: &sts.AssumeRoleInput{
				RoleArn:         aws.String(cfg.flAWSRoleArn),
				RoleSessionName: aws.String(cfg.flAWSSessionName),
				DurationSeconds: aws.Int32(int32(cfg.flDuration)),
			},
			Version:   "2011-06-15",
			Region:    cfg.flAWSRegion,
			TPMSigner: tpmSigner,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Could not initialize TPM Credentials %v", err)
			os.Exit(1)
		}
	} else {

		hc, err = hmaccred.NewAWSTPMCredentials(hmaccred.TPMProvider{
			GetSessionTokenInput: &sts.GetSessionTokenInput{
				DurationSeconds: aws.Int32(3600),
			},
			Version:   "2011-06-15",
			Region:    cfg.flAWSRegion,
			TPMSigner: tpmSigner,
		})

		if err != nil {
			fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Could not initialize TPM Credentials %v", err)
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Second*time.Duration(cfg.flTimeout)))
	defer cancel()
	creds, err := hc.Retrieve(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Could not retrieve credentials %v", err)
		os.Exit(1)
	}
	resp := &processCredentialsResponse{
		Version:         1,
		AccessKeyId:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      fmt.Sprintf("%s", creds.Expires.Format(RFC3339)),
	}

	m, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Error marshalling processCredential output %v", err)
		os.Exit(1)
	}
	fmt.Println(string(m))
}
