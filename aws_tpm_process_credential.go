package awstpmcredential

import (
	"context"
	"encoding/hex"
	"io"
	"strconv"
	"time"

	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	keyfile "github.com/foxboron/go-tpm-keyfiles"

	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	hmaccred "github.com/salrashid123/aws_hmac/tpm"
	hmacsigner "github.com/salrashid123/aws_hmac/tpm/signer"
)

const ()

// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
type ProcessCredentialsResponse struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

const (
	rfc3339 = "2006-01-02T15:04:05Z07:00"
)

type AWSTPMConfig struct {
	TPMCloser            io.ReadWriteCloser
	PersistentHandle     uint
	AWSAccessKeyID       string
	CredentialFile       string
	AWSRoleArn           string
	AWSRegion            string
	Duration             uint64
	Timeout              uint
	AWSSessionName       string
	AssumeRole           bool
	TPMSessionPublicName string
	Parentpass           string
	Keypass              string
	Pcrs                 string
	UseEKParent          bool
}

var (
	cfg = AWSTPMConfig{}
)

func NewAWSTPMCredential(cfgValues *AWSTPMConfig) (*ProcessCredentialsResponse, error) {
	cfg = *cfgValues

	rwr := transport.FromReadWriter(cfg.TPMCloser)

	// first check if we should use session encryption with the TPM
	// if the "name" object is specified, we will use the EK RSAEKTemplate and compare what its 'name' against a  known value
	encsess := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptOut))

	var encryptionSessionHandle tpm2.TPMHandle

	if cfg.TPMSessionPublicName != "" {
		createEKRsp, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
		}.Execute(rwr, encsess)
		if err != nil {
			return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: error creating EK Primary  %v", err)
		}
		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: createEKRsp.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		if cfg.TPMSessionPublicName != hex.EncodeToString(createEKRsp.Name.Buffer) {
			return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential:: session encryption names do not match expected [%s] got [%s]", cfg.TPMSessionPublicName, hex.EncodeToString(createEKRsp.Name.Buffer))
		}
	}

	var keyHandle tpm2.TPMHandle
	var primaryKey *tpm2.CreatePrimaryResponse
	var parentSession tpm2.Session

	if cfg.CredentialFile != "" {

		c, err := os.ReadFile(cfg.CredentialFile)
		if err != nil {
			return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: error reading encrypted credential file %s: %v", cfg.CredentialFile, err)
		}

		key, err := keyfile.Decode(c)
		if err != nil {
			return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: error decoding credential file %s: %v", cfg.CredentialFile, err)
		}

		if cfg.UseEKParent {
			primaryKey, err = tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
			}.Execute(rwr)
			if err != nil {
				return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential:can't create pimaryEK: %v", err)
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()
			var load_session_cleanup func() error
			parentSession, load_session_cleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
			if err != nil {
				return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: can't load policysession : %v", err)
			}
			defer load_session_cleanup()

			_, err = tpm2.PolicySecret{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth([]byte(cfg.Parentpass)),
				},
				PolicySession: parentSession.Handle(),
				NonceTPM:      parentSession.NonceTPM(),
			}.Execute(rwr)
			if err != nil {
				return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential:can't create policysecret: %v", err)
			}

		} else {
			// now load the key using the H2 template
			// specify its parent directly
			primaryKey, err = tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHOwner,
				InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
			}.Execute(rwr)
			if err != nil {
				return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: error creating H2 primary key %v", err)
			}
			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()
			parentSession = tpm2.PasswordAuth([]byte(cfg.Parentpass))
			// now the actual key can get loaded from that parent
		}
		hmacKey, err := tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: primaryKey.ObjectHandle,
				Name:   tpm2.TPM2BName(primaryKey.Name),
				Auth:   parentSession,
			},
			InPublic:  key.Pubkey,
			InPrivate: key.Privkey,
		}.Execute(rwr)
		if err != nil {
			return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: error loading hmac key %v", err)
		}
		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: hmacKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()
		keyHandle = hmacKey.ObjectHandle

	} else if cfg.PersistentHandle != 0 {
		if cfg.UseEKParent {
			var err error
			primaryKey, err = tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
			}.Execute(rwr)
			if err != nil {
				return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: can't create pimaryEK: %v", err)
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()
			var load_session_cleanup func() error
			parentSession, load_session_cleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
			if err != nil {
				return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: can't load policysession : %v", err)
			}
			defer load_session_cleanup()

			_, err = tpm2.PolicySecret{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth([]byte(cfg.Parentpass)),
				},
				PolicySession: parentSession.Handle(),
				NonceTPM:      parentSession.NonceTPM(),
			}.Execute(rwr)
			if err != nil {
				return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: can't create policysecret: %v", err)
			}
		}
		keyHandle = tpm2.TPMHandle(cfg.PersistentHandle)
	} else {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: either -credential-file or persistentHandle")
	}

	// pub, err := tpm2.ReadPublic{
	// 	ObjectHandle: keyHandle,
	// }.Execute(rwr)
	// if err != nil {
	// 	return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: Error creating tpm2.Public TPM: %v", err)
	// }

	var sess hmacsigner.Session
	var err error
	if cfg.Pcrs != "" {
		strpcrs := strings.Split(cfg.Pcrs, ",")
		var pcrList = []uint{}

		for _, i := range strpcrs {
			j, err := strconv.Atoi(i)
			if err != nil {
				return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential:  could convert pcr value: %v", err)
			}
			pcrList = append(pcrList, uint(j))
		}

		sel := []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
			}}
		selection := tpm2.TPMLPCRSelection{
			PCRSelections: sel,
		}
		// expectedDigest, err := getExpectedPCRDigest(rwr, selection, tpm2.TPMAlgSHA256)
		// if err != nil {
		// 	return processCredentialsResponse{}, fmt.Errorf("ERROR:  could not get PolicySession: %v", err)
		// }

		if cfg.UseEKParent {
			sess, err = hmacsigner.NewPCRAndDuplicateSelectSession(rwr, sel, []byte(cfg.Keypass), primaryKey.Name)
			if err != nil {
				return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: can't create autsession: %v", err)
			}
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: primaryKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		} else {

			sess, err = hmacsigner.NewPCRSession(rwr, selection.PCRSelections)
			if err != nil {
				return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential:  could not get PolicySession: %v", err)
			}
		}

	} else if cfg.Keypass != "" {
		if cfg.UseEKParent {
			sess, err = hmacsigner.NewPolicyAuthValueAndDuplicateSelectSession(rwr, []byte(cfg.Keypass), primaryKey.Name)
			if err != nil {
				return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: can't create autsession: %v", err)
			}
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: primaryKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		} else {
			sess, err = hmacsigner.NewPasswordSession(rwr, []byte(cfg.Keypass))
			if err != nil {
				return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential:  could not get PolicySession: %v", err)
			}
		}
	}

	tpmSigner, err := hmacsigner.NewTPMSigner(&hmacsigner.TPMSignerConfig{
		TPMConfig: hmacsigner.TPMConfig{
			TPMDevice:        cfg.TPMCloser,
			Handle:           keyHandle,
			AuthSession:      sess,
			EncryptionHandle: encryptionSessionHandle,
		},
		AccessKeyID: cfg.AWSAccessKeyID,
	})
	if err != nil {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: Error creating signer open TPM %v", err)
	}

	var hc *hmaccred.TPMCredentialsProvider

	if cfg.AssumeRole {
		hc, err = hmaccred.NewAWSTPMCredentials(hmaccred.TPMProvider{
			AssumeRoleInput: &sts.AssumeRoleInput{
				RoleArn:         aws.String(cfg.AWSRoleArn),
				RoleSessionName: aws.String(cfg.AWSSessionName),
				DurationSeconds: aws.Int32(int32(cfg.Duration)),
			},
			Version:   "2011-06-15",
			Region:    cfg.AWSRegion,
			TPMSigner: tpmSigner,
		})
		if err != nil {
			return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: Could not initialize TPM Credentials %v", err)
		}
	} else {

		hc, err = hmaccred.NewAWSTPMCredentials(hmaccred.TPMProvider{
			GetSessionTokenInput: &sts.GetSessionTokenInput{
				DurationSeconds: aws.Int32(int32(cfg.Duration)),
			},
			Version:   "2011-06-15",
			Region:    cfg.AWSRegion,
			TPMSigner: tpmSigner,
		})

		if err != nil {
			return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: Could not initialize TPM Credentials %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Second*time.Duration(cfg.Timeout)))
	defer cancel()
	creds, err := hc.Retrieve(ctx)
	if err != nil {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-tpm-process-credential: Could not retrieve credentials %v", err)
	}
	return &ProcessCredentialsResponse{
		Version:         1,
		AccessKeyId:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      creds.Expires.Format(rfc3339),
	}, nil

}
