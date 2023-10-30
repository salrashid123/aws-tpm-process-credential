package main

import (
	"encoding/json"

	"fmt"
	"os"

	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"

	"strings"

	"flag"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/uuid"

	"github.com/salrashid123/aws_hmac/stsschema"

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
	ISO8601 = "2006-01-02T15:04:05-0700"
)

type credConfig struct {
	flTPMPath          string
	flPersistentHandle uint
	flAWSAccessKeyID   string
	flAWSRoleArn       string
	flAWSRegion        string
	flDuration         uint64
	flAWSSessionName   string
	flAssumeRole       bool
}

var (
	cfg = &credConfig{}
)

func main() {
	//ctx := context.Background()	flag.Parse	var err error
	flag.StringVar(&cfg.flTPMPath, "tpm-path", "/dev/tpm0", "Path to the TPM Object")
	flag.UintVar(&cfg.flPersistentHandle, "persistentHandle", 0x81008003, "Handle value")
	flag.Uint64Var(&cfg.flDuration, "duration", uint64(3600), "Duration value")
	flag.StringVar(&cfg.flAWSRoleArn, "aws-arn", "", "AWS ARN Value")
	flag.StringVar(&cfg.flAWSRegion, "aws-region", "", "AWS Region")
	flag.BoolVar(&cfg.flAssumeRole, "assumeRole", false, "Assume Role")
	flag.StringVar(&cfg.flAWSAccessKeyID, "aws-access-key-id", "", "(required) AWS access key id")
	flag.StringVar(&cfg.flAWSSessionName, "aws-session-name", fmt.Sprintf("gcp-%s", uuid.New().String()), "AWS SessionName")

	flag.Parse()

	argError := func(s string, v ...interface{}) {
		//flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "Invalid Argument error: "+s, v...)
		os.Exit(1)
	}

	if cfg.flAWSAccessKeyID == "" || cfg.flAWSRegion == "" {
		argError("-aws-access-key-id --aws-region cannot be null")
	}

	if cfg.flAssumeRole && cfg.flAWSSessionName == "" {
		argError("-aws-session-name cannot be null if --flAssumeRole=true")
	}
	rwc, err := tpm2.OpenTPM(cfg.flTPMPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", cfg.flTPMPath, err)
		os.Exit(1)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			if strings.Contains(err.Error(), "file already closed") {
				os.Exit(0)
			}
			fmt.Fprintf(os.Stderr, "Can't close TPM (may already be closed earlier) %s: %v", cfg.flTPMPath, err)
			os.Exit(1)
		}
	}()

	tpmSigner, err := hmacsigner.NewTPMSigner(&hmacsigner.TPMSignerConfig{
		TPMConfig: hmacsigner.TPMConfig{
			TPMDevice: rwc,
			TpmHandle: tpmutil.Handle(cfg.flPersistentHandle),
		},
		AccessKeyID: cfg.flAWSAccessKeyID,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating signer open TPM %s: %v", cfg.flTPMPath, err)
		os.Exit(1)
	}

	var creds *credentials.Credentials

	if cfg.flAssumeRole {
		creds, err = hmaccred.NewAWSTPMCredentials(hmaccred.TPMProvider{
			AssumeRoleInput: &stsschema.AssumeRoleInput{
				RoleArn:         aws.String(cfg.flAWSRoleArn),
				RoleSessionName: aws.String(cfg.flAWSSessionName),
				DurationSeconds: aws.Int64(int64(cfg.flDuration)),
			},
			Version:   "2011-06-15",
			Region:    cfg.flAWSRegion,
			TPMSigner: tpmSigner,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not initialize Tink Credentials %v", err)
			os.Exit(1)
		}

	} else {
		creds, err = hmaccred.NewAWSTPMCredentials(hmaccred.TPMProvider{
			GetSessionTokenInput: &stsschema.GetSessionTokenInput{
				DurationSeconds: aws.Int64(int64(cfg.flDuration)),
			},
			Version:   "2011-06-15",
			Region:    cfg.flAWSRegion,
			TPMSigner: tpmSigner,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not initialize Tink Credentials %v", err)
			os.Exit(1)
		}
	}

	val, err := creds.Get()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing STS Credentials %v", err)
		os.Exit(1)
	}

	t, err := creds.ExpiresAt()
	if err != nil {
		log.Fatalf("Error getting Expiration Time %v", err)
	}

	resp := &processCredentialsResponse{
		Version:         1,
		AccessKeyId:     val.AccessKeyID,
		SecretAccessKey: val.SecretAccessKey,
		SessionToken:    val.SessionToken,
		Expiration:      fmt.Sprintf("%s", t.Format(ISO8601)),
	}

	m, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling processCredential output %v", err)
		os.Exit(1)
	}
	fmt.Println(string(m))
}
