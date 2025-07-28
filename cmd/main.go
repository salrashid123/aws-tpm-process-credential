package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"

	"github.com/google/go-tpm/tpmutil"
	"github.com/google/uuid"
	awstpmcredential "github.com/salrashid123/aws-tpm-process-credential"
)

const (
	parent_pass_var = "TPM_PARENT_AUTH"
	key_pass_var    = "TPM_KEY_AUTH"
)

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Int("persistentHandle", 0x81008003, "Handle value")
	credemtialFile   = flag.String("credential-file", "", "Encrypted Credential")
	duration         = flag.Uint64("duration", uint64(3600), "Duration value")

	awsRoleArn           = flag.String("aws-arn", "", "AWS ARN Value")
	awsRegion            = flag.String("aws-region", "", "AWS Region")
	assumeRole           = flag.Bool("assumeRole", false, "Assume Role")
	awsAccessKeyID       = flag.String("aws-access-key-id", "", "(required) AWS access key id")
	timeout              = flag.Int("timeout", 2, "(optional) timeout (default 2s)")
	awsSessionName       = flag.String("aws-session-name", fmt.Sprintf("gcp-%s", uuid.New().String()), "AWS SessionName")
	tpmSessionPublicName = flag.String("tpm-session-encrypt-with-name", "", "hex encoded TPM object 'name' to use with an encrypted session")
	parentPass           = flag.String("parentPass", "", "Passphrase for the key handle (will use TPM_KEY_AUTH env var)")
	keyPass              = flag.String("keyPass", "", "Passphrase for the key handle (will use TPM_KEY_AUTH env var)")
	pcrs                 = flag.String("pcrs", "", "PCR Bound value (increasing order, comma separated)")
	useEKParent          = flag.Bool("useEKParent", false, "Use endorsement RSAKey as parent (not h2) (default: false)")

	version = flag.Bool("version", false, "print version")

	Commit, Tag, Date string
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
		// } else if path == "simulator" {
		// 	return simulator.Get()
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {

	flag.Parse()

	if *version {
		// go build  -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)" cmd/main.go
		fmt.Printf("Version: %s\n", Tag)
		fmt.Printf("Date: %s\n", Date)
		fmt.Printf("Commit: %s\n", Commit)
		os.Exit(0)
	}

	parentPasswordAuth := getEnv(parent_pass_var, "", *parentPass)
	keyPasswordAuth := getEnv(key_pass_var, "", *keyPass)

	rwr, err := openTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Error opening TPM %v", err)
		os.Exit(1)
	}
	resp, err := awstpmcredential.NewAWSTPMCredential(&awstpmcredential.AWSTPMConfig{
		TPMCloser:            rwr,
		PersistentHandle:     uint(*persistentHandle),
		AWSAccessKeyID:       *awsAccessKeyID,
		CredentialFile:       *credemtialFile,
		AWSRoleArn:           *awsRoleArn,
		AWSRegion:            *awsRegion,
		Duration:             *duration,
		Timeout:              uint(*timeout),
		AWSSessionName:       *awsSessionName,
		AssumeRole:           *assumeRole,
		TPMSessionPublicName: *tpmSessionPublicName,
		Parentpass:           parentPasswordAuth,
		Keypass:              keyPasswordAuth,
		Pcrs:                 *pcrs,
		UseEKParent:          *useEKParent,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Error getting credentials %v", err)
		os.Exit(1)
	}
	m, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Error marshalling processCredential output %v", err)
		os.Exit(1)
	}
	fmt.Println(string(m))
}

func getEnv(key, fallback string, fromArg string) string {
	if fromArg != "" {
		return fromArg
	}
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
