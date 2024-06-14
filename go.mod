module github.com/salrashid123/aws-tpm-process-credential

go 1.22.0

toolchain go1.22.2

require (
	github.com/aws/aws-sdk-go-v2 v1.27.2
	github.com/aws/aws-sdk-go-v2/service/sts v1.28.12
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20240607201534-c7a43ea1908b
	github.com/google/go-tpm v0.9.1
	github.com/google/uuid v1.6.0
	github.com/salrashid123/aws_hmac/tpm v0.0.0-20240614120343-9c9dcc94616b
	github.com/salrashid123/aws_hmac/tpm/signer v0.0.0-20240614120343-9c9dcc94616b
)

require (
	github.com/salrashid123/aws_hmac/stsschema v0.0.0-20240614120343-9c9dcc94616b // indirect
	github.com/salrashid123/aws_hmac/tpm/signer/v4 v4.0.0-20240614120343-9c9dcc94616b // indirect
)

require (
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.11 // indirect
	github.com/aws/smithy-go v1.20.2 // indirect
	github.com/gorilla/schema v1.3.0 // indirect
	// github.com/salrashid123/aws_hmac/stsschema v0.0.0-20240603121823-6fc15dbd588a // indirect
	// github.com/salrashid123/aws_hmac/tpm/signer/v4 v4.0.0-20240603121823-6fc15dbd588a // indirect
	// github.com/salrashid123/aws_hmac/stsschema v0.0.0 // indirect
	// github.com/salrashid123/aws_hmac/tpm/signer/v4 v4.0.0 // indirect
	golang.org/x/crypto v0.24.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
)
