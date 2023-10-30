
# AWS Process Credentials for Hardware Security Modules (HSM) and TPM based AWS_SECRET_ACCESS_KEY

AWS [Process Credential](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) source where the `AWS_SECRET_ACCESS_KEY` is embedded into a `Trusted Platform Module (TPM)`.

Use the binary as a way to use aws cli and any sdk library where you never actually need to know the _source_ `AWS_SECRET_ACCESS_KEY`. 

To use this, you need to save the AWS_SECRET_ACCESS_KEY into the TPM:

1. Directly load `AWS_SECRET_ACCESS_KEY` 

  With this, you "load" the AWS_SECRET_ACCESS_KEY into a TPM's [persistentHandle](https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf) such that it can only be used on that TPM along. 

2. Securely Transfer `AWS_SECRET_ACCESS_KEY` from one hose to another

  This flow is not shown in this repo but is describe in:  [Duplicate an externally loaded HMAC key](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate#duplicate-an-externally-loaded-hmac-key)


This repo shows how to do `1`

If you're curious how all this works, see

- [AWS Credentials for Hardware Security Modules and TPM based AWS_SECRET_ACCESS_KEY](https://github.com/salrashid123/aws_hmac)

---



### Setup

On a system which has the TPM, [install go](https://go.dev/doc/install), then run the following which seals the key to `persistentHandle`
```bash
$ export AWS_ACCESS_KEY_ID=AKIAUH3H6EGK-redacted
$ export AWS_SECRET_ACCESS_KEY=--redacted--

$ git clone https://github.com/salrashid123/aws_hmac.git
$ cd aws_hmac/example/tpm
$ go run main.go  \
   --awsRegion=us-east-1 -accessKeyID $AWS_ACCESS_KEY_ID \
   -secretAccessKey $AWS_SECRET_ACCESS_KEY --persistentHandle=0x81008003
```


While this repo uses persistentHandle, its easy enough to use TPM encrypted files as shown here: [hmac import to files](https://github.com/salrashid123/tpm2/tree/master/hmac_import#hmac-import-to-files)

### Configure AWS Process Credential Profiles

To test the process credential API and persistent handle, first download `aws-tpm-process-credential` from the Releases section or build it on your own

This repo will assume a role  `"arn:aws:iam::291738886548:user/svcacct1"` has access to AssumeRole on `arn:aws:iam::291738886548:role/gcpsts` and both the user and role has access to an s3 bucket

![images/role_trust.png](images/role_trust.png)


Edit  `~/.aws/config` and set the process credential parameters 

```conf
[profile sessiontoken]
credential_process = /path/to/aws-tpm-process-credential  --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=false --persistentHandle=0x81008003 --aws-access-key-id=AKIAUH3H6EGK-redacted  --duration=3600

[profile assumerole]
credential_process = /path/to/aws-tpm-process-credential  --aws-arn="arn:aws:iam::291738886548:role/gcpsts" --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=true --persistentHandle=0x81008003 --aws-access-key-id=AKIAUH3H6EGK-redacted  --duration=3600 
```

#### Verify AssumeRole


To verify `AssumeRole` first just run `aws-tpm-process-credential` directly

```bash
$ sudo /path/to/aws-tpm-process-credential \
   --aws-arn="arn:aws:iam::291738886548:role/gcpsts" --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=true --persistentHandle=0x81008003 --aws-access-key-id=$AWS_ACCESS_KEY_ID  --duration=3600 

{
  "Version": 1,
  "AccessKeyId": "ASIAUH3H6EGKIA6WLCJG",
  "SecretAccessKey": "h7anawgBS5xNPlUcJ2P7x9YED5iltredacted",
  "SessionToken": "FwoGZXIvYXdzEKz//////////wEaDK+OR7VuQewac2+redacted",
  "Expiration": "2023-10-29T19:33:27+0000"
}
```

if that works, verify the aws cli

```bash
$ aws sts get-caller-identity  --profile assumerole
{
    "UserId": "AROAUH3H6EGKHZUSB4BC5:mysession",
    "Account": "291738886548",
    "Arn": "arn:aws:sts::291738886548:assumed-role/gcpsts/mysession"
}

# then finally s3
$  aws s3 ls mineral-minutia --region us-east-2 --profile sessiontoken
2020-08-10 02:52:08        411 README.md
2020-11-03 00:16:00          3 foo.txt
```

#### Verify SessionToken

To verify the session token, first just run `aws-tpm-process-credential` directly

```bash
$  sudo /path/to/aws-tpm-process-credential \
    --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=false --persistentHandle=0x81008003 --aws-access-key-id=$AWS_ACCESS_KEY_ID  --duration=3600

{
  "Version": 1,
  "AccessKeyId": "ASIAUH3H6EGKFOX7G5XU",
  "SecretAccessKey": "lwfjGGh41y/3RI0HUlYJFCK5LWxredacted",
  "SessionToken": "FwoGZXIvYXdzEKv//////////wEaDOrG0ZqGoVCnU89juyKBredacted",
  "Expiration": "2023-10-29T18:59:58+0000"
}
```

if that works, verify the aws cli

```bash
$ aws sts get-caller-identity  --profile sessiontoken
{
    "UserId": "AIDAUH3H6EGKDO36JYJH3",
    "Account": "291738886548",
    "Arn": "arn:aws:iam::291738886548:user/svcacct1"
}

# then finally s3
$ aws s3 ls mineral-minutia --region us-east-2 --profile sessiontoken
2020-08-10 02:52:08        411 README.md
2020-11-03 00:16:00          3 foo.txt
```

---

#### References

- [TPM Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-tpm)
- [PKCS-11 Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-pkcs)
- [AWS Authentication using TPM HMAC](https://github.com/salrashid123/aws_hmac/tree/main/example/tpm#usage-tpm)
- [AWS Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

