### AWS Process Credentials for Trusted Platform Module (TPM)

AWS [Process Credential](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) source where the `AWS_SECRET_ACCESS_KEY` is embedded into a `Trusted Platform Module (TPM)`.

Use the binary as a way to use aws cli and any sdk library where after setup, you don't actually need to know the _source_ AWS_SECRET_ACCESS_KEY. 

To use this, you need to save the AWS_SECRET_ACCESS_KEY into the TPM:

1. Directly load `AWS_SECRET_ACCESS_KEY` 

   With this, you "load" the AWS_SECRET_ACCESS_KEY into a TPM's [persistentHandle](https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf) or a TPM encrypted PEM  that it can only be used on that TPM alone. 

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
$ go run create/main.go --accessKeyID $AWS_ACCESS_KEY_ID \
   --secretAccessKey $AWS_SECRET_ACCESS_KEY \
   --persistentHandle=0x81008003 --out=private.pem
```

At this point the hmac key is saved to *both* a persistent handle and an encrypted representation as PEM (see [tpm2 primary key for (eg TCG EK Credential Profile H-2 profile](https://gist.github.com/salrashid123/9822b151ebb66f4083c5f71fd4cdbe40))

```bash
-----BEGIN TSS2 PRIVATE KEY-----
MIHyBgZngQUKAQMCBQCAAAAABDIAMAAIAAsABABSAAAABQALACBkiLm1axCgdEJd
x2/m1J3k070HR2AY7fPXJ+ebWLciPQSBrACqACBcyk0W0lW71RgcPEeFJmOCmmOZ
Ww98+HwktElq9tPMWgAQRKX1ES2lUlg1h3psbVKbI38kuUWjFu1/27R/8r4cnGHx
K/2tVabz5qHl5T7UvnBJ8Cka1joTVmVugt9aNqHSlgovvnjwxWtok4rgyHPxPjly
CqYYr6ZsALXv/mmvs6dyeuz3Xo9YPFmzTxnvEfqZHhpNAOe8fB8HzouLczT2vRLl
nwb+VkA=
-----END TSS2 PRIVATE KEY-----
```

You can use either way.  With files you can dynamically specify the credentials to use while with persistent handles, you need to load them first and have limited ability capacity.

### Configuration Options

You can set the following options on usage:

| Option | Description |
|:------------|-------------|
| **`--tpm-path`** | path to the TPM device (default: `/dev/tpm0`) |
| **`--aws-access-key-id`** | (required) The value for `AWS_ACCESS_KEY_ID`  |
| **`--persistentHandle`** | Persistent Handle for the HMAC key (default: `0x81008003`) |
| **`--credential-file`** | Path to the TPM HMAC credential file (default: ``) |
| **`--aws-arn`** | AWS ARN value to use (default: ``) |
| **`--aws-session-name`** | Session Name to use (default: ``) |
| **`--aws-region`** | AWS Region to use (default: ``) |
| **`--assumeRole`** | Boolean flag to switch the token type returned (default: `false`) |
| **`--duration`** | Lifetime for the AWS token (default: `3600s`) |
| **`--timeout`** | Timeout waiting for HMAC signature from the TPM (default: `2s`) |


### Configure AWS Process Credential Profiles

To test the process credential API and persistent handle, first download `aws-tpm-process-credential` from the Releases section or build it on your own

This repo will assume a role  `"arn:aws:iam::291738886548:user/svcacct1"` has access to AssumeRole on `arn:aws:iam::291738886548:role/gcpsts` and both the user and role has access to an s3 bucket

![images/role_trust.png](images/role_trust.png)


Edit  `~/.aws/config` and set the process credential parameters 

if you want to use `persistentHandle`:
```conf
[profile sessiontoken]
credential_process = /path/to/aws-tpm-process-credential  --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=false --persistentHandle=0x81008003 --aws-access-key-id=AKIAUH3H6EGK-redacted  --duration=3600

[profile assumerole]
credential_process = /path/to/aws-tpm-process-credential  --aws-arn="arn:aws:iam::291738886548:role/gcpsts" --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=true --persistentHandle=0x81008003 --aws-access-key-id=AKIAUH3H6EGK-redacted  --duration=3600 
```

or credential file:

```conf
[profile sessiontokenfile]
credential_process = /path/to/aws-tpm-process-credential  --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=false --credential-file=/path/to/private.pem --aws-access-key-id=AKIAUH3H6EGK-redacted  --duration=3600

[profile assumerolefile]
credential_process = /path/to/aws-tpm-process-credential  --aws-arn="arn:aws:iam::291738886548:role/gcpsts" --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=true --credential-file=/path/to/private.pem --aws-access-key-id=AKIAUH3H6EGK-redacted  --duration=3600 
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


### Encrypted KeyFile format

The TPM encrypted file is not decodable in userspace (it must be used inside the TPM by the TPM).  The default format used here is compatible with openssl as described in [ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent)  where the template h-2 is described in pg 43 [TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r2_10feb2021.pdf)

Of course the encrypted key can **ONLY** be used ont that TPM.

### Using TPM2_Tools

You can also import the hmac key using `tpm2_tools` and write it to an encrypted file

```bash
export secret="AWS4$AWS_SECRET_ACCESS_KEY"
echo -n $secret > hmac.key
hexkey=$(xxd -p -c 256 < hmac.key)

## this is the "H2" profile from https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_import -C primary.ctx -G hmac -i hmac.key -u hmac.pub -r hmac.priv 
tpm2_load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx 

echo -n "foo" > hmac_input.txt 
tpm2_hmac -g sha256 -c hmac.ctx hmac_input.txt | xxd -p -c 256

# now export the keys using  https://github.com/tpm2-software/tpm2-tss-engine/blob/master/man/tpm2tss-genkey.1.md
tpm2tss-genkey -u key.pub -r key.priv private.pem
```


### Session Auth

This provide does not support any authorization policies you may have (eg [hmac with pcr policy](https://gist.github.com/salrashid123/9ee5e02d5991c8d53717bd9a179a65b0)).  

This is a todo where we need to initialize an appropriate `tpm2.AuthHandle` with the sessions setup.  if you need something like this, LMK

The same applies to the owner-auth (eg, it assumes no parent password is required...again, this could be just an enhancement if there is demand)

#### References

- [TPM Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-tpm)
- [PKCS-11 Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-pkcs)
- [AWS Authentication using TPM HMAC](https://github.com/salrashid123/aws_hmac/tree/main/example/tpm#usage-tpm)
- [AWS Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

