### AWS Process Credentials for Trusted Platform Module (TPM)

AWS [Process Credential](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) source where the `AWS_SECRET_ACCESS_KEY` is embedded into a `Trusted Platform Module (TPM)`.

Use the binary as a way to use aws cli and any sdk library where after setup, you don't actually need to know the _source_ AWS_SECRET_ACCESS_KEY. 

To use this, you need to save the `AWS_SECRET_ACCESS_KEY` into the TPM:

1. Directly load `AWS_SECRET_ACCESS_KEY` 

   With this, you "load" the `AWS_SECRET_ACCESS_KEY` into a TPM's [persistentHandle](https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf) or a TPM encrypted PEM  that it can only be used on that TPM alone. 

2. Securely Transfer `AWS_SECRET_ACCESS_KEY` from one hose to another

   This flow is not shown in this repo but is describe in:  [Duplicate an externally loaded HMAC key](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate#duplicate-an-externally-loaded-hmac-key)


This repo shows how to do `1`

If you're curious how all this works, see

- [AWS Credentials for Hardware Security Modules and TPM based AWS_SECRET_ACCESS_KEY](https://github.com/salrashid123/aws_hmac)

---

### Configuration Options

You can set the following options on usage:

| Option | Description |
|:------------|-------------|
| **`--tpm-path`** | path to the TPM device (default: `/dev/tpm0`) |
| **`--aws-access-key-id`** | (required) The value for `AWS_ACCESS_KEY_ID`  |
| **`--persistentHandle`** | Persistent Handle for the HMAC key (default: `0x81008003`) |
| **`--credential-file`** | Path to the TPM HMAC credential file (default: ``) |
| **`--keypass`** | Passphrase for the key handle (will use TPM_KEY_AUTH env var) |
| **`--parentPass`** | Passphrase for the key handle (will use TPM_KEY_AUTH env var) |
| **`--pcrs`** | PCR Bound value (increasing order, comma separated) |
| **`--aws-arn`** | AWS ARN value to use (default: ``) |
| **`--aws-session-name`** | Session Name to use (default: ``) |
| **`--aws-region`** | AWS Region to use (default: ``) |
| **`--assumeRole`** | Boolean flag to switch the token type returned (default: `false`) |
| **`--duration`** | Lifetime for the AWS token (default: `3600s`) |
| **`--timeout`** | Timeout waiting for HMAC signature from the TPM (default: `2s`) |
| **`--tpm-session-encrypt-with-name`** | hex encoded TPM object 'name' to use with an encrypted session |


### Setup

On a system which has the TPM, [install go](https://go.dev/doc/install), then run the following which seals the key to `persistentHandle`

```bash
## add the AWS4 prefix to the raw hmac secret access key prior to import
export secret="AWS4$AWS_SECRET_ACCESS_KEY"
echo -n $secret > hmac.key
hexkey=$(xxd -p -c 256 < hmac.key)

## create the primary
### the specific primary here happens to be the h2 template described later on but you are free to define any template and policy
### this is the "H2" profile from https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_import -C primary.ctx -G hmac -i hmac.key -u hmac.pub -r hmac.priv 
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx 

## either create a persistent handle or encode into a PEM file
# tpm2_evictcontrol -C o -c hmac.ctx 0x81010002

tpm2_encodeobject -C primary.ctx -u hmac.pub -r  hmac.priv -o private.pem

## or golang:
# $ git clone https://github.com/salrashid123/aws_hmac.git
# $ cd aws_hmac/example/tpm
# $ go run create/main.go --accessKeyID $AWS_ACCESS_KEY_ID \
#    --secretAccessKey $AWS_SECRET_ACCESS_KEY \
#    --persistentHandle=0x81010002 --out=private.pem
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

To run this directly

```bash

go build -o aws-tpm-process-credential cmd/main.go

## using persistent handle
./aws-tpm-process-credential  --aws-region=us-east-1 \
    --aws-session-name=mysession --assumeRole=false --persistentHandle=0x81010002 \
    --aws-access-key-id=$AWS_ACCESS_KEY_ID  --duration=3600

# using encrypted file
./aws-tpm-process-credential  --aws-region=us-east-1 \
    --aws-session-name=mysession --assumeRole=false --credential-file=/path/to/private.pem \
    --aws-access-key-id=$AWS_ACCESS_KEY_ID  --duration=3600    
```

### Configure AWS Process Credential Profiles

To test the process credential API and persistent handle, first download `aws-tpm-process-credential` from the Releases section or build it on your own

This repo will assume a role  `"arn:aws:iam::291738886548:user/svcacct1"` has access to AssumeRole on `arn:aws:iam::291738886548:role/gcpsts` and both the user and role has access to an s3 bucket

![images/role_trust.png](images/role_trust.png)


Edit  `~/.aws/config` and set the process credential parameters 

if you want to use `persistentHandle`:

```conf
[profile sessiontoken]
credential_process = /path/to/aws-tpm-process-credential  --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=false --persistentHandle=0x81010002 --aws-access-key-id=AKIAUH3H6EGK-redacted  --duration=3600

[profile assumerole]
credential_process = /path/to/aws-tpm-process-credential  --aws-arn="arn:aws:iam::291738886548:role/gcpsts" --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=true --persistentHandle=0x81010002 --aws-access-key-id=AKIAUH3H6EGK-redacted  --duration=3600 
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
$ /path/to/aws-tpm-process-credential \
   --aws-arn="arn:aws:iam::291738886548:role/gcpsts" --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=true --persistentHandle=0x81010002 --aws-access-key-id=$AWS_ACCESS_KEY_ID  --duration=3600 

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
    --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=false --persistentHandle=0x81010002 --aws-access-key-id=$AWS_ACCESS_KEY_ID  --duration=3600

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

### Testing

```bash
export AWS_ACCESS_KEY_ID=redacted
export AWS_SECRET_ACCESS_KEY=redacted
export AWS_ROLE_SESSION_NAME=mysession
export AWS_DEFAULT_REGION=us-east-1
export AWS_ROLE_ARN=arn:aws:iam::291738886548:role/cicdrole
export AWS_ACCOUNT_ARN=arn:aws:iam::291738886548:user/testservice
export AWS_ROLE_SESSION_ARN=arn:aws:sts::291738886548:assumed-role/cicdrole/mysession

go test -v
```

---

### Encrypted KeyFile format

The TPM encrypted file is not decodable in userspace (it must be used inside the TPM by the TPM).  The default format used here is compatible with openssl as described in [ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent)  where the template h-2 is described in pg 43 [TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r2_10feb2021.pdf)

Of course the encrypted key can **ONLY** be used ont that TPM.


### PCR Policy

If you want to setup access to the key using a TPM PCR policy (eg, pcr values you specified during key creation must be met during signing), then configure it first during key creation:


In the following PCR 23 is used:

```bash
export secret="AWS4$AWS_SECRET_ACCESS_KEY"
echo -n $secret > hmac.key
hexkey=$(xxd -p -c 256 < hmac.key)

tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
tpm2_flushcontext session.dat

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_import -C primary.ctx -G hmac -i hmac.key -u hmac.pub -r hmac.priv -L policy.dat
tpm2_load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx 

## either use persistent handle or PEM file
tpm2_evictcontrol -C o -c hmac.ctx 0x81010003
tpm2_encodeobject -C primary.ctx -u hmac.pub -r  hmac.priv -o private.pem
```

And then again by passing through the `--pcrs=` parameter

```bash
./aws-tpm-process-credential \
 --aws-arn="arn:aws:iam::291738886548:role/gcpsts" --aws-region=us-east-1 \
   --aws-session-name=mysession --assumeRole=true --persistentHandle=0x81010003 \
    --aws-access-key-id=$AWS_ACCESS_KEY_ID  --duration=3600 --pcrs=23
```

ofcourse if you alter the value, the key can't be used for signing again

```bash
$ tpm2_pcrread sha256:23
  sha256:
    23: 0xC78009FDF07FC56A11F122370658A353AAA542ED63E44C4BC15FF4CD105AB33C

$ tpm2_pcrextend 23:sha256=0xC78009FDF07FC56A11F122370658A353AAA542ED63E44C4BC15FF4CD105AB33C
```

### Password Policy

If you want to setup access to the key using a TPM Password policy (eg, you have to supply a passphrase first), then configure it first during key creation:

```bash
export passphrase="testpwd"
export secret="AWS4$AWS_SECRET_ACCESS_KEY"
echo -n $secret > hmac.key
hexkey=$(xxd -p -c 256 < hmac.key)

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_import -C primary.ctx -G hmac -i hmac.key -u hmac.pub -r hmac.priv -p $passphrase
tpm2_load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx 

## either use persistent handle or PEM file
tpm2_evictcontrol -C o -c hmac.ctx 0x81010004
tpm2_encodeobject -C primary.ctx -u hmac.pub -r  hmac.priv -o private.pem
```

And then again by passing through the `--keyPass=` parameter

```bash
./aws-tpm-process-credential \
 --aws-arn="arn:aws:iam::291738886548:role/gcpsts" --aws-region=us-east-1 \
  --aws-session-name=mysession --assumeRole=true --persistentHandle=0x81010004 \
  --aws-access-key-id=$AWS_ACCESS_KEY_ID  --duration=3600 --keyPass=$passphrase
```

If you want to create a custom policy, you need to modify the code as described [here](https://github.com/salrashid123/aws_hmac/blob/main/example/tpm/README.md#pcr-policy)


### SoftwareTPM

If you just want to test this with a software TPM:

```bash
## Initialize TPM-A
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

export TPM2TOOLS_TCTI="swtpm:port=2321"
tpm2_pcrread sha256:0,23
```

#### Verify Release Binary

If you download a binary from the "Releases" page, you can verify the signature with GPG:

```bash
gpg --keyserver keys.openpgp.org --recv-keys 3FCD7ECFB7345F2A98F9F346285AEDB3D5B5EF74

export VERSION=0.0.7
## to verify the checksum file for a given release:
wget https://github.com/salrashid123/aws-tpm-process-credential/releases/download/v$VERSION/aws-tpm-process-credential_$VERSION_checksums.txt
wget https://github.com/salrashid123/aws-tpm-process-credential/releases/download/v$VERSION/aws-tpm-process-credential_$VERSION_checksums.txt.sig

gpg --verify aws-tpm-process-credential_$VERSION_checksums.txt.sig aws-tpm-process-credential_$VERSION_checksums.txt
```

#### Verify Release Binary with github Attestation

You can also verify the binary using [github attestation](https://github.blog/news-insights/product-news/introducing-artifact-attestations-now-in-public-beta/)

For example, the attestation for releases `[@refs/tags/v0.0.7]` can be found at

* [https://github.com/salrashid123/aws-tpm-process-credential/attestations](https://github.com/salrashid123/aws-tpm-process-credential/attestations)

Then to verify:

```bash
$ export VERSION=0.0.7
$ wget https://github.com/salrashid123/aws-tpm-process-credential/releases/download/v$VERSION/aws-tpm-process-credential_$VERSION_linux_amd64
$ wget https://github.com/salrashid123/aws-tpm-process-credential/attestations/4853131/download -O salrashid123-aws-tpm-process-credential-attestation-4853131.json

$ gh attestation verify --owner salrashid123 --bundle salrashid123-aws-tpm-process-credential-attestation-4853131.json  aws-tpm-process-credential_$VERSION_linux_amd64
```

### Encrypted TPM Sessions

If you want to enable [TPM Encrypted sessions](https://github.com/salrashid123/tpm2/tree/master/tpm_encrypted_session), you should provide the "name" of a trusted key on the TPM for each call.

A trusted key can be the EK Key. You can get the name using `tpm2_tools`:

```bash
tpm2_createek -c primary.ctx -G rsa -u ek.pub -Q
tpm2_readpublic -c primary.ctx -o ek.pem -n name.bin -f pem -Q
xxd -p -c 100 name.bin 
  000bb50d34f6377bb3c2f41a1b4b6094ed6efcd7032d28054566db0766879dad1ee0
```

Then use the hex value returned in the `--tpm-session-encrypt-with-name=` argument.

For example:

```bash
   --tpm-session-encrypt-with-name=000bb50d34f6377bb3c2f41a1b4b6094ed6efcd7032d28054566db0766879dad1ee0
```

You can also derive the "name" from a public key of a known template:

see [go-tpm.tpm2_get_name](https://github.com/salrashid123/tpm2/tree/master/tpm2_get_name)

#### References

- [TPM Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-tpm)
- [PKCS-11 Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-pkcs)
- [AWS Authentication using TPM HMAC](https://github.com/salrashid123/aws_hmac/tree/main/example/tpm#usage-tpm)
- [AWS Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

