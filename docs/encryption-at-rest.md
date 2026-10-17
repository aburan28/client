# Encryption at Rest

dfdaemon can encrypt the task content it caches on disk, so a stolen,
re-mounted or improperly disposed disk does not expose the distributed
artifacts. The encryption is native to the client and does not depend on
LUKS, dm-crypt or encrypted cloud volumes.

## Scope

Encryption at rest protects the **cached content on disk** of the tasks, the
persistent tasks and the persistent cache tasks. It does not change the P2P
protocol: a peer that is authorized to download a piece still receives the
plaintext over the (optionally mTLS protected) transport, exactly as without
encryption, and the piece digests exchanged between peers are still the
digests of the plaintext. Distributing ciphertext end to end between peers is
a separate design.

The in-memory piece cache (`storage.cacheCapacity`) holds plaintext, as it
never reaches the disk. The task metadata stored in RocksDB (task ids, piece
digests, response headers) is not encrypted by this feature.

## Design

- **Per-object data encryption keys.** Every task content file is encrypted
  with its own random 256-bit data encryption key (DEK). Compromising one DEK
  exposes one task only.
- **AES-256-GCM over authenticated chunks.** The plaintext of a piece is split
  into 64 KiB chunks, each encrypted and authenticated independently with a
  random nonce. A chunk is stored as `nonce || ciphertext || tag`, and its
  plaintext offset is bound as associated data, so chunks cannot be swapped
  within a file. Tampered or truncated chunks fail to authenticate and are
  reported as errors instead of being served.
- **Envelope encryption through a KMS.** The DEK is wrapped by a key encryption
  key (KEK) managed by the configured key management service and stored in a
  4 KiB header at the start of the content file, together with the layout
  parameters. The wrapping is bound to the identity of the file (the kind of
  task and the task id) and to the layout parameters, so a content file moved
  to another task, or a header with altered parameters, fails to unwrap its
  DEK. Any dfdaemon holding the KEK can read the file, so the storage can be
  kept across restarts (`storage.keep: true`).
- **Piece-based layout.** The pieces are encrypted independently and stored in
  disjoint regions of the file at a fixed stride, so concurrent and
  out-of-order piece writes, partial downloads and random-access range reads
  within a piece keep working unchanged. A range read decrypts only the chunks
  covering it.

```text
+--------+------------------------------+------------------------------+-----
| header | piece 0                      | piece 1                      | ...
|        | chunk 0  | chunk 1  | ...    | chunk 0  | chunk 1  | ...    |
|        | n|ct|tag | n|ct|tag |        | n|ct|tag | n|ct|tag |        |
+--------+------------------------------+------------------------------+-----
```

The disk overhead is 4 KiB per task plus 28 bytes per 64 KiB chunk (about
0.04%).

## Configuration

```yaml
storage:
  # Keep the encrypted content across restarts, the key encryption key is
  # enough to read it again.
  keep: true
  encryption:
    enable: true
    kms:
      # The provider of the key encryption key: file, awsKms, gcpKms,
      # azureKeyVault or vaultTransit, see below.
      provider: file
      file:
        # The active key encryption key: 32 raw bytes, 64 hex characters or
        # standard base64, e.g. a mounted Kubernetes secret.
        keyFile: /etc/dragonfly/kek.key
        # The previous key encryption keys, only used to unwrap the data keys
        # of the tasks created before a rotation.
        previousKeyFiles:
          - /etc/dragonfly/kek-old.key
```

### Key management services

The `kms.provider` selects where the key encryption key lives. The `file`
provider above keeps it on the node. The cloud providers below wrap the data
keys with a key that never leaves the service, so a node holds no key
encryption key at all, and every wrap and unwrap is audited by the service.
The wrapping context (the identity of the file and its layout parameters)
is bound through the encryption context or additional authenticated data of
the service, or by a digest wrapped together with the data key for the
services without one.

A data key is wrapped once per task and unwrapped once per task per dfdaemon
start (or after the task's cipher is evicted), so the request volume to the
service is low, in the order of the task creations.

**AWS KMS** (`awsKms`, requires dfdaemon built with `--features aws-kms`):

```yaml
storage:
  encryption:
    enable: true
    kms:
      provider: awsKms
      awsKms:
        # The id, ARN or alias of a symmetric KMS key.
        keyId: alias/dragonfly
        # Optional, defaults to the region of the environment.
        region: us-east-1
        # Optional, e.g. a VPC endpoint.
        endpoint: https://vpce-xxx.kms.us-east-1.vpce.amazonaws.com
```

The credentials come from the default credential chain: the environment,
the shared configuration, the web identity of an EKS service account (IRSA
or Pod Identity) or the instance metadata. The identity needs `kms:Encrypt`
and `kms:Decrypt` on the key. The context is bound as the encryption context
`dragonfly:context`, which appears in CloudTrail.

**Google Cloud KMS** (`gcpKms`):

```yaml
storage:
  encryption:
    enable: true
    kms:
      provider: gcpKms
      gcpKms:
        keyName: projects/my-project/locations/global/keyRings/dragonfly/cryptoKeys/content
        # Optional, defaults to GOOGLE_APPLICATION_CREDENTIALS, then the
        # metadata server (GCE, GKE workload identity).
        credentialsFile: /etc/dragonfly/gcp-sa.json
```

The identity needs the `cloudkms.cryptoKeyVersions.useToEncrypt` and
`useToDecrypt` permissions on the key (the Cloud KMS CryptoKey
Encrypter/Decrypter role). The context is bound as the additional
authenticated data.

**Azure Key Vault and Managed HSM** (`azureKeyVault`):

```yaml
storage:
  encryption:
    enable: true
    kms:
      provider: azureKeyVault
      azureKeyVault:
        vaultUrl: https://my-vault.vault.azure.net
        keyName: dragonfly
        # Optional, defaults to the latest version for new tasks.
        keyVersion: ""
        # RSA-OAEP-256 (default), RSA-OAEP, RSA1_5, or A128KW, A192KW,
        # A256KW for the symmetric keys of a managed HSM.
        algorithm: RSA-OAEP-256
        # Optional, default to AZURE_AUTHORITY_HOST, AZURE_TENANT_ID,
        # AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and AZURE_FEDERATED_TOKEN_FILE.
        authorityHost: https://login.microsoftonline.com
        tenantId: ""
        clientId: ""
        clientSecretFile: ""
        federatedTokenFile: ""
```

The credentials come, in this order, from the workload identity (a
federated token file, as injected by the AKS workload identity webhook),
the client secret, or the managed identity of the virtual machine or the
pod. The identity needs the `wrapKey` and `unwrapKey` key permissions. The
service has no associated data for key wrapping, so the digest of the
context is wrapped together with the data key and verified on unwrap.

**HashiCorp Vault transit** (`vaultTransit`):

```yaml
storage:
  encryption:
    enable: true
    kms:
      provider: vaultTransit
      vaultTransit:
        # Optional, defaults to VAULT_ADDR.
        address: https://vault.example.com:8200
        # Optional, defaults to VAULT_NAMESPACE.
        namespace: ""
        mount: transit
        keyName: dragonfly
        # A static token, or the Kubernetes auth method with the service
        # account token of the pod. Defaults to VAULT_TOKEN.
        tokenFile: ""
        kubernetesAuthMount: kubernetes
        kubernetesRole: dragonfly
        kubernetesJwtFile: /var/run/secrets/kubernetes.io/serviceaccount/token
```

The token needs the `update` capability on `transit/encrypt/dragonfly` and
`transit/decrypt/dragonfly`. Like for Azure, the digest of the context is
wrapped together with the data key. The Vault key versions are handled by
Vault: after `vault write -f transit/keys/dragonfly/rotate`, new tasks use
the new version and the old ones stay readable until `min_decryption_version`
excludes their version.

With every cloud provider, the file header of a task names the key version
that wrapped its data key, but the unwrap always goes to the configured key
of the configured service, so a header edited on disk cannot redirect the
credentials or the request to another key or another endpoint.

A key encryption key for the `file` provider is generated with, for example:

```shell
head -c 32 /dev/urandom | base64 > /etc/dragonfly/kek.key
chmod 0400 /etc/dragonfly/kek.key
```

dfdaemon refuses to start when the encryption is enabled and the active key
file is missing or invalid. The hex and base64 forms are decoded in constant
time, so the decoding does not leak the key through timing.

### Key rotation

1. Generate a new key and configure it as `keyFile`, moving the old key to
   `previousKeyFiles`.
2. Restart dfdaemon. New tasks are wrapped with the new key, and the existing
   tasks stay readable with the old key.
3. Once the tasks created before the rotation are garbage collected (see the
   `gc.policy` TTLs) or re-downloaded, remove the old key from
   `previousKeyFiles`.

### Enabling, disabling or losing the key

At startup, dfdaemon checks the kept tasks against the encryption
configuration and deletes the tasks whose content on disk is unusable: the
plaintext tasks when the encryption is enabled, the encrypted tasks when it is
disabled, and the encrypted tasks whose key encryption key is no longer
available. The deleted tasks are downloaded again on demand.

## Behavior changes with encryption enabled

- **Hard links are refused.** A hard link between the cache and an output path
  would expose the ciphertext (or import a plaintext file into the encrypted
  cache), so dfdaemon copies the decrypted content to the output path instead.
  Download requests with `force_hard_link: true` fail. Importing a local file
  as a persistent task reads it piece by piece instead of linking it.
- **Zero-copy uploads are disabled.** Pieces served over TCP are decrypted in
  user space instead of being sent with `sendfile`, and the pieces served over
  QUIC or gRPC are decrypted the same way.
- **CPU usage.** AES-256-GCM is hardware accelerated on most platforms (AES-NI,
  ARMv8 crypto extensions) through aws-lc-rs, the encryption and decryption
  run on the blocking thread pool and overlap the network I/O.

## Threat model

Encryption at rest defends against offline access to the disk: disk theft,
snapshots and backups of volumes, improper disposal, or another tenant
reading a shared or re-provisioned disk. It does not defend against an
attacker with code execution as the dfdaemon user or root on a running node,
who can read the key encryption key, the unwrapped data keys in memory, or
simply request the plaintext through the dfdaemon APIs. Protect the key file
with file permissions and a secret manager, and the dfdaemon APIs with mTLS.
