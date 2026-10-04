# vault-ceremony Reference

## Requirements

- Vault 2.x with integrated storage (Raft)
- A Vault token for `generate-root`, `rekey`, `approve`, `cancel`, and for `status` to show ceremonies in progress: `VAULT_TOKEN`, or the one `vault login` saved in `~/.vault-token`. It needs `read` and `update` on `sys/generate-root/*` and on `sys/rekey/*` or `sys/rekey-recovery-key/*`. `init`, `unseal`, `key`, `bootstrap` and `restore` need none
- For each holder, an OpenPGP tool that decrypts with their key (`gpg`, `sq`, or a hardware token through either). vault-ceremony itself never decrypts

## Files

vault-ceremony runs from the root of the cluster's repository, which every holder and the coordinator have a clone of:

| Path | Contents | Committed |
|---|---|---|
| `ceremony.yaml` | The cluster | yes |
| `policies/*.hcl` | ACL policies written by bootstrap, named after the file | yes |
| `pubkeys/<name>.gpg` | Binary OpenPGP public key of every holder and operator | yes |
| `ca/root.crt` | The CA certificate the nodes' TLS certificates chain to | yes |
| `state/shares.json` | Encrypted keys, their kind (unseal or recovery), and which holder has which | yes |
| `state/shares.pending.json` | New keys of a rekey awaiting verification | yes |
| `state/root-token.json` | A generated root token, encrypted to the person it is for | yes |
| `state/archive/` | Key sets replaced by rekey or restore | yes |
| `state/passwords/<name>.asc` | Encrypted initial operator passwords | yes |

### Sharing State

Pull before each step of a ceremony. A command that changes `state/` says so; commit and push the change before the next person's step.

| Step | Changes `state/` |
|---|---|
| `init`, `restore` | coordinator |
| `bootstrap` | root-token holder |
| `approve` that completes a root token generation or a rekey step | the last holder to approve |
| removing `state/root-token.json` once the token is revoked | the person the token is for |
| `cancel` of a rekey awaiting verification | coordinator |

### ceremony.yaml

```yaml
nodes:
  - name: vault-0
    ip: 172.28.0.10              # API on :8200, cluster on :8201
  - name: vault-1
    ip: 172.28.0.11
  - name: vault-2
    ip: 172.28.0.12

threshold: 3
holders: [alice, bob, carol, safe-hq, safe-dc2]   # key n goes to the n-th holder
root_token_holder: alice         # receives the initial root token; one of the holders

operators:                       # created by bootstrap
  - name: alice
    policies: [admin]

audit:                           # enabled by bootstrap
  - path: file
    type: file
    options: {file_path: /vault/logs/audit.log}
```

## Commands

Every command is one verb followed by flags. `--as` is who runs it, `--for` who receives a result, `--nonce` which ceremony, `--node` which node.

Holders run `key`, `unseal`, `approve`, `initial-root-token`, `bootstrap` and `root-token` as themselves (`--as <name>`). The coordinator runs the rest. `status` shows who does what next, and `version` prints the version.

What is encrypted to a holder comes out of `key`, `initial-root-token` or `root-token` as an armored OpenPGP message. The holder decrypts it with their own tool, written `<decrypt>` below, and pipes the plaintext into the command that needs it. The plaintext exists only in the pipe.

### Initialize

Once the nodes are running, with TLS certificates from the CA in `ca/root.crt` for their IPs:

```bash
$ vault-ceremony init
```

### Unseal

Each holder, the leader first, then the followers once they have joined:

```bash
$ vault-ceremony key --as alice | <decrypt> | vault-ceremony unseal --node vault-0 --as alice
$ vault-ceremony key --as alice | <decrypt> | vault-ceremony unseal --as alice
```

A node that is unreachable or has not joined yet is reported; run the command again. Under an auto-unseal seal there is nothing to unseal: the seal does it.

### Bootstrap

```bash
$ vault-ceremony initial-root-token --as alice | <decrypt> | vault-ceremony bootstrap --as alice
```

Run by `root_token_holder`. Enables the audit devices, writes `policies/`, creates a userpass login and identity entity for each operator with an initial password encrypted to `pubkeys/<name>.gpg`, and revokes the root token. If it fails, run it again.

### Status

```bash
$ vault-ceremony status [--as <name>]
```

Seal and HA state of every node, then the next step of whoever has one: the coordinator's from setting up to init, the holders' for unsealing, bootstrap, approvals and decrypting a root token. A root token generation or rekey that would hand its result to someone outside `pubkeys/` is flagged, for holders not to approve and the coordinator to cancel. With `--as`, only that person's steps are shown.

### Generate a Root Token

The coordinator starts it for someone in `pubkeys/`, holders approve with the nonce, and that person decrypts the token:

```bash
$ vault-ceremony generate-root --for alice
$ vault-ceremony key --as <holder> | <decrypt> | vault-ceremony approve --nonce <nonce> --as <holder>
$ vault-ceremony root-token --as alice | <decrypt>
```

Holders approve with unseal keys or recovery keys, whichever the cluster has. `approve` shows who the token is for, and refuses a generation started without a PGP key or for someone outside `pubkeys/`. `cancel --nonce <nonce>` abandons it. The encrypted token stays in `state/root-token.json`; its owner removes the file, and commits, once the token is revoked.

When nobody can log in, the cluster can be opened to a generation without a token, until it is closed again. In every node's configuration, applied with `SIGHUP`:

```hcl
enable_unauthenticated_access = ["generate-root"]
```

While it is open, anyone who can reach the API can cancel the generation. Remove it, and send `SIGHUP` again, once the holders have approved.

### Rekey

Change `holders` in `ceremony.yaml` and add the new public keys, then:

```bash
$ vault-ceremony rekey
$ vault-ceremony key --as <current holder> | <decrypt> | vault-ceremony approve --nonce <nonce> --as <current holder>
$ vault-ceremony key --nonce <verification nonce> --as <new holder> | <decrypt> | vault-ceremony approve --nonce <verification nonce> --as <new holder>
```

Rekeys the unseal keys or the recovery keys, whichever the cluster has. `approve` shows who the new keys are for, and refuses a rekey to anyone outside `pubkeys/`. The last current holder's approval prints the verification nonce; `key` with that nonce prints the new key. The new keys replace `state/shares.json` once `threshold` new holders have approved with them. `cancel --nonce <nonce>` abandons it.

### Restore

Keep each snapshot next to the key set that belongs to it:

```bash
$ vault operator raft snapshot save backup.snap
$ cp state/shares.json backup.shares.json
```

Restore into a first node that has never been initialized, with every other node stopped. Then restart it, unseal it under Shamir, and start the other nodes:

```bash
$ vault-ceremony restore --snapshot backup.snap --shares backup.shares.json
```
