# vault-ceremony

A command-line tool for the ceremonies of a HashiCorp Vault cluster whose keys are held by people: unsealing, generating a root token, replacing the keys, restoring. Each key is OpenPGP-encrypted to its holder. vault-ceremony never decrypts: holders do, with their own tool, between two vault-ceremony commands.

## Usage

### Status

Anyone, at any step:

```bash
$ vault-ceremony status --as <your name>
```

It shows what you do next, as the command to run, with your own decryption in place of `<decrypt>`:

```
$ vault-ceremony status --as bob
NODE          ADDRESS                   SEAL    INITIALIZED  SEALED  HA       VERSION
foundation-0  https://172.28.0.10:8200  shamir  true         false   active   2.1.1
foundation-1  https://172.28.0.11:8200  shamir  true         false   standby  2.1.1
foundation-2  https://172.28.0.12:8200  shamir  true         false   standby  2.1.1

bob: Root token generation for alice, 1 of 3 approvals so far.
  vault-ceremony key --as bob | <decrypt> | vault-ceremony approve --nonce 7bafe722-a338-3187-383f-0e8ee1f3e1d6 --as bob
```

Without `--as`, it shows everyone's next step.

### Holders

1. When asked: pull the cluster's repository, log in with `vault login` (or have an operator log in, in your shell), run `vault-ceremony status --as <your name>`, and run the command it shows, with your own decryption in place of `<decrypt>`, for example `gpg -d`:

   ```bash
   $ vault-ceremony key --as bob | gpg -d | vault-ceremony approve --nonce <nonce> --as bob
   ```

2. If the command says `state/` changed: commit and push.

Before using your key, `approve` says what you are approving: who will get the root token, or who will get the new keys. Check that it is what the coordinator announced. It refuses anything that would go to someone outside the cluster.

### Coordinator

The first time, once the nodes are running with TLS from your CA:

```bash
$ vault-ceremony init
```

Then `status` takes the holders through unsealing and bootstrap.

Later:

| To | Run | Then |
|---|---|---|
| Get a root token for someone | `vault-ceremony generate-root --for <name>` | Holders approve; `<name>` decrypts `vault-ceremony root-token` |
| Replace the keys, or a holder | Edit `holders` in `ceremony.yaml`; `vault-ceremony rekey` | Current holders approve; new holders approve |
| Abandon either | `vault-ceremony cancel --nonce <nonce>` | |
| Restore a snapshot | `vault-ceremony restore --snapshot <file> --shares <file>`, with only the first node running | Restart that node; under Shamir, holders unseal |

Tell the holders the nonce that `generate-root` or `rekey` prints: they approve only that one.

## Requirements

- Vault 2.x with integrated storage (Raft)
- For generating a root token and rekeying, a Vault token from `vault login`, as well as the keys
- For each holder, an OpenPGP tool that can decrypt with their key

The cluster's repository layout, `ceremony.yaml`, and every command are in the [reference](docs/reference.md).

## License

This project is licensed under the [MIT License](./LICENSE).
