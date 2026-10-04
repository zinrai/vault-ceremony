package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/zinrai/vault-ceremony/internal/shares"
	"github.com/zinrai/vault-ceremony/internal/workspace"
)

func runKey(args []string) error {
	fs := newFlags("key --as <name> [--nonce <nonce>]", "Print your encrypted key, for you to decrypt and pipe into unseal or approve.\nWith the nonce of a rekey's verification, your new key.")
	as := asFlag(fs)
	nonce := fs.String("nonce", "", "nonce of the ceremony you are approving")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("as", *as); err != nil {
		return err
	}
	path := workspace.SharesFile
	if *nonce != "" {
		if pending, err := shares.Load(workspace.PendingFile); err == nil && pending.VerificationNonce == *nonce {
			path = workspace.PendingFile
		}
	}
	set, err := shares.Load(path)
	if err != nil {
		return err
	}
	sh, err := set.Of(*as)
	if err != nil {
		return err
	}
	return printArmored(sh)
}

func runInitialRootToken(args []string) error {
	fs := newFlags("initial-root-token --as <name>", "Print the initial root token encrypted to you, for you to decrypt and pipe into bootstrap.")
	as := asFlag(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("as", *as); err != nil {
		return err
	}
	set, err := shares.Load(workspace.SharesFile)
	if err != nil {
		return err
	}
	if set.RootToken == nil {
		return errors.New("no initial root token: bootstrap has already revoked it")
	}
	if set.RootToken.Holder != *as {
		return fmt.Errorf("the initial root token is encrypted to %s, not %s", set.RootToken.Holder, *as)
	}
	return printArmored(*set.RootToken)
}

// Printed and kept, not removed once read: if decrypting fails, a root
// token nobody can see would stay valid. Remove it once it is revoked.
func runRootToken(args []string) error {
	fs := newFlags("root-token --as <name>", "Print the generated root token encrypted to you, for you to decrypt.")
	as := asFlag(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("as", *as); err != nil {
		return err
	}
	var rt shares.Share
	if err := workspace.ReadJSON(workspace.RootTokenFile, &rt); err != nil {
		return fmt.Errorf("%w (not enough approvals yet, or not pulled)", err)
	}
	if rt.Holder != *as {
		return fmt.Errorf("the root token is encrypted to %s, not %s", rt.Holder, *as)
	}
	return printArmored(rt)
}

func printArmored(sh shares.Share) error {
	b, err := sh.Armored()
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(b)
	return err
}
