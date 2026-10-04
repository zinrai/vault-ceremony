package main

import (
	"fmt"

	"github.com/zinrai/vault-ceremony/internal/cluster"
	"github.com/zinrai/vault-ceremony/internal/shares"
	"github.com/zinrai/vault-ceremony/internal/workspace"
)

// By nonce, not by kind of ceremony: as with approve, the coordinator names
// the one attempt meant, and nothing else is cancelled by mistake.
func runCancel(args []string) error {
	fs := newFlags("cancel --nonce <nonce>", "Cancel the root token generation or rekey with this nonce.")
	nonce := fs.String("nonce", "", "nonce of the ceremony (required)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("nonce", *nonce); err != nil {
		return err
	}
	_, a, err := openActive()
	if err != nil {
		return err
	}
	current, err := shares.Load(workspace.SharesFile)
	if err != nil {
		return err
	}
	recovery := current.Kind == shares.Recovery
	if rootInProgress(a, *nonce) {
		return cancelRoot(a)
	}
	if rekeyNonce, ok := rekeyInProgress(a, recovery, *nonce); ok {
		return cancelRekey(a, recovery, rekeyNonce)
	}
	return fmt.Errorf("no root token generation or rekey with nonce %s is in progress", *nonce)
}

func rootInProgress(a cluster.Node, nonce string) bool {
	g, err := a.GenerateRootStatus()
	return err == nil && g.Started && g.Nonce == nonce
}

// The rekey's own nonce, not the one given: during verification the
// coordinator names the verification's, which Vault does not take for a
// cancel.
func rekeyInProgress(a cluster.Node, recovery bool, nonce string) (string, bool) {
	r, err := a.RekeyStatus(recovery)
	if err != nil || !r.Started {
		return "", false
	}
	if r.Nonce == nonce {
		return r.Nonce, true
	}
	v, err := a.RekeyVerifyStatus(recovery)
	return r.Nonce, err == nil && v.Started && v.Nonce == nonce
}

func cancelRoot(a cluster.Node) error {
	if err := a.GenerateRootCancel(); err != nil {
		return err
	}
	fmt.Println("Root token generation cancelled.")
	return nil
}

func cancelRekey(a cluster.Node, recovery bool, nonce string) error {
	if err := a.RekeyCancel(recovery, nonce); err != nil {
		return err
	}
	fmt.Println("Rekey cancelled; the current keys remain valid.")
	if !workspace.Exists(workspace.PendingFile) {
		return nil
	}
	if err := workspace.Remove(workspace.PendingFile); err != nil {
		return err
	}
	shareState()
	return nil
}
