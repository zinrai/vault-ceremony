package main

import (
	"fmt"
	"strings"

	"github.com/zinrai/vault-ceremony/internal/cluster"
	"github.com/zinrai/vault-ceremony/internal/pubkeys"
	"github.com/zinrai/vault-ceremony/internal/shares"
	"github.com/zinrai/vault-ceremony/internal/vault"
	"github.com/zinrai/vault-ceremony/internal/workspace"
)

// One verb for every ceremony, not one per ceremony: what a holder decides
// is the same each time, whether this nonce, announced by the coordinator,
// should get their key. The nonce is required, not looked up: a key must go
// to the attempt the holder was told of, not to whichever one is running.
func runApprove(args []string) error {
	fs := newFlags("approve --nonce <nonce> --as <name>", "Approve the root token generation or rekey with this nonce, using your key.\nRefused if the result would go to anyone outside pubkeys/.")
	as := asFlag(fs)
	nonceFlag := fs.String("nonce", "", "nonce announced by the coordinator (required)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("nonce", *nonceFlag); err != nil {
		return err
	}
	if err := required("as", *as); err != nil {
		return err
	}
	nonce := *nonceFlag
	cfg, a, err := openActive()
	if err != nil {
		return err
	}
	ppl, err := people(cfg)
	if err != nil {
		return err
	}
	current, err := shares.Load(workspace.SharesFile)
	if err != nil {
		return err
	}
	recovery := current.Kind == shares.Recovery

	g, err := a.GenerateRootStatus()
	if err != nil && vault.IsStatus(err, 403) {
		return err
	}
	if err == nil && g.Started && g.Nonce == nonce {
		if _, err := current.Of(*as); err != nil {
			return err
		}
		return approveRoot(a, ppl, g, *as)
	}
	if r, err := a.RekeyStatus(recovery); err == nil && r.Started && r.Nonce == nonce {
		if _, err := current.Of(*as); err != nil {
			return err
		}
		return approveRekey(a, ppl, r, current.Kind, *as)
	}
	if v, err := a.RekeyVerifyStatus(recovery); err == nil && v.Started && v.Nonce == nonce {
		return approveVerification(a, recovery, nonce, *as)
	}
	return fmt.Errorf("no root token generation or rekey with nonce %s is in progress", nonce)
}

func approveRoot(a cluster.Node, ppl pubkeys.People, g *vault.GenerateRoot, as string) error {
	if g.PGPFingerprint == "" {
		return fmt.Errorf("refusing: generation %s was started without a PGP key, so whoever started it would get the root token. Cancel it: vault-ceremony cancel --nonce %s", g.Nonce, g.Nonce)
	}
	to, err := ppl.Name(g.PGPFingerprint)
	if err != nil {
		return fmt.Errorf("refusing: %w. Cancel it: vault-ceremony cancel --nonce %s", err, g.Nonce)
	}
	fmt.Printf("Root token generation %s: the token will be encrypted to %s.\n", g.Nonce, to)
	key, err := readPlaintext("key")
	if err != nil {
		return err
	}
	u, err := a.GenerateRootUpdate(g.Nonce, key)
	if err != nil {
		return err
	}
	if !u.Complete {
		fmt.Printf("Approved, %d/%d.\n", u.Progress, u.Required)
		return nil
	}
	if err := workspace.WriteJSON(workspace.RootTokenFile, shares.Share{Holder: to, Ciphertext: u.EncodedToken}); err != nil {
		return err
	}
	fmt.Printf("Approved; the root token is in %s, encrypted to %s.\n", workspace.RootTokenFile, to)
	fmt.Printf("Next: %s runs  vault-ceremony root-token --as %s | <decrypt>\n", to, to)
	shareState()
	return nil
}

func approveRekey(a cluster.Node, ppl pubkeys.People, r *vault.Rekey, kind shares.Kind, as string) error {
	names, err := ppl.Names(r.PGPFingerprints)
	if err != nil {
		return fmt.Errorf("refusing: %w. Cancel it: vault-ceremony cancel --nonce %s", err, r.Nonce)
	}
	fmt.Printf("Rekey %s: new %s keys for %s, threshold %d.\n", r.Nonce, kind, strings.Join(names, ", "), r.T)
	key, err := readPlaintext("key")
	if err != nil {
		return err
	}
	u, err := a.RekeyUpdate(kind == shares.Recovery, r.Nonce, key)
	if err != nil {
		return err
	}
	if !u.Complete {
		fmt.Printf("Approved, %d/%d.\n", u.Progress, u.Required)
		return nil
	}
	pending, err := shares.New(kind, r.T, names, u.KeysB64)
	if err != nil {
		return err
	}
	pending.VerificationNonce = u.VerificationNonce
	if err := pending.Save(workspace.PendingFile); err != nil {
		return err
	}
	fmt.Printf("Approved; the new keys are in %s.\n", workspace.PendingFile)
	fmt.Printf("Next: %d new holders each prove their new key:\n  vault-ceremony key --nonce %s --as <name> | <decrypt> | vault-ceremony approve --nonce %s --as <name>\n", r.T, u.VerificationNonce, u.VerificationNonce)
	shareState()
	return nil
}

func approveVerification(a cluster.Node, recovery bool, nonce, as string) error {
	pending, err := shares.Load(workspace.PendingFile)
	if err != nil {
		return fmt.Errorf("%w (not pulled yet?)", err)
	}
	if pending.VerificationNonce != nonce {
		return fmt.Errorf("%s is for another rekey; pull, and check the nonce", workspace.PendingFile)
	}
	fmt.Printf("Rekey verification %s: proving you can decrypt your new %s key.\n", nonce, pending.Kind)
	if _, err := pending.Of(as); err != nil {
		return err
	}
	key, err := readPlaintext("new key")
	if err != nil {
		return err
	}
	r, err := a.RekeyVerifyUpdate(recovery, nonce, key)
	if err != nil {
		return err
	}
	if !r.Complete {
		if v, err := a.RekeyVerifyStatus(recovery); err == nil {
			fmt.Printf("Verified, %d/%d.\n", v.Progress, v.T)
		}
		return nil
	}

	return promotePending(pending)
}

func promotePending(pending *shares.Set) error {
	old, err := workspace.Archive(workspace.SharesFile)
	if err != nil {
		return err
	}
	pending.VerificationNonce = ""
	if err := pending.Save(workspace.SharesFile); err != nil {
		return err
	}
	if err := workspace.Remove(workspace.PendingFile); err != nil {
		return err
	}
	fmt.Printf("Rekey complete. %s now holds the new %s keys:\n", workspace.SharesFile, pending.Kind)
	for i, s := range pending.Shares {
		fmt.Printf("  %s key %d -> %s\n", pending.Kind, i+1, s.Holder)
	}
	fmt.Printf("The previous keys (%s) no longer work on this cluster,\nbut still belong to snapshots taken before now.\n", old)
	shareState()
	return nil
}
