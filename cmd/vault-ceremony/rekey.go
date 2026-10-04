package main

import (
	"fmt"

	"github.com/zinrai/vault-ceremony/internal/shares"
	"github.com/zinrai/vault-ceremony/internal/vault"
	"github.com/zinrai/vault-ceremony/internal/workspace"
)

func runRekey(args []string) error {
	fs := newFlags("rekey", "Start replacing every key with new ones for the holders now in ceremony.yaml.\nThe current keys stay valid until enough new holders have verified theirs.")
	if err := parse(fs, args); err != nil {
		return err
	}
	cfg, a, err := openActive()
	if err != nil {
		return err
	}
	current, err := shares.Load(workspace.SharesFile)
	if err != nil {
		return err
	}
	keys, err := holderKeys(cfg, cfg.Holders)
	if err != nil {
		return err
	}
	r, err := a.RekeyStart(current.Kind == shares.Recovery, vault.RekeyRequest{
		SecretShares:        len(cfg.Holders),
		SecretThreshold:     cfg.Threshold,
		PGPKeys:             keys,
		RequireVerification: true,
	})
	if err != nil {
		return err
	}
	fmt.Printf("Rekey of the %s keys started: %d new keys, threshold %d. Nonce: %s\n", current.Kind, len(cfg.Holders), cfg.Threshold, r.Nonce)
	fmt.Printf("Next: %d current holders each run\n  vault-ceremony key --as <name> | <decrypt> | vault-ceremony approve --nonce %s --as <name>\n", current.Threshold, r.Nonce)
	return nil
}
