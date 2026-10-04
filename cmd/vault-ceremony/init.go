package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/zinrai/vault-ceremony/internal/cluster"
	"github.com/zinrai/vault-ceremony/internal/config"
	"github.com/zinrai/vault-ceremony/internal/pgp"
	"github.com/zinrai/vault-ceremony/internal/shares"
	"github.com/zinrai/vault-ceremony/internal/vault"
	"github.com/zinrai/vault-ceremony/internal/workspace"
)

func runInit(args []string) error {
	fs := newFlags("init", "Initialize the cluster. Share n is encrypted to the n-th holder in ceremony.yaml,\nthe initial root token to root_token_holder. No plaintext is written.")
	if err := parse(fs, args); err != nil {
		return err
	}
	cfg, nodes, err := open()
	if err != nil {
		return err
	}
	if workspace.Exists(workspace.SharesFile) {
		return fmt.Errorf("%s already exists; move it away to initialize a new cluster", workspace.SharesFile)
	}
	first := nodes[0]
	seal, err := first.SealStatus()
	if err != nil {
		return err
	}
	if seal.Initialized {
		return fmt.Errorf("%s is already initialized", first.Name)
	}
	set, err := initialize(cfg, first, seal.RecoverySeal)
	if err != nil {
		return err
	}
	if err := saveInitial(set); err != nil {
		return err
	}
	printInitialized(cfg, first.Name, seal.Type, set.Kind)
	return nil
}

func initialize(cfg *config.Config, first cluster.Node, recovery bool) (*shares.Set, error) {
	keys, err := holderKeys(cfg, cfg.Holders)
	if err != nil {
		return nil, err
	}
	rootKey, err := pgp.VaultKey(workspace.PubkeyFile(cfg.RootToken))
	if err != nil {
		return nil, err
	}
	req := vault.Shares(recovery, len(cfg.Holders), cfg.Threshold, keys)
	req.RootTokenPGPKey = rootKey
	resp, err := first.Init(req)
	if err != nil {
		return nil, err
	}
	set, err := shares.New(shares.KindOf(recovery), cfg.Threshold, cfg.Holders, resp.Shares(recovery))
	if err != nil {
		return nil, err
	}
	set.RootToken = &shares.Share{Holder: cfg.RootToken, Ciphertext: resp.RootToken}
	return set, nil
}

// Printed rather than lost: the cluster is initialized and this is the only
// copy.
func saveInitial(set *shares.Set) error {
	err := set.Save(workspace.SharesFile)
	if err == nil {
		return nil
	}
	b, _ := json.MarshalIndent(set, "", "  ")
	fmt.Fprintf(os.Stderr, "Could not write %s; the encrypted shares are:\n%s\n", workspace.SharesFile, b)
	return err
}

func printInitialized(cfg *config.Config, node, sealType string, kind shares.Kind) {
	fmt.Printf("Initialized %s (%s seal): %d %s keys, threshold %d. Written to %s:\n",
		node, sealType, len(cfg.Holders), kind, cfg.Threshold, workspace.SharesFile)
	for i, h := range cfg.Holders {
		fmt.Printf("  %s key %d -> %s\n", kind, i+1, h)
	}
	fmt.Printf("  initial root token -> %s\n", cfg.RootToken)
	shareState()
	fmt.Println()
	if kind == shares.Recovery {
		fmt.Printf("The seal unseals every node. Next, %s runs\n  vault-ceremony initial-root-token --as %s | <decrypt> | vault-ceremony bootstrap --as %s\n", cfg.RootToken, cfg.RootToken, cfg.RootToken)
		return
	}
	fmt.Printf("Next: %d holders each run\n  vault-ceremony key --as <name> | <decrypt> | vault-ceremony unseal --as <name>\n", cfg.Threshold)
}

func holderKeys(cfg *config.Config, holders []string) ([]string, error) {
	var keys []string
	for _, h := range holders {
		k, err := pgp.VaultKey(workspace.PubkeyFile(h))
		if err != nil {
			return nil, fmt.Errorf("public key of %s: %w", h, err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}
