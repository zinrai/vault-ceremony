package main

import (
	"fmt"

	"github.com/zinrai/vault-ceremony/internal/pgp"
	"github.com/zinrai/vault-ceremony/internal/workspace"
)

func runGenerateRoot(args []string) error {
	fs := newFlags("generate-root --for <name>", "Start generating a root token, encrypted to <name>'s key in pubkeys/.")
	forName := fs.String("for", "", "who receives the root token (required)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("for", *forName); err != nil {
		return err
	}
	if workspace.Exists(workspace.RootTokenFile) {
		return fmt.Errorf("%s holds the previous root token: once it is revoked, remove the file and commit", workspace.RootTokenFile)
	}
	_, a, err := openActive()
	if err != nil {
		return err
	}
	key, err := pgp.VaultKey(workspace.PubkeyFile(*forName))
	if err != nil {
		return fmt.Errorf("public key of %s: %w", *forName, err)
	}
	g, err := a.GenerateRootStart(key)
	if err != nil {
		return err
	}
	fmt.Printf("Root token generation for %s started. Nonce: %s\n", *forName, g.Nonce)
	fmt.Printf("Next: %d holders each run\n  vault-ceremony key --as <name> | <decrypt> | vault-ceremony approve --nonce %s --as <name>\n", g.Required, g.Nonce)
	return nil
}
