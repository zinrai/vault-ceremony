package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zinrai/vault-ceremony/internal/config"
	"github.com/zinrai/vault-ceremony/internal/pgp"
	"github.com/zinrai/vault-ceremony/internal/shares"
	"github.com/zinrai/vault-ceremony/internal/vault"
	"github.com/zinrai/vault-ceremony/internal/workspace"
)

// No secrets engines or AppRoles: bootstrap does only what it takes for
// operators to log in as themselves. The rest they do with the vault CLI,
// under audit and under their own names.
func runBootstrap(args []string) error {
	fs := newFlags("bootstrap --as <name>", "As the root-token holder, with the initial root token on stdin: enable audit,\nwrite policies/, create the operators of ceremony.yaml, then revoke the token.\nSafe to run again if it fails part way: the token stays valid until the end.\n\n  vault-ceremony initial-root-token --as <name> | <decrypt> | vault-ceremony bootstrap --as <name>")
	as := asFlag(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("as", *as); err != nil {
		return err
	}
	cfg, a, err := openActive()
	if err != nil {
		return err
	}
	set, err := shares.Load(workspace.SharesFile)
	if err != nil {
		return err
	}
	if set.RootToken == nil {
		return errors.New("no initial root token: bootstrap has already run. Use generate-root for a new root token")
	}
	if set.RootToken.Holder != *as {
		return fmt.Errorf("the initial root token is encrypted to %s, not %s", set.RootToken.Holder, *as)
	}
	token, err := readPlaintext("initial root token")
	if err != nil {
		return err
	}
	c := a.WithToken(token)

	for _, step := range []func(*config.Config, *vault.Client) error{enableAudit, writePolicies, createOperators} {
		if err := step(cfg, c); err != nil {
			return fmt.Errorf("%w\nThe initial root token is still valid; fix the cause and run bootstrap again", err)
		}
	}
	if err := c.RevokeSelf(); err != nil {
		return fmt.Errorf("revoke the initial root token: %w", err)
	}
	set.RootToken = nil
	if err := set.Save(workspace.SharesFile); err != nil {
		return err
	}
	fmt.Printf("\nInitial root token revoked. There is no root token.\n")
	shareState()
	fmt.Printf("Operators: decrypt %s/<name>.asc, log in with userpass, change the password.\n", workspace.PasswordDir)
	return nil
}

func enableAudit(cfg *config.Config, c *vault.Client) error {
	have, err := c.AuditDevices()
	if err != nil {
		return err
	}
	for _, a := range cfg.Audits {
		if _, ok := have[a.Path]; ok {
			continue
		}
		if err := c.EnableAudit(a.Path, a.Type, a.Options); err != nil {
			return err
		}
		fmt.Printf("audit %s: enabled (%s)\n", a.Path, a.Type)
	}
	return nil
}

func writePolicies(_ *config.Config, c *vault.Client) error {
	files, err := filepath.Glob(filepath.Join(workspace.PolicyDir, "*.hcl"))
	if err != nil {
		return err
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(filepath.Base(f), ".hcl")
		if err := c.WritePolicy(name, string(b)); err != nil {
			return err
		}
		fmt.Printf("policy %s: written\n", name)
	}
	return nil
}

// An identity entity, not only a userpass user: audit records then name
// the person. The password is encrypted before the user exists, not after:
// a password nobody can read would lock them out.
func createOperators(cfg *config.Config, c *vault.Client) error {
	if len(cfg.Operators) == 0 {
		return nil
	}
	accessor, err := userpassAccessor(c)
	if err != nil {
		return err
	}
	for _, op := range cfg.Operators {
		if err := createOperator(c, op, accessor, workspace.PubkeyFile(op.Name)); err != nil {
			return fmt.Errorf("operator %s: %w", op.Name, err)
		}
	}
	return nil
}

func userpassAccessor(c *vault.Client) (string, error) {
	auths, err := c.AuthMethods()
	if err != nil {
		return "", err
	}
	if _, ok := auths["userpass"]; ok {
		return auths["userpass"].Accessor, nil
	}
	if err := c.EnableAuth("userpass", "userpass"); err != nil {
		return "", err
	}
	if auths, err = c.AuthMethods(); err != nil {
		return "", err
	}
	return auths["userpass"].Accessor, nil
}

func createOperator(c *vault.Client, op config.Operator, accessor, pubkey string) error {
	id, err := c.WriteEntity(op.Name, op.Policies)
	if err != nil {
		return err
	}
	if err := c.EnsureEntityAlias(op.Name, id, accessor); err != nil {
		return err
	}
	exists, err := c.UserpassUserExists(op.Name)
	if err != nil || exists {
		return err
	}
	password, err := randomPassword()
	if err != nil {
		return err
	}
	sealed, err := pgp.EncryptTo(pubkey, []byte(password+"\n"))
	if err != nil {
		return err
	}
	out := filepath.Join(workspace.PasswordDir, op.Name+".asc")
	if err := workspace.WriteFile(out, sealed, 0o600); err != nil {
		return err
	}
	if err := c.CreateUserpassUser(op.Name, password); err != nil {
		return err
	}
	fmt.Printf("operator %s: created (%s), password encrypted to %s\n", op.Name, strings.Join(op.Policies, ","), out)
	return nil
}

func randomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
