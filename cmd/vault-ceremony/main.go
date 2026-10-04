// Command vault-ceremony covers only what needs unseal or recovery keys, or
// the initial root token, not what an operator can do with the vault CLI.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/zinrai/vault-ceremony/internal/cluster"
	"github.com/zinrai/vault-ceremony/internal/config"
	"github.com/zinrai/vault-ceremony/internal/pubkeys"
	"github.com/zinrai/vault-ceremony/internal/workspace"
)

type command struct {
	name    string
	summary string
	run     func(args []string) error
}

// By who runs them, not alphabetically: a holder needs two commands, and
// should not have to find them among the coordinator's.
var roles = []struct {
	role     string
	commands []command
}{
	{"Anyone", []command{
		{"status", "show the nodes, any ceremony in progress, and who does what next", runStatus},
		{"version", "print the version and exit", runVersion},
	}},
	{"Holders", []command{
		{"key", "print your encrypted key, to decrypt and pipe into unseal or approve", runKey},
		{"unseal", "unseal nodes with your key, read from stdin", runUnseal},
		{"approve", "approve the root token generation or rekey with --nonce, key from stdin", runApprove},
		{"initial-root-token", "print the initial root token encrypted to you", runInitialRootToken},
		{"bootstrap", "set up with the initial root token from stdin, then revoke it", runBootstrap},
		{"root-token", "print the root token generated for you, encrypted to you", runRootToken},
	}},
	{"Coordinator", []command{
		{"init", "initialize the cluster; every key encrypted to its holder", runInit},
		{"generate-root", "start generating a root token --for someone in pubkeys/", runGenerateRoot},
		{"rekey", "start replacing every unseal or recovery key", runRekey},
		{"cancel", "cancel the root token generation or rekey with --nonce", runCancel},
		{"restore", "restore a snapshot into a node that was never initialized", runRestore},
	}},
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: vault-ceremony <command> [--flag value]...\n")
	for _, r := range roles {
		fmt.Fprintf(os.Stderr, "\n%s:\n", r.role)
		for _, c := range r.commands {
			fmt.Fprintf(os.Stderr, "  %-19s %s\n", c.name, c.summary)
		}
	}
	fmt.Fprintf(os.Stderr, `
Run in the cluster's repository, after pulling it. Holders decrypt with
their own OpenPGP tool, between two commands:  vault-ceremony key --as bob | <decrypt> | vault-ceremony unseal --as bob
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	name := os.Args[1]
	c, ok := find(name)
	if !ok {
		if name != "-h" && name != "--help" && name != "help" {
			fmt.Fprintf(os.Stderr, "vault-ceremony: unknown command %q\n\n", name)
		}
		usage()
		os.Exit(2)
	}
	err := c.run(os.Args[2:])
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault-ceremony %s: %v\n", name, err)
		os.Exit(1)
	}
}

func find(name string) (command, bool) {
	all := allCommands()
	i := slices.IndexFunc(all, func(c command) bool { return c.name == name })
	if i < 0 {
		return command{}, false
	}
	return all[i], true
}

func allCommands() []command {
	var all []command
	for _, r := range roles {
		all = append(all, r.commands...)
	}
	return all
}

func newFlags(name, help string) *flag.FlagSet {
	fs := flag.NewFlagSet("vault-ceremony "+name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: vault-ceremony %s\n\n%s\n", name, help)
		fs.PrintDefaults()
	}
	return fs
}

// Flags only, never a positional argument: every command reads the same
// way, and --as, --for, --nonce and --node always mean the same thing.
func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	return nil
}

func required(name, value string) error {
	if value == "" {
		return fmt.Errorf("--%s is required", name)
	}
	return nil
}

// One name, not a list: one run is one person, as in production. A flag
// only, not also an environment variable: who a command runs as must be
// read off the command itself.
func asFlag(fs *flag.FlagSet) *string {
	return fs.String("as", "", "your name in ceremony.yaml (required)")
}

func open() (*config.Config, []cluster.Node, error) {
	cfg, err := config.Load(workspace.ConfigFile)
	if err != nil {
		return nil, nil, err
	}
	nodes, err := cluster.Connect(cfg, workspace.CACertFile, vaultToken())
	return cfg, nodes, err
}

// The vault CLI's token, not a flag of our own: operators already log in
// with vault login, and a token on a command line ends up in shell history.
// None is fine: init, unseal and restore need none, and with break-glass
// the cluster takes ceremonies without one.
func vaultToken() string {
	if t := os.Getenv("VAULT_TOKEN"); t != "" {
		return t
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(home, ".vault-token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func openActive() (*config.Config, cluster.Node, error) {
	cfg, nodes, err := open()
	if err != nil {
		return nil, cluster.Node{}, err
	}
	a, err := cluster.Active(nodes)
	return cfg, a, err
}

func people(cfg *config.Config) (pubkeys.People, error) {
	return pubkeys.Load(workspace.PubkeyDir)
}

// From stdin, never from a flag or a file: the plaintext then exists only
// in the pipe from the holder's own decryption.
func readPlaintext(what string) (string, error) {
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return "", fmt.Errorf("pipe in your decrypted %s; vault-ceremony status shows how", what)
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("no %s on stdin: did decrypting fail?", what)
	}
	return v, nil
}

// Printed, not run: the tool does not depend on git, and every holder must
// have the same state/ before the next step of a ceremony.
func shareState() {
	fmt.Println("Commit and push the changes in state/, so that every holder has them.")
}

func runVersion(args []string) error {
	if err := parse(newFlags("version", "Print the version and exit."), args); err != nil {
		return err
	}
	printVersion()
	return nil
}
