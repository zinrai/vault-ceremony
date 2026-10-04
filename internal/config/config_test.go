package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestTheClusterIsReadAsDeclared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ceremony.yaml")
	yaml := `
nodes:
  - {name: vault-0, ip: 172.28.0.10}
  - {name: vault-1, ip: 172.28.0.11}
threshold: 2
holders: [alice, bob, carol]
root_token_holder: bob
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if got := c.Nodes[1].APIAddr(); got != "https://172.28.0.11:8200" {
		t.Errorf("second node is reached at %s", got)
	}
	if !slices.Equal(c.Holders, []string{"alice", "bob", "carol"}) {
		t.Errorf("holders are %v, out of declared order", c.Holders)
	}
	if c.Threshold != 2 {
		t.Errorf("threshold is %d", c.Threshold)
	}
	if c.RootToken != "bob" {
		t.Errorf("the initial root token goes to %q, not the declared holder", c.RootToken)
	}
}
