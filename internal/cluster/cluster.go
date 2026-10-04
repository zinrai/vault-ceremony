package cluster

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/zinrai/vault-ceremony/internal/config"
	"github.com/zinrai/vault-ceremony/internal/vault"
)

type Node struct {
	config.Node
	*vault.Client
}

// Only the root CA in caFile, not the system pool: no public CA may vouch
// for a node. The token goes to every request, not only to ceremonies:
// Vault ignores it where none is needed, even when it has expired.
func Connect(cfg *config.Config, caFile, token string) ([]Node, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("root CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no certificate", caFile)
	}
	var nodes []Node
	for _, n := range cfg.Nodes {
		nodes = append(nodes, Node{n, vault.New(n.APIAddr(), pool).WithToken(token)})
	}
	return nodes, nil
}

func Pick(nodes []Node, name string) ([]Node, error) {
	if name == "all" {
		return nodes, nil
	}
	for _, n := range nodes {
		if n.Name == name {
			return []Node{n}, nil
		}
	}
	return nil, fmt.Errorf("unknown node %q", name)
}

func Active(nodes []Node) (Node, error) {
	for _, n := range nodes {
		l, err := n.Leader()
		if err != nil {
			continue
		}
		if l.IsSelf {
			return n, nil
		}
		if m, ok := byAddr(nodes, l.LeaderAddress); ok {
			return m, nil
		}
	}
	return Node{}, errors.New("no active node; is the cluster unsealed?")
}

func byAddr(nodes []Node, addr string) (Node, bool) {
	for _, n := range nodes {
		if addr != "" && n.APIAddr() == addr {
			return n, true
		}
	}
	return Node{}, false
}

// Not a retry for the user: only for a command whose next step cannot run
// until n is active.
func WaitActive(n Node, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if l, err := n.Leader(); err == nil && l.IsSelf {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not become active within %s", n.Name, timeout)
		}
		time.Sleep(time.Second)
	}
}
