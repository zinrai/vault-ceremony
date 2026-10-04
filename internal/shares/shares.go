// Package shares records which holder got which share, rather than relying
// on the order of holders in ceremony.yaml, which may have changed since.
package shares

import (
	"fmt"
	"time"

	"github.com/zinrai/vault-ceremony/internal/pgp"
	"github.com/zinrai/vault-ceremony/internal/workspace"
)

type Share struct {
	Holder     string `json:"holder"`
	Ciphertext string `json:"ciphertext"`
}

// Armored ciphertext, never plaintext: the holder decrypts it outside this
// tool, and the plaintext comes back on a pipe.
func (s Share) Armored() ([]byte, error) {
	return pgp.Armor(s.Ciphertext)
}

// Kind is recorded, not inferred from the cluster: a holder must know
// whether their share unseals a node or only recovers one.
type Kind string

const (
	Unseal   Kind = "unseal"
	Recovery Kind = "recovery"
)

func KindOf(recovery bool) Kind {
	if recovery {
		return Recovery
	}
	return Unseal
}

type Set struct {
	Kind              Kind      `json:"kind"`
	Created           time.Time `json:"created"`
	Threshold         int       `json:"threshold"`
	Shares            []Share   `json:"shares"`
	RootToken         *Share    `json:"root_token,omitempty"`
	VerificationNonce string    `json:"verification_nonce,omitempty"`
}

func New(kind Kind, threshold int, holders, ciphertexts []string) (*Set, error) {
	if len(holders) != len(ciphertexts) {
		return nil, fmt.Errorf("vault returned %d shares for %d holders", len(ciphertexts), len(holders))
	}
	s := &Set{Kind: kind, Created: time.Now().UTC(), Threshold: threshold}
	for i, h := range holders {
		s.Shares = append(s.Shares, Share{Holder: h, Ciphertext: ciphertexts[i]})
	}
	return s, nil
}

func Load(path string) (*Set, error) {
	var s Set
	if err := workspace.ReadJSON(path, &s); err != nil {
		return nil, err
	}
	if len(s.Shares) == 0 || s.Threshold < 1 {
		return nil, fmt.Errorf("%s: no shares", path)
	}
	return &s, nil
}

func (s *Set) Save(path string) error { return workspace.WriteJSON(path, s) }

func (s *Set) Holders() []string {
	var names []string
	for _, sh := range s.Shares {
		names = append(names, sh.Holder)
	}
	return names
}

func (s *Set) Of(holder string) (Share, error) {
	for _, sh := range s.Shares {
		if sh.Holder == holder {
			return sh, nil
		}
	}
	return Share{}, fmt.Errorf("%s holds no share in this set", holder)
}
