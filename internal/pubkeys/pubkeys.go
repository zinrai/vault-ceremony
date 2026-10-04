// Package pubkeys names whoever a ceremony would hand keys or a root token
// to, by the fingerprints Vault reports, rather than trusting whoever
// started it: any operator can start generate-root or rekey, and anyone can
// during break-glass.
package pubkeys

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zinrai/vault-ceremony/internal/pgp"
)

type People map[string]string

func Load(dir string) (People, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.gpg"))
	if err != nil {
		return nil, err
	}
	p := People{}
	for _, f := range files {
		fpr, err := pgp.Fingerprint(f)
		if err != nil {
			return nil, err
		}
		p[fpr] = strings.TrimSuffix(filepath.Base(f), ".gpg")
	}
	return p, nil
}

func (p People) Name(fingerprint string) (string, error) {
	name, ok := p[strings.ToLower(fingerprint)]
	if !ok {
		return "", fmt.Errorf("fingerprint %q is not in pubkeys/: someone outside the cluster would get the result", fingerprint)
	}
	return name, nil
}

// Names keeps Vault's order, not the order of holders in ceremony.yaml:
// key n of a rekey goes to the n-th fingerprint, whatever the file says now.
func (p People) Names(fingerprints []string) ([]string, error) {
	var names []string
	for _, f := range fingerprints {
		n, err := p.Name(f)
		if err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, nil
}
