package workspace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Fixed, not set in ceremony.yaml: every clone of a cluster's repository
// has the same layout, and nobody has to look up where things are.
const (
	ConfigFile = "ceremony.yaml"
	PolicyDir  = "policies"
	CACertFile = "ca/root.crt"
	PubkeyDir  = "pubkeys"

	SharesFile    = "state/shares.json"
	PendingFile   = "state/shares.pending.json"
	RootTokenFile = "state/root-token.json"
	PasswordDir   = "state/passwords"
	ArchiveDir    = "state/archive"
)

func PubkeyFile(name string) string {
	return filepath.Join(PubkeyDir, name+".gpg")
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Rename, not write in place: a crash must not leave a truncated shares
// file, which may be the only copy. Parents 0700, not 0755: most of what
// lands here is for one person's eyes.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func ReadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// 0600, not 0644: shares and OTPs are not for everyone, encrypted or not.
func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(path, append(b, '\n'), 0o600)
}

func Remove(paths ...string) error {
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// Moved aside, never deleted: an old share set still unseals the snapshots
// taken while it was current.
func Archive(path string) (string, error) {
	ext := filepath.Ext(path)
	stamp := time.Now().UTC().Format("20060102T150405Z")
	dst := filepath.Join(ArchiveDir, strings.TrimSuffix(filepath.Base(path), ext)+"-"+stamp+ext)
	if err := os.MkdirAll(ArchiveDir, 0o700); err != nil {
		return "", err
	}
	return dst, os.Rename(path, dst)
}
