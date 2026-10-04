package pubkeys

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
)

func generate(t *testing.T, dir, name string) string {
	t.Helper()
	e, err := openpgp.NewEntity(name, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, name+".gpg"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := e.Serialize(f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(e.PrimaryKey.Fingerprint)
}

func TestTheResultOfACeremonyGoesOnlyToPeopleInPubkeys(t *testing.T) {
	dir := t.TempDir()
	alice := generate(t, dir, "alice")
	bob := generate(t, dir, "bob")
	people, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	names, err := people.Names([]string{bob, alice})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"bob", "alice"}) {
		t.Errorf("new keys would go to %v, not in Vault's order [bob alice]", names)
	}
	if _, err := people.Name("0123456789abcdef0123456789abcdef01234567"); err == nil {
		t.Error("a key outside pubkeys/ was accepted")
	}
}
