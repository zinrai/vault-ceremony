package shares

import (
	"path/filepath"
	"testing"
)

func TestEachShareIsRecordedForTheHolderItWasEncryptedTo(t *testing.T) {
	set, err := New(Unseal, 2, []string{"alice", "bob", "carol"}, []string{"for-alice", "for-bob", "for-carol"})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"alice", "bob", "carol"} {
		sh, err := set.Of(h)
		if err != nil {
			t.Fatal(err)
		}
		if sh.Ciphertext != "for-"+h {
			t.Errorf("%s would decrypt %q", h, sh.Ciphertext)
		}
	}
	if _, err := set.Of("mallory"); err == nil {
		t.Error("someone who is not a holder got a share")
	}
	if _, err := New(Unseal, 2, []string{"alice", "bob"}, []string{"one"}); err == nil {
		t.Error("a holder was left without a share")
	}
}

func TestASavedSetComesBackWithEverythingACeremonyNeeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "shares.json")
	set, err := New(Recovery, 2, []string{"alice", "bob"}, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	set.RootToken = &Share{Holder: "alice", Ciphertext: "root"}
	set.VerificationNonce = "nonce"
	if err := set.Save(path); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Threshold != 2 || len(got.Shares) != 2 || got.Shares[1] != (Share{"bob", "b"}) {
		t.Errorf("shares came back as %+v", got)
	}
	if got.RootToken == nil || *got.RootToken != (Share{"alice", "root"}) {
		t.Error("the initial root token was lost: bootstrap could not run")
	}
	if got.Kind != Recovery {
		t.Errorf("recovery keys came back as %q: a rekey would use the wrong endpoint", got.Kind)
	}
	if got.VerificationNonce != "nonce" {
		t.Error("the verification nonce was lost: a rekey could not complete")
	}
}
