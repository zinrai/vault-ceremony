// Package pgp handles only what needs no private key: public keys and
// ciphertext. Decrypting is the holder's, with whatever OpenPGP tool and
// hardware they use, not this tool's to choose.
package pgp

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func readKey(pubkeyFile string) (*openpgp.Entity, error) {
	f, err := os.Open(pubkeyFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	keys, err := openpgp.ReadKeyRing(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pubkeyFile, err)
	}
	if len(keys) != 1 {
		return nil, fmt.Errorf("%s: %d keys, want one", pubkeyFile, len(keys))
	}
	return keys[0], nil
}

// The primary key's, not the encryption subkey's: that is the fingerprint
// Vault reports for the keys it encrypts to.
func Fingerprint(pubkeyFile string) (string, error) {
	e, err := readKey(pubkeyFile)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(e.PrimaryKey.Fingerprint), nil
}

func EncryptTo(pubkeyFile string, plaintext []byte) ([]byte, error) {
	e, err := readKey(pubkeyFile)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	aw, err := armor.Encode(&out, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}
	w, err := openpgp.Encrypt(aw, []*openpgp.Entity{e}, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	return append(out.Bytes(), '\n'), nil
}

// Armored, not the raw bytes Vault returns: every OpenPGP tool reads it
// from a pipe, and a terminal can show it.
func Armor(base64Message string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(base64Message)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	aw, err := armor.Encode(&out, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}
	if _, err := aw.Write(raw); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	return append(out.Bytes(), '\n'), nil
}

func VaultKey(pubkeyFile string) (string, error) {
	b, err := os.ReadFile(pubkeyFile)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
