package vault

import "fmt"

// A hint, not only the 403: since Vault 2.0 these endpoints want a token as
// well as the keys, and a holder who is not an operator will not know that.
func ceremonyErr(err error) error {
	if IsStatus(err, 403) {
		return fmt.Errorf("%w\nCeremonies need a Vault token with update on sys/generate-root/* and sys/rekey*/*:\nan operator logs in with vault login, in the shell where this runs", err)
	}
	return err
}

func (c *Client) ceremony(method, path string, in, out any) error {
	return ceremonyErr(c.Do(method, path, in, out))
}

type GenerateRoot struct {
	Started        bool   `json:"started"`
	Nonce          string `json:"nonce"`
	Progress       int    `json:"progress"`
	Required       int    `json:"required"`
	Complete       bool   `json:"complete"`
	EncodedToken   string `json:"encoded_token"`
	PGPFingerprint string `json:"pgp_fingerprint"`
}

func (c *Client) GenerateRootStatus() (*GenerateRoot, error) {
	var r GenerateRoot
	return &r, c.ceremony("GET", "sys/generate-root/attempt", nil, &r)
}

// A PGP key, not an OTP: holders can then see who the token is for before
// they approve, and nobody has a secret to keep in the meantime.
func (c *Client) GenerateRootStart(pgpKey string) (*GenerateRoot, error) {
	var r GenerateRoot
	return &r, c.ceremony("PUT", "sys/generate-root/attempt", map[string]string{"pgp_key": pgpKey}, &r)
}

func (c *Client) GenerateRootUpdate(nonce, key string) (*GenerateRoot, error) {
	var r GenerateRoot
	return &r, c.ceremony("PUT", "sys/generate-root/update", map[string]string{"nonce": nonce, "key": key}, &r)
}

func (c *Client) GenerateRootCancel() error {
	return c.ceremony("DELETE", "sys/generate-root/attempt", nil, nil)
}

type RekeyRequest struct {
	SecretShares        int      `json:"secret_shares"`
	SecretThreshold     int      `json:"secret_threshold"`
	PGPKeys             []string `json:"pgp_keys"`
	RequireVerification bool     `json:"require_verification"`
}

type Rekey struct {
	Started           bool     `json:"started"`
	Nonce             string   `json:"nonce"`
	T                 int      `json:"t"`
	Progress          int      `json:"progress"`
	Required          int      `json:"required"`
	PGPFingerprints   []string `json:"pgp_fingerprints"`
	Complete          bool     `json:"complete"`
	KeysB64           []string `json:"keys_base64"`
	VerificationNonce string   `json:"verification_nonce"`
}

func rekeyPath(recovery bool, op string) string {
	if recovery {
		return "sys/rekey-recovery-key/" + op
	}
	return "sys/rekey/" + op
}

func (c *Client) RekeyStatus(recovery bool) (*Rekey, error) {
	var r Rekey
	return &r, c.ceremony("GET", rekeyPath(recovery, "init"), nil, &r)
}

func (c *Client) RekeyStart(recovery bool, req RekeyRequest) (*Rekey, error) {
	var r Rekey
	return &r, c.ceremony("PUT", rekeyPath(recovery, "init"), req, &r)
}

func (c *Client) RekeyUpdate(recovery bool, nonce, key string) (*Rekey, error) {
	var r Rekey
	return &r, c.ceremony("PUT", rekeyPath(recovery, "update"), map[string]string{"nonce": nonce, "key": key}, &r)
}

// The rekey's nonce, not the verification's: Vault refuses to cancel
// without the one it handed out at init.
func (c *Client) RekeyCancel(recovery bool, nonce string) error {
	return c.ceremony("DELETE", rekeyPath(recovery, "init"), map[string]string{"nonce": nonce}, nil)
}

type RekeyVerify struct {
	Started  bool   `json:"started"`
	Nonce    string `json:"nonce"`
	T        int    `json:"t"`
	Progress int    `json:"progress"`
	Complete bool   `json:"complete"`
}

func (c *Client) RekeyVerifyStatus(recovery bool) (*RekeyVerify, error) {
	var r RekeyVerify
	return &r, c.ceremony("GET", rekeyPath(recovery, "verify"), nil, &r)
}

func (c *Client) RekeyVerifyUpdate(recovery bool, nonce, key string) (*RekeyVerify, error) {
	var r RekeyVerify
	return &r, c.ceremony("PUT", rekeyPath(recovery, "verify"), map[string]string{"nonce": nonce, "key": key}, &r)
}
