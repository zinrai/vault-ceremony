package vault

type SealStatus struct {
	Type         string `json:"type"`
	RecoverySeal bool   `json:"recovery_seal"`
	Initialized  bool   `json:"initialized"`
	Sealed       bool   `json:"sealed"`
	T            int    `json:"t"`
	N            int    `json:"n"`
	Progress     int    `json:"progress"`
	Version      string `json:"version"`
}

func (c *Client) SealStatus() (*SealStatus, error) {
	var s SealStatus
	return &s, c.Do("GET", "sys/seal-status", nil, &s)
}

func (c *Client) Unseal(key string) (*SealStatus, error) {
	var s SealStatus
	return &s, c.Do("POST", "sys/unseal", map[string]string{"key": key}, &s)
}

type Leader struct {
	IsSelf        bool   `json:"is_self"`
	LeaderAddress string `json:"leader_address"`
}

func (c *Client) Leader() (*Leader, error) {
	var l Leader
	return &l, c.Do("GET", "sys/leader", nil, &l)
}

type InitRequest struct {
	SecretShares      int      `json:"secret_shares,omitempty"`
	SecretThreshold   int      `json:"secret_threshold,omitempty"`
	PGPKeys           []string `json:"pgp_keys,omitempty"`
	RecoveryShares    int      `json:"recovery_shares,omitempty"`
	RecoveryThreshold int      `json:"recovery_threshold,omitempty"`
	RecoveryPGPKeys   []string `json:"recovery_pgp_keys,omitempty"`
	RootTokenPGPKey   string   `json:"root_token_pgp_key,omitempty"`
}

func Shares(recovery bool, n, threshold int, pgpKeys []string) InitRequest {
	if recovery {
		return InitRequest{RecoveryShares: n, RecoveryThreshold: threshold, RecoveryPGPKeys: pgpKeys}
	}
	return InitRequest{SecretShares: n, SecretThreshold: threshold, PGPKeys: pgpKeys}
}

type InitResponse struct {
	KeysB64         []string `json:"keys_base64"`
	RecoveryKeysB64 []string `json:"recovery_keys_base64"`
	RootToken       string   `json:"root_token"`
}

func (r *InitResponse) Shares(recovery bool) []string {
	if recovery {
		return r.RecoveryKeysB64
	}
	return r.KeysB64
}

func (c *Client) Initialized() (bool, error) {
	var r struct {
		Initialized bool `json:"initialized"`
	}
	return r.Initialized, c.Do("GET", "sys/init", nil, &r)
}

func (c *Client) Init(req InitRequest) (*InitResponse, error) {
	var r InitResponse
	return &r, c.Do("PUT", "sys/init", req, &r)
}
