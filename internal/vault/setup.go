package vault

import (
	"encoding/json"
	"strings"
)

// Only what bootstrap needs, not a general client: after bootstrap,
// operators use the vault CLI.

type MountInfo struct {
	Type     string `json:"type"`
	Accessor string `json:"accessor"`
}

func (c *Client) mounts(path string) (map[string]MountInfo, error) {
	var raw map[string]json.RawMessage
	if err := c.Do("GET", path, nil, &raw); err != nil {
		return nil, err
	}
	if data, ok := raw["data"]; ok {
		raw = nil
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
	}
	out := map[string]MountInfo{}
	for k, v := range raw {
		if !strings.HasSuffix(k, "/") {
			continue
		}
		var m MountInfo
		if err := json.Unmarshal(v, &m); err != nil {
			return nil, err
		}
		out[strings.TrimSuffix(k, "/")] = m
	}
	return out, nil
}

func (c *Client) AuditDevices() (map[string]MountInfo, error) { return c.mounts("sys/audit") }

func (c *Client) EnableAudit(path, typ string, options map[string]string) error {
	return c.Do("PUT", "sys/audit/"+path, map[string]any{"type": typ, "options": options}, nil)
}

func (c *Client) AuthMethods() (map[string]MountInfo, error) { return c.mounts("sys/auth") }

func (c *Client) EnableAuth(path, typ string) error {
	return c.Do("POST", "sys/auth/"+path, map[string]string{"type": typ}, nil)
}

func (c *Client) WritePolicy(name, policy string) error {
	return c.Do("PUT", "sys/policies/acl/"+name, map[string]string{"policy": policy}, nil)
}

func (c *Client) WriteEntity(name string, policies []string) (string, error) {
	if err := c.Do("POST", "identity/entity/name/"+name, map[string]any{"policies": policies}, nil); err != nil {
		return "", err
	}
	var r struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	return r.Data.ID, c.Do("GET", "identity/entity/name/"+name, nil, &r)
}

func (c *Client) EnsureEntityAlias(name, entityID, mountAccessor string) error {
	var found struct {
		Data *struct{} `json:"data"`
	}
	if err := c.Do("POST", "identity/lookup/entity", map[string]string{"alias_name": name, "alias_mount_accessor": mountAccessor}, &found); err != nil {
		return err
	}
	if found.Data != nil {
		return nil
	}
	return c.Do("POST", "identity/entity-alias", map[string]string{"name": name, "canonical_id": entityID, "mount_accessor": mountAccessor}, nil)
}

func (c *Client) UserpassUserExists(name string) (bool, error) {
	err := c.Do("GET", "auth/userpass/users/"+name, nil, nil)
	if IsStatus(err, 404) {
		return false, nil
	}
	return err == nil, err
}

func (c *Client) CreateUserpassUser(name, password string) error {
	return c.Do("POST", "auth/userpass/users/"+name, map[string]string{"password": password}, nil)
}

func (c *Client) RevokeSelf() error {
	return c.Do("POST", "auth/token/revoke-self", nil, nil)
}
