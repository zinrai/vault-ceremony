// Package vault is not github.com/hashicorp/vault/api: that module pulls
// in much of Vault, and this tool must stay one small binary to carry to an
// offline workstation.
package vault

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	Addr  string
	Token string
	http  *http.Client
}

// Proxy settings from the environment are ignored, not honoured: a
// cluster that everything else depends on must not depend on a proxy.
func New(addr string, roots *x509.CertPool) *Client {
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &Client{Addr: addr, http: &http.Client{Transport: tr, Timeout: 5 * time.Minute}}
}

func (c *Client) WithToken(token string) *Client {
	cp := *c
	cp.Token = token
	return &cp
}

type Error struct {
	Method string
	Path   string
	Status int
	Errors []string
}

func (e *Error) Error() string {
	msg := strings.Join(e.Errors, "; ")
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("%s /v1/%s: %d %s", e.Method, e.Path, e.Status, msg)
}

func IsStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

func (c *Client) send(method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequest(method, c.Addr+"/v1/"+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Request", "true")
	if c.Token != "" {
		req.Header.Set("X-Vault-Token", c.Token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		e := &Error{Method: method, Path: path, Status: resp.StatusCode}
		var body struct {
			Errors []string `json:"errors"`
		}
		if json.NewDecoder(resp.Body).Decode(&body) == nil {
			e.Errors = body.Errors
		}
		return nil, e
	}
	return resp, nil
}

func (c *Client) Do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	resp, err := c.send(method, path, body, "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) Upload(path string, r io.Reader) error {
	resp, err := c.send(http.MethodPost, path, r, "application/octet-stream")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}
