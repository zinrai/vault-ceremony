package config

import (
	"fmt"
	"net"
	"os"
	"slices"

	"github.com/goccy/go-yaml"
)

// Fixed, not configurable: the node contract has nothing to negotiate.
const (
	APIPort     = 8200
	ClusterPort = 8201
)

type Node struct {
	Name string `yaml:"name"`
	IP   string `yaml:"ip"`
}

func (n Node) APIAddr() string     { return fmt.Sprintf("https://%s:%d", n.IP, APIPort) }
func (n Node) ClusterAddr() string { return fmt.Sprintf("https://%s:%d", n.IP, ClusterPort) }

// Not map[string]string: that would reject "version: 2" in YAML, and
// Vault wants strings.
type Strings map[string]string

func (s *Strings) UnmarshalYAML(unmarshal func(any) error) error {
	var raw map[string]any
	if err := unmarshal(&raw); err != nil {
		return err
	}
	*s = Strings{}
	for k, v := range raw {
		(*s)[k] = fmt.Sprint(v)
	}
	return nil
}

// Not left for operators to enable later: bootstrap enables audit first,
// so that everything after it is recorded.
type Audit struct {
	Path    string  `yaml:"path"`
	Type    string  `yaml:"type"`
	Options Strings `yaml:"options"`
}

type Operator struct {
	Name     string   `yaml:"name"`
	Policies []string `yaml:"policies"`
}

type Config struct {
	Nodes     []Node     `yaml:"nodes"`
	Threshold int        `yaml:"threshold"`
	Holders   []string   `yaml:"holders"`
	RootToken string     `yaml:"root_token_holder"`
	Operators []Operator `yaml:"operators"`
	Audits    []Audit    `yaml:"audit"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := yaml.UnmarshalWithOptions(b, c, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c *Config) validate() error {
	for _, check := range []func() error{c.validateNodes, c.validateHolders, c.validateOperators, c.validateAudits} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateNodes() error {
	if len(c.Nodes) == 0 {
		return fmt.Errorf("no nodes")
	}
	for _, n := range c.Nodes {
		if n.Name == "" {
			return fmt.Errorf("node without a name")
		}
		if ip := net.ParseIP(n.IP); ip == nil || ip.To4() == nil {
			return fmt.Errorf("node %s: %q is not an IPv4 address", n.Name, n.IP)
		}
	}
	if err := unique("node name", c.Nodes, func(n Node) string { return n.Name }); err != nil {
		return err
	}
	return unique("node IP", c.Nodes, func(n Node) string { return n.IP })
}

func (c *Config) validateHolders() error {
	if len(c.Holders) == 0 {
		return fmt.Errorf("no holders")
	}
	if err := unique("holder", c.Holders, func(s string) string { return s }); err != nil {
		return err
	}
	if c.Threshold < 1 || c.Threshold > len(c.Holders) {
		return fmt.Errorf("threshold must be between 1 and the number of holders (%d)", len(c.Holders))
	}
	if len(c.Holders) > 1 && c.Threshold < 2 {
		return fmt.Errorf("threshold must be at least 2 when there is more than one holder")
	}
	// Required, not the first holder by default: who receives the initial
	// root token is a decision, and must be visible in the file.
	if c.RootToken == "" {
		return fmt.Errorf("root_token_holder is required")
	}
	if !c.IsHolder(c.RootToken) {
		return fmt.Errorf("root_token_holder %q is not a holder", c.RootToken)
	}
	return nil
}

func (c *Config) validateOperators() error {
	for _, o := range c.Operators {
		if o.Name == "" || len(o.Policies) == 0 {
			return fmt.Errorf("operator %q: name and policies are required", o.Name)
		}
	}
	return unique("operator", c.Operators, func(o Operator) string { return o.Name })
}

func (c *Config) validateAudits() error {
	for _, a := range c.Audits {
		if a.Path == "" || a.Type == "" {
			return fmt.Errorf("audit entries need path and type")
		}
	}
	return nil
}

func unique[T any](what string, items []T, key func(T) string) error {
	seen := map[string]bool{}
	for _, it := range items {
		k := key(it)
		if seen[k] {
			return fmt.Errorf("duplicate %s %q", what, k)
		}
		seen[k] = true
	}
	return nil
}

func (c *Config) IsHolder(name string) bool {
	return slices.Contains(c.Holders, name)
}
