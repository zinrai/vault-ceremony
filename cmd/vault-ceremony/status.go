package main

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/zinrai/vault-ceremony/internal/cluster"
	"github.com/zinrai/vault-ceremony/internal/config"
	"github.com/zinrai/vault-ceremony/internal/pubkeys"
	"github.com/zinrai/vault-ceremony/internal/shares"
	"github.com/zinrai/vault-ceremony/internal/workspace"
)

type audience int

const (
	audienceEveryone audience = iota
	audienceCoordinator
	audienceHolders
)

type step struct {
	to      audience
	holders []string
	what    string
	cmd     string
}

func toEveryone(what string) step { return step{to: audienceEveryone, what: what} }

func toCoordinator(what, cmd string) step { return step{to: audienceCoordinator, what: what, cmd: cmd} }

func toHolders(names []string, what, cmd string) step {
	return step{to: audienceHolders, holders: names, what: what, cmd: cmd}
}

// Who does what next, not only the state: nobody should have to remember
// the steps of a ceremony they run once a year. With --as, only that
// person's steps, so a holder never has to read anyone else's. No Raft
// peers or autopilot: operators have vault operator raft autopilot state.
func runStatus(args []string) error {
	fs := newFlags("status [--as <name>]", "Show the nodes, and who does what next. With --as, only your next step.")
	as := fs.String("as", "", "show only this person's steps")
	if err := parse(fs, args); err != nil {
		return err
	}
	cfg, err := config.Load(workspace.ConfigFile)
	if err != nil {
		return err
	}
	steps, err := nextSteps(cfg)
	if err != nil {
		return err
	}
	printSteps(steps, *as)
	return nil
}

func nextSteps(cfg *config.Config) ([]step, error) {
	if !workspace.Exists(workspace.CACertFile) {
		return []step{toEveryone(fmt.Sprintf("No CA certificate at %s: the CA of the nodes' TLS certificates.", workspace.CACertFile))}, nil
	}
	nodes, err := cluster.Connect(cfg, workspace.CACertFile, vaultToken())
	if err != nil {
		return nil, err
	}
	reachable, initialized, sealed, recovery, active := printNodes(nodes)
	if !reachable {
		return []step{toEveryone("No node is reachable. Start them with whatever runs them, then look again.")}, nil
	}
	if !initialized {
		return []step{toCoordinator("Not initialized.", "vault-ceremony init")}, nil
	}

	set, err := shares.Load(workspace.SharesFile)
	if err != nil {
		return []step{toEveryone(fmt.Sprintf("Initialized, but %s is missing: pull.", workspace.SharesFile))}, nil
	}
	holders := set.Holders()
	var steps []step
	if len(sealed) > 0 && !recovery {
		steps = append(steps, toHolders(holders, fmt.Sprintf("Sealed: %s.", strings.Join(sealed, ", ")), "vault-ceremony key --as <name> | <decrypt> | vault-ceremony unseal --as <name>"))
	}
	if active == nil {
		return steps, nil
	}
	if set.RootToken != nil {
		steps = append(steps, toHolders([]string{set.RootToken.Holder}, "Not bootstrapped yet.", "vault-ceremony initial-root-token --as <name> | <decrypt> | vault-ceremony bootstrap --as <name>"))
	}
	ppl, err := people(cfg)
	if err != nil {
		ppl = pubkeys.People{}
	}
	cs, err := ceremonySteps(*active, ppl, holders, recovery)
	if err != nil {
		return append(steps, toEveryone(fmt.Sprintf("Ceremonies in progress cannot be seen: %v", err))), nil
	}
	steps = append(steps, cs...)
	var rt shares.Share
	if workspace.ReadJSON(workspace.RootTokenFile, &rt) == nil {
		steps = append(steps, toHolders([]string{rt.Holder}, "A root token is ready for you. Once you have revoked it, remove "+workspace.RootTokenFile+" and commit.", "vault-ceremony root-token --as <name> | <decrypt>"))
	}
	return steps, nil
}

func printNodes(nodes []cluster.Node) (reachable, initialized bool, sealed []string, recovery bool, active *cluster.Node) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tADDRESS\tSEAL\tINITIALIZED\tSEALED\tHA\tVERSION")
	for i := range nodes {
		st := describe(nodes[i])
		fmt.Fprintln(tw, st.row)
		if !st.reachable {
			continue
		}
		reachable = true
		initialized = initialized || st.initialized
		recovery = st.recovery
		if st.needsKeys {
			sealed = append(sealed, nodes[i].Name)
		}
		if st.active {
			active = &nodes[i]
		}
	}
	tw.Flush()
	return
}

type nodeState struct {
	row                                                 string
	reachable, initialized, recovery, needsKeys, active bool
}

func describe(n cluster.Node) nodeState {
	s, err := n.SealStatus()
	if err != nil {
		return nodeState{row: fmt.Sprintf("%s\t%s\tunreachable: %v", n.Name, n.APIAddr(), err)}
	}
	st := nodeState{reachable: true, initialized: s.Initialized, recovery: s.RecoverySeal}
	sealed, ha := "false", "-"
	switch {
	case s.Sealed && s.Initialized && !s.RecoverySeal:
		sealed = fmt.Sprintf("true (%d/%d)", s.Progress, s.T)
		st.needsKeys = true
	case s.Sealed:
		sealed = "true"
	default:
		ha = haOf(n)
		st.active = ha == "active"
	}
	st.row = fmt.Sprintf("%s\t%s\t%s\t%t\t%s\t%s\t%s", n.Name, n.APIAddr(), s.Type, s.Initialized, sealed, ha, s.Version)
	return st
}

func haOf(n cluster.Node) string {
	l, err := n.Leader()
	switch {
	case err != nil:
		return "-"
	case l.IsSelf:
		return "active"
	default:
		return "standby"
	}
}

func ceremonySteps(a cluster.Node, ppl pubkeys.People, holders []string, recovery bool) ([]step, error) {
	root, err := rootSteps(a, ppl, holders)
	if err != nil {
		return nil, err
	}
	rekey, err := rekeySteps(a, ppl, holders, recovery)
	if err != nil {
		return nil, err
	}
	return append(root, rekey...), nil
}

func rootSteps(a cluster.Node, ppl pubkeys.People, holders []string) ([]step, error) {
	g, err := a.GenerateRootStatus()
	if err != nil || !g.Started {
		return nil, err
	}
	to, err := ppl.Name(g.PGPFingerprint)
	if err != nil || g.PGPFingerprint == "" {
		return []step{
			toHolders(holders, fmt.Sprintf("Root token generation %s is NOT for anyone in pubkeys/. Do not approve it.", g.Nonce), ""),
			toCoordinator(fmt.Sprintf("Root token generation %s is NOT for anyone in pubkeys/.", g.Nonce), "vault-ceremony cancel --nonce "+g.Nonce),
		}, nil
	}
	return []step{toHolders(holders,
		fmt.Sprintf("Root token generation for %s, %d of %d approvals so far.", to, g.Progress, g.Required),
		"vault-ceremony key --as <name> | <decrypt> | vault-ceremony approve --nonce "+g.Nonce+" --as <name>")}, nil
}

func rekeySteps(a cluster.Node, ppl pubkeys.People, holders []string, recovery bool) ([]step, error) {
	r, err := a.RekeyStatus(recovery)
	if err != nil || !r.Started {
		return nil, err
	}
	var steps []step
	names, err := ppl.Names(r.PGPFingerprints)
	if err != nil {
		steps = append(steps,
			toHolders(holders, fmt.Sprintf("Rekey %s is NOT for the people in pubkeys/. Do not approve it.", r.Nonce), ""),
			toCoordinator(fmt.Sprintf("Rekey %s is NOT for the people in pubkeys/.", r.Nonce), "vault-ceremony cancel --nonce "+r.Nonce))
	} else {
		steps = append(steps, toHolders(holders,
			fmt.Sprintf("Rekey for %s, %d of %d approvals so far.", strings.Join(names, ", "), r.Progress, r.Required),
			"vault-ceremony key --as <name> | <decrypt> | vault-ceremony approve --nonce "+r.Nonce+" --as <name>"))
	}
	return append(steps, verifySteps(a, recovery)...), nil
}

// Errors ignored, not reported: until the approvals are complete, there is
// no verification for Vault to report on.
func verifySteps(a cluster.Node, recovery bool) []step {
	v, err := a.RekeyVerifyStatus(recovery)
	if err != nil || !v.Started {
		return nil
	}
	pending, err := shares.Load(workspace.PendingFile)
	if err != nil {
		return []step{toEveryone(fmt.Sprintf("A rekey awaits verification, but %s is missing: pull.", workspace.PendingFile))}
	}
	return []step{toHolders(pending.Holders(),
		fmt.Sprintf("Your new key from the rekey needs verifying, %d of %d so far.", v.Progress, v.T),
		"vault-ceremony key --nonce "+v.Nonce+" --as <name> | <decrypt> | vault-ceremony approve --nonce "+v.Nonce+" --as <name>")}
}

func printSteps(steps []step, as string) {
	fmt.Println()
	shown := 0
	for _, s := range steps {
		line, ok := stepLine(s, as)
		if !ok {
			continue
		}
		fmt.Print(line)
		shown++
	}
	switch {
	case shown > 0:
	case as == "":
		fmt.Println("Nothing to do.")
	default:
		fmt.Printf("Nothing for %s to do.\n", as)
	}
}

func stepLine(s step, as string) (string, bool) {
	var b strings.Builder
	switch {
	case s.to == audienceEveryone:
		b.WriteString(s.what + "\n")
	case as == "":
		fmt.Fprintf(&b, "%s: %s\n", s.label(), s.what)
	case s.to == audienceHolders && slices.Contains(s.holders, as):
		fmt.Fprintf(&b, "%s: %s\n", as, s.what)
	default:
		return "", false
	}
	if s.cmd == "" {
		return b.String(), true
	}
	cmd := s.cmd
	if as != "" {
		cmd = strings.ReplaceAll(cmd, "<name>", as)
	}
	fmt.Fprintf(&b, "  %s\n", cmd)
	return b.String(), true
}

func (s step) label() string {
	switch {
	case s.to == audienceCoordinator:
		return "Coordinator"
	case len(s.holders) == 1:
		return s.holders[0]
	default:
		return "Holders (" + strings.Join(s.holders, ", ") + ")"
	}
}
