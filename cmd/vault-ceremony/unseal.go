package main

import (
	"errors"
	"fmt"

	"github.com/zinrai/vault-ceremony/internal/cluster"
	"github.com/zinrai/vault-ceremony/internal/shares"
	"github.com/zinrai/vault-ceremony/internal/workspace"
)

func runUnseal(args []string) error {
	fs := newFlags("unseal --as <name> [--node <node>]", "Submit your key, read from stdin, to one node or all nodes. Unseal the leader\nfirst: followers join it, then take the same keys. A node that cannot be\nreached, or has not joined yet, is reported; run the command again later.\n\n  vault-ceremony key --as <name> | <decrypt> | vault-ceremony unseal --as <name>")
	as := asFlag(fs)
	target := fs.String("node", "all", "node name, or all")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("as", *as); err != nil {
		return err
	}
	_, nodes, err := open()
	if err != nil {
		return err
	}
	targets, err := cluster.Pick(nodes, *target)
	if err != nil {
		return err
	}
	set, err := shares.Load(workspace.SharesFile)
	if err != nil {
		return err
	}
	if set.Kind == shares.Recovery {
		return errors.New("this cluster is unsealed by its seal, not by shares: a sealed node means the seal is unreachable, and recovery keys cannot help")
	}
	if _, err := set.Of(*as); err != nil {
		return err
	}
	key, err := readPlaintext("key")
	if err != nil {
		return err
	}

	failed := false
	for _, n := range targets {
		if err := unseal(n, set, key); err != nil {
			fmt.Printf("%s: %v\n", n.Name, err)
			failed = true
		}
	}
	if failed {
		return errors.New("not every node took the share")
	}
	return nil
}

func unseal(n cluster.Node, set *shares.Set, key string) error {
	s, err := n.SealStatus()
	if err != nil {
		return fmt.Errorf("unreachable: %w", err)
	}
	if !s.Sealed {
		fmt.Printf("%s: already unsealed\n", n.Name)
		return nil
	}
	// Uninitialized here is a follower that has not joined yet, not a fresh
	// cluster: retry_join completes once the leader is active.
	if !s.Initialized {
		return errors.New("has not joined the cluster yet; unseal the leader, then run this again")
	}
	if s.T != set.Threshold || s.N != len(set.Shares) {
		return fmt.Errorf("expects %d of %d shares, but %s holds %d of %d. Wrong share set, or the node still has the\nseal configuration from before a restore: restart it, then run this again",
			s.T, s.N, workspace.SharesFile, set.Threshold, len(set.Shares))
	}
	s, err = n.Unseal(key)
	switch {
	case err != nil:
		return err
	case !s.Sealed:
		fmt.Printf("%s: unsealed\n", n.Name)
	case s.Progress == 0:
		// Back at zero is not a rejected share: the threshold was met and
		// the follower is catching up with the leader.
		fmt.Printf("%s: threshold met, joining the cluster; it unseals once it has caught up\n", n.Name)
	default:
		fmt.Printf("%s: share accepted, %d/%d\n", n.Name, s.Progress, s.T)
	}
	return nil
}
