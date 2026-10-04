package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/zinrai/vault-ceremony/internal/cluster"
	"github.com/zinrai/vault-ceremony/internal/shares"
	"github.com/zinrai/vault-ceremony/internal/vault"
	"github.com/zinrai/vault-ceremony/internal/workspace"
)

// Not into an existing cluster: Vault only restores into a running,
// unsealed one, so a throwaway single-share barrier is created in memory
// and replaced by the snapshot's. --shares is required, not derived from
// the snapshot's name: with the wrong share set, nobody can unseal.
func runRestore(args []string) error {
	fs := newFlags("restore --snapshot <file> --shares <file>", "Restore a snapshot into freshly provisioned nodes. Afterwards the cluster is\nsealed by the snapshot's shares, which become "+workspace.SharesFile+".")
	snap := fs.String("snapshot", "", "snapshot file (required)")
	sharesPath := fs.String("shares", "", "share set that was current when the snapshot was taken (required)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("snapshot", *snap); err != nil {
		return err
	}
	if err := required("shares", *sharesPath); err != nil {
		return err
	}
	set, err := shares.Load(*sharesPath)
	if err != nil {
		return err
	}
	f, err := os.Open(*snap)
	if err != nil {
		return err
	}
	defer f.Close()
	_, nodes, err := open()
	if err != nil {
		return err
	}
	first := nodes[0]
	if err := checkFresh(first, nodes[1:]); err != nil {
		return err
	}
	if err := restoreInto(first, f); err != nil {
		return err
	}
	if err := installShares(set); err != nil {
		return err
	}
	fmt.Printf("Restored. %s is now %s.\n", workspace.SharesFile, *sharesPath)
	shareState()
	fmt.Printf("Next: restart %s, which still holds the throwaway seal configuration in memory.\n", first.Name)
	if set.Kind == shares.Unseal {
		fmt.Println("Holders unseal it with the shares that were current when the snapshot was taken.")
	}
	fmt.Println("Then start the other nodes; they join it. An operator proves the data is readable by logging in.")
	return nil
}

// Stopped, not merely uninitialized: under an auto-unseal seal a running
// follower unseals itself, joins the throwaway cluster, and outvotes the
// restore when the first node restarts.
func checkFresh(first cluster.Node, others []cluster.Node) error {
	ok, err := first.Initialized()
	if err != nil {
		return fmt.Errorf("%s: %w", first.Name, err)
	}
	if ok {
		return fmt.Errorf("%s is initialized; restore needs a node that never was", first.Name)
	}
	for _, n := range others {
		if _, err := n.SealStatus(); err == nil {
			return fmt.Errorf("%s is running; stop every node but %s during a restore, and start them after it", n.Name, first.Name)
		}
	}
	return nil
}

func restoreInto(first cluster.Node, snapshot io.Reader) error {
	seal, err := first.SealStatus()
	if err != nil {
		return err
	}
	fmt.Printf("Initializing %s with a throwaway barrier (one share, in memory only)...\n", first.Name)
	init, err := first.Init(vault.Shares(seal.RecoverySeal, 1, 1, nil))
	if err != nil {
		return err
	}
	if !seal.RecoverySeal {
		if _, err := first.Unseal(init.KeysB64[0]); err != nil {
			return err
		}
	}
	// Waiting here, not leaving it to the user: once initialized, this
	// command cannot be run again.
	if err := cluster.WaitActive(first, 60*time.Second); err != nil {
		return err
	}
	fmt.Println("Restoring the snapshot...")
	return first.WithToken(init.RootToken).Upload("sys/storage/raft/snapshot-force", snapshot)
}

func installShares(set *shares.Set) error {
	if workspace.Exists(workspace.SharesFile) {
		old, err := workspace.Archive(workspace.SharesFile)
		if err != nil {
			return err
		}
		fmt.Printf("Previous %s archived to %s.\n", workspace.SharesFile, old)
	}
	return set.Save(workspace.SharesFile)
}
