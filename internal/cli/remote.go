package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/magroski/blindfold/internal/vault"
)

const remoteUsage = "usage: " + Bin + " remote add <box> <ssh-destination> [--bin PATH] | remote ls | remote rm <box>"

// cmdRemote manages the boxes this vault syncs with. The registry is sealed:
// it decides where `push` sends values.
func cmdRemote(env Env, args []string) error {
	if len(args) == 0 {
		return remoteList(env)
	}
	switch args[0] {
	case "add":
		return remoteAdd(env, args[1:])
	case "ls", "list":
		return remoteList(env)
	case "rm", "remove":
		return remoteRemove(env, args[1:])
	}
	return fmt.Errorf("%s", remoteUsage)
}

func remoteAdd(env Env, args []string) error {
	fs := flag.NewFlagSet("remote add", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	bin := fs.String("bin", vault.DefaultRemoteBin,
		"blindfold on the box, when a non-interactive ssh session's PATH does not find it")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 2 {
		return fmt.Errorf("%s", remoteUsage)
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	remote := vault.Remote{Name: positional[0], Destination: positional[1], Bin: *bin}
	if err := v.AddRemote(remote); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Added %s (%s). Compare with:\n  %s sync %s\n", remote.Name, remote.Destination, Bin, remote.Name)
	return nil
}

func remoteList(env Env) error {
	v, err := openVault()
	if err != nil {
		return err
	}
	remotes, err := v.Remotes()
	if err != nil {
		return err
	}
	if len(remotes) == 0 {
		fmt.Fprintf(env.Stdout, "No boxes yet. Add one with:\n  %s remote add <box> <ssh-destination>\n", Bin)
		return nil
	}
	rows := [][]string{{"BOX", "DESTINATION", "BLINDFOLD"}}
	for _, r := range remotes {
		rows = append(rows, []string{r.Name, r.Destination, r.Bin})
	}
	writeTable(env.Stdout, rows)
	return nil
}

func remoteRemove(env Env, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("%s", remoteUsage)
	}
	v, err := openVault()
	if err != nil {
		return err
	}
	if err := v.RemoveRemote(args[0]); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Removed %s. Its own vault is untouched.\n", args[0])
	return nil
}

// findRemotes resolves box names, or every registered box when none are named.
// An unknown name lists what is registered.
func findRemotes(v *vault.Vault, names []string) ([]vault.Remote, error) {
	remotes, err := v.Remotes()
	if err != nil {
		return nil, err
	}
	if len(remotes) == 0 {
		return nil, fmt.Errorf("no boxes registered; add one with `%s remote add <box> <ssh-destination>`", Bin)
	}
	if len(names) == 0 {
		return remotes, nil
	}

	byName := make(map[string]vault.Remote, len(remotes))
	registered := make([]string, 0, len(remotes))
	for _, r := range remotes {
		byName[r.Name] = r
		registered = append(registered, r.Name)
	}
	found := make([]vault.Remote, 0, len(names))
	for _, name := range names {
		r, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("no box named %q. Registered: %s", name, strings.Join(registered, ", "))
		}
		found = append(found, r)
	}
	return found, nil
}
