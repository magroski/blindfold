package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemotesRoundTrip(t *testing.T) {
	v := newTestVault(t)
	if err := v.AddRemote(Remote{Name: "mac-box", Destination: "me@mac.local"}); err != nil {
		t.Fatal(err)
	}
	if err := v.AddRemote(Remote{Name: "linux-box", Destination: "dev-linux", Bin: "/opt/bin/blindfold"}); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(v.Dir())
	if err != nil {
		t.Fatal(err)
	}
	remotes, err := reopened.Remotes()
	if err != nil {
		t.Fatal(err)
	}
	if len(remotes) != 2 || remotes[0].Name != "linux-box" || remotes[1].Destination != "me@mac.local" {
		t.Errorf("remotes = %+v, want both, sorted by name", remotes)
	}
	if remotes[1].Bin != DefaultRemoteBin {
		t.Errorf("unset bin = %q, want %q", remotes[1].Bin, DefaultRemoteBin)
	}

	if err := reopened.RemoveRemote("mac-box"); err != nil {
		t.Fatal(err)
	}
	if remotes, _ := reopened.Remotes(); len(remotes) != 1 {
		t.Errorf("after remove: %+v", remotes)
	}
	if err := reopened.RemoveRemote("mac-box"); err == nil {
		t.Error("removing an unknown box succeeded")
	}
}

// A destination is handed to ssh as an argument, and a bin to the remote
// shell: neither may read as an option or break a word.
func TestAddRemoteValidates(t *testing.T) {
	v := newTestVault(t)
	if err := v.AddRemote(Remote{Name: "box", Destination: "host"}); err != nil {
		t.Fatal(err)
	}
	if err := v.AddRemote(Remote{Name: "home-bin", Destination: "host", Bin: "~/go/bin/blindfold"}); err != nil {
		t.Errorf("a home-relative bin was refused: %v", err)
	}
	for _, r := range []Remote{
		{Name: "box", Destination: "other"},                        // duplicate name
		{Name: "-box", Destination: "host"},                        // name reads as a flag
		{Name: "b2", Destination: ""},                              // no destination
		{Name: "b3", Destination: "-oProxyCommand=sh -c x"},        // ssh option injection
		{Name: "b4", Destination: "host extra"},                    // whitespace
		{Name: "b5", Destination: "host", Bin: "blindfold\nrm -r"}, // control character
		{Name: "b6", Destination: "host", Bin: "$(id)/blindfold"},  // shell syntax
		{Name: "b7", Destination: "host", Bin: "/opt/my tools/bf"}, // a word break
		{Name: "b8", Destination: "host", Bin: "-x"},               // reads as an option
	} {
		if err := v.AddRemote(r); err == nil {
			t.Errorf("AddRemote(%+v) accepted", r)
		}
	}
}

// The registry decides where `push` sends values. Rewritten by hand — here,
// replaced with one sealed under another key — it must be refused, not used.
func TestRemotesTamperRefused(t *testing.T) {
	v := newTestVault(t)
	if err := v.AddRemote(Remote{Name: "mac-box", Destination: "me@mac.local"}); err != nil {
		t.Fatal(err)
	}

	other, _ := newKey()
	forged, err := seal(other, []byte(`[{"name":"mac-box","destination":"attacker.example"}]`), remotesAAD)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(v.Dir(), SealedFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file sealedFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	file.Remotes = &forged
	if data, err = json.Marshal(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(v.Dir())
	if err != nil {
		t.Fatal(err)
	}
	remotes, err := reopened.Remotes()
	if err == nil {
		t.Fatalf("a forged registry was used: %+v", remotes)
	}
	if !strings.Contains(err.Error(), "edited by hand") {
		t.Errorf("error = %v, want it to name the cause", err)
	}
}

// Writing the registry leaves every entry readable.
func TestRemotesKeepEntries(t *testing.T) {
	v := newTestVault(t)
	if err := v.Put(sampleEntry(), map[string]string{"ES_API_KEY": "k"}); err != nil {
		t.Fatal(err)
	}
	if err := v.AddRemote(Remote{Name: "box", Destination: "host"}); err != nil {
		t.Fatal(err)
	}
	reopened, _ := Open(v.Dir())
	if got, err := reopened.UnsealVar("cdp-es", "ES_API_KEY"); err != nil || got != "k" {
		t.Errorf("UnsealVar = %q, %v", got, err)
	}
}
