package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/magroski/blindfold/internal/vault"
)

// --var stores its value in cleartext metadata. Pointed at a secret, it would
// silently unseal it, so it is refused and the sealed value stays as it was.
func TestEditVarRefusesToUnsealASecret(t *testing.T) {
	h := newHarness(t)
	const sealed, leaked = "sealed-value", "value-from-argv"
	h.mustRun(sealed, "add", "api", "--secret", "API_KEY")

	code, stdout, stderr := h.run("", "edit", "api", "--var", "API_KEY="+leaked)
	if code == 0 {
		t.Errorf("edit --var replaced a secret with a public variable: %s", stdout)
	}
	if strings.Contains(stdout+stderr, leaked) {
		t.Errorf("edit echoed the value: %q", stdout+stderr)
	}
	for _, want := range []string{"cleartext", "--set API_KEY", "rotate"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("refusal %q does not mention %q", stderr, want)
		}
	}

	metadata, err := os.ReadFile(filepath.Join(h.dir, vault.MetadataFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(metadata), leaked) {
		t.Error("the value reached the cleartext metadata file")
	}

	exports := h.mustRun("", "env", "api")
	if got := evalAndEcho(t, exports, "API_KEY"); got != sealed {
		t.Errorf("after the refusal API_KEY = %q, want the sealed %q", got, sealed)
	}
}

// Removing the secret in the same command is the explicit way to make it public.
func TestEditVarUnsealsWhenTheSecretIsRemovedFirst(t *testing.T) {
	h := newHarness(t)
	h.mustRun("sealed-value", "add", "api", "--secret", "API_KEY")

	h.mustRun("", "edit", "api", "--rm-var", "API_KEY", "--var", "API_KEY=now-public")

	exports := h.mustRun("", "env", "api")
	if got := evalAndEcho(t, exports, "API_KEY"); got != "now-public" {
		t.Errorf("API_KEY = %q, want now-public", got)
	}
}
