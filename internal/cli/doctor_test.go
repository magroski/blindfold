package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// $BLINDFOLD_PASSPHRASE is inherited by every command the shell runs, an
// agent's included, so doctor flags it — but only when it is the key actually
// in use.
func TestDoctorWarnsOnlyWhenTheEnvPassphraseIsTheKeySource(t *testing.T) {
	h := newHarness(t)
	passphraseFile := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(passphraseFile, []byte("pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		env  map[string]string
		warn bool
	}{
		{"env passphrase", map[string]string{"BLINDFOLD_KEK_FILE": "", "BLINDFOLD_PASSPHRASE": "pw"}, true},
		{"passphrase file outranks it", map[string]string{
			"BLINDFOLD_KEK_FILE": "", "BLINDFOLD_PASSPHRASE_FILE": passphraseFile, "BLINDFOLD_PASSPHRASE": "pw"}, false},
		{"key file outranks it", map[string]string{"BLINDFOLD_PASSPHRASE": "pw"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			out := h.mustRun("", "doctor")
			if warned := strings.Contains(out, "BLINDFOLD_PASSPHRASE_FILE"); warned != tc.warn {
				t.Errorf("warned = %t, want %t; doctor said:\n%s", warned, tc.warn, out)
			}
		})
	}
}
