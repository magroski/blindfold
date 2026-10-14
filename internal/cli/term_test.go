package cli

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"testing"
)

// A terminal that cannot hide input must not get the secret echoed instead:
// it would stay on screen and in the scrollback.
func TestHiddenPromptRefusesToEcho(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.WriteString("s3cr3t\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()

	original := readPassword
	readPassword = func(int) ([]byte, error) { return nil, errors.New("inappropriate ioctl for device") }
	t.Cleanup(func() { readPassword = original })

	p := &prompter{in: r, out: &bytes.Buffer{}, buf: bufio.NewReader(r)}
	if value, err := p.hidden("Value: "); err == nil {
		t.Errorf("hidden() = %q, nil; want an error rather than an echoed read", value)
	}
}
