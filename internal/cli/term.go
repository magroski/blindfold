package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// readPassword reads a line without echo. Tests swap it to simulate a terminal
// that cannot hide input.
var readPassword = term.ReadPassword

// prompter asks a person questions at a terminal.
//
// Visible answers are read through a buffered reader and hidden ones straight
// from the file descriptor, which is a hazard: the buffer can swallow input the
// raw read then misses. Both go through here so that the one place that has to
// reconcile them is the one place that knows about both.
type prompter struct {
	in  *os.File
	out io.Writer
	buf *bufio.Reader
}

// newPrompter returns a prompter, or false when there is no terminal to ask.
func newPrompter(env Env) (*prompter, bool) {
	f, ok := env.Stdin.(*os.File)
	if !ok || !isTerminal(f) {
		return nil, false
	}
	return &prompter{in: f, out: env.Stderr, buf: bufio.NewReader(f)}, true
}

// line asks for a visible answer, returning fallback for an empty one.
func (p *prompter) line(prompt, fallback string) string {
	fmt.Fprint(p.out, prompt)
	answer, err := p.buf.ReadString('\n')
	if err != nil && answer == "" {
		return fallback
	}
	if answer = strings.TrimSpace(answer); answer != "" {
		return answer
	}
	return fallback
}

// yesNo asks a yes/no question, returning fallback for anything else.
func (p *prompter) yesNo(prompt string, fallback bool) bool {
	switch strings.ToLower(p.line(prompt, "")) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	}
	return fallback
}

// hidden asks for an answer without echoing it, so a pasted secret does not stay
// visible on screen or in the scrollback.
func (p *prompter) hidden(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	defer fmt.Fprintln(p.out)

	// Anything already buffered was queued by a script or a heredoc rather than
	// typed. Reading the descriptor directly would step over it and take the
	// line after the one meant for this prompt.
	if p.buf.Buffered() > 0 {
		line, err := p.buf.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err
	}

	data, err := readPassword(int(p.in.Fd()))
	if err != nil {
		// Never fall back to an echoed read: the secret would stay on screen
		// and in the scrollback. Piped input needs no terminal at all.
		return "", fmt.Errorf("this terminal cannot hide input (%v); pipe the value in on stdin instead", err)
	}
	return string(data), nil
}
