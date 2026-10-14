//go:build unix

package cli

import "syscall"

// replaceProcess becomes the command: same PID, so signals reach it directly and
// its exit status is the caller's, with nothing in between. It returns only if
// the replacement failed.
func replaceProcess(path string, argv, envv []string) error {
	return syscall.Exec(path, argv, envv)
}
