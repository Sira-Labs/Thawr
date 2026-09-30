// Command thawr is the single binary for the Thawr private network. It
// runs as the control server (`thawr server`), as the node client
// (`thawr client`), and as the administration CLI (`thawr admin`).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// version, commit and builtAt are set at build time via -ldflags
// "-X main.version=..."; `thawr version` falls back to Go's VCS stamp.
var (
	version = "dev"
	commit  string
	builtAt string
)

func main() {
	if err := newRootCmd(os.Stdout, os.Stderr).ExecuteContext(context.Background()); err != nil {
		err = permissionError(err)
		fmt.Fprintln(os.Stderr, "thawr:", err)
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(1)
	}
}
