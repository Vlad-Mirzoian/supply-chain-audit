// Command ssca is the CLI and CI adapter of the supply-chain auditing suite.
package main

import (
	"os"
)

func main() {
	os.Exit(run(os.Args[1:]))
}
