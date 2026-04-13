package main

import (
	"fmt"
	"os"

	"github.com/8enji/veil/internal/cli"
)

var version = "dev"

func main() {
	root := cli.NewRoot(version)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
