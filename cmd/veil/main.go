package main

import (
	"os"

	"github.com/8enji/veil/internal/cli"
)

var version = "dev"

func main() {
	root := cli.NewRoot(version)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
