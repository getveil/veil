package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	if len(os.Args) >= 2 && (os.Args[1] == "--version" || os.Args[1] == "version" || os.Args[1] == "-v") {
		fmt.Println("veil", version)
		return
	}
	fmt.Fprintln(os.Stderr, "veil: command wiring pending; use --version")
	os.Exit(2)
}
