package main

import (
	"fmt"
	"os"

	"github.com/sho-luv/srcleaks/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if cmd.ExitCode != 0 {
		os.Exit(cmd.ExitCode)
	}
}
