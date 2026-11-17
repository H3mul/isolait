package main

import (
	"os"

	"github.com/H3mul/isolait/internal/cli"
)

func main() {
	if err := cli.Root().Execute(); err != nil {
		os.Exit(1)
	}
}
