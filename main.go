package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/H3mul/isolait/internal/cli"
)

func main() {
	err := cli.Root().Execute()
	var exit *cli.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		os.Exit(exit.Code)
	default:
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
