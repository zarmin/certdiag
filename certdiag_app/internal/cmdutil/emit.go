package cmdutil

import "fmt"

// EmitStructured prints the output for the given display format, selecting
// among the human, JSON, and YAML producers. Any format other than
// OutputJSON/OutputYAML falls back to human. Each producer is only invoked for
// the selected format, so callers can defer expensive rendering into the
// closure.
func EmitStructured(format string, human, json, yaml func() string) {
	switch format {
	case OutputJSON:
		fmt.Print(json())
	case OutputYAML:
		fmt.Print(yaml())
	default:
		fmt.Print(human())
	}
}
