package cli

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// notInPrompt are commands that make no sense typed into a running session's prompt: they attach, start
// another session or are internal.
var notInPrompt = map[string]bool{"start": true, "attach": true, "exec": true, "daemon": true, "_spawn": true, "init": true, "preflight": true}

// promptRunner returns the function behind the leader prompt: it runs a line of the isolait command grammar in
// this process with the given session as the target, and returns its output (or its error) as text.
func promptRunner(d deps, id string) func(line string) string {
	return func(line string) string {
		args, err := tokenize(line)
		if err != nil {
			return "error: " + err.Error()
		}
		if len(args) > 0 && args[0] == "isolait" {
			args = args[1:]
		}
		if len(args) == 0 {
			return ""
		}
		if notInPrompt[args[0]] {
			return fmt.Sprintf("%s is not available in the prompt; run it from a shell", args[0])
		}
		root := rootWith(d)
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetIn(strings.NewReader(""))
		root.SetArgs(append(args, "--sid", id))
		if err := root.Execute(); err != nil {
			var ee *ExitError
			if !errors.As(err, &ee) {
				return strings.TrimSpace(out.String()+" ") + " error: " + err.Error()
			}
		}
		return strings.TrimSpace(out.String())
	}
}

// tokenize splits a command line like a shell would for simple cases: spaces separate words, single and double
// quotes group, and a backslash escapes the next character outside single quotes.
func tokenize(line string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote rune
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case quote == '\'':
			if r == '\'' {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case quote == '"':
			switch {
			case r == '"':
				quote = 0
			case r == '\\' && i+1 < len(runes) && (runes[i+1] == '"' || runes[i+1] == '\\'):
				i++
				cur.WriteRune(runes[i])
			default:
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == '\\':
			if i+1 >= len(runes) {
				return nil, errors.New("a backslash at the end of the line")
			}
			i++
			cur.WriteRune(runes[i])
			inWord = true
		case r == ' ' || r == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}
