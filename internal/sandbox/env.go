package sandbox

import (
	"fmt"
	"sort"
	"strings"
)

// neverInherited are agent and bus socket variables: with --inherit-env they are still dropped unless named
// explicitly with --env, because they hand the sandbox the user's keys or session bus.
var neverInherited = map[string]bool{
	"SSH_AUTH_SOCK": true, "SSH_AGENT_PID": true, "GPG_AGENT_INFO": true, "DBUS_SESSION_BUS_ADDRESS": true,
}

// BuildEnv returns the sandbox environment as sorted K=V pairs. Order of precedence: base (variables isolait
// sets itself, such as HOME and PATH) overrides anything from the host; names are forwarded from host with
// their host value; LANG, LC_* and COLORTERM always pass (LANG defaults to C.UTF-8); inherit forwards the whole host environment minus neverInherited.
func BuildEnv(host []string, names []string, inherit bool, base map[string]string) ([]string, error) {
	hostMap := map[string]string{}
	for _, kv := range host {
		k, v := splitEnv(kv)
		hostMap[k] = v
	}
	out := map[string]string{}
	if inherit {
		for k, v := range hostMap {
			if !neverInherited[k] {
				out[k] = v
			}
		}
	}
	for _, n := range names {
		if strings.ContainsRune(n, '=') || n == "" {
			return nil, fmt.Errorf("env name %q is not a variable name", n)
		}
		if v, ok := hostMap[n]; ok {
			out[n] = v
		}
	}
	for k, v := range hostMap { // locale and terminal capability carry no secrets
		if k == "LANG" || k == "COLORTERM" || strings.HasPrefix(k, "LC_") {
			out[k] = v
		}
	}
	if out["LANG"] == "" {
		out["LANG"] = "C.UTF-8"
	}
	for k, v := range base {
		out[k] = v
	}
	kvs := make([]string, 0, len(out))
	for k, v := range out {
		kvs = append(kvs, k+"="+v)
	}
	sort.Strings(kvs)
	return kvs, nil
}

func splitEnv(kv string) (string, string) {
	k, v, _ := strings.Cut(kv, "=")
	return k, v
}
