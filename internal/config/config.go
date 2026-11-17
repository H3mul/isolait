// Package config loads isolait's tiered configuration: flags > trusted workspace .isolait/config >
// global config > defaults. A workspace config is ignored entirely until its exact content is trusted.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// Layer is one tier as written: scalars are pointers so "unset" differs from the zero value, which is
// what lets a higher tier override only what it sets. Flags are a Layer too.
type Layer struct {
	Leader       *string      `toml:"leader"`
	Tools        []string     `toml:"tools"`
	Env          []string     `toml:"env"`
	InheritEnv   *bool        `toml:"inherit_env"`
	InheritPath  *bool        `toml:"inherit_path"`
	AllowUserns  *bool        `toml:"allow_userns"`
	MaxPortRange *int         `toml:"max_port_range"`
	Limits       *LimitsLayer `toml:"limits"`
}

// LimitsLayer is the [limits] table as written.
type LimitsLayer struct {
	Pids     *int    `toml:"pids"`
	Memory   *string `toml:"memory"`
	CPU      *string `toml:"cpu"`
	Required *bool   `toml:"required"`
}

// Limits are per-session resource limits applied through a systemd user scope (best effort).
type Limits struct {
	Pids     int    // maximum processes and threads in the whole session
	Memory   string // systemd MemoryMax, e.g. "8G" or "50%"; empty means no cap
	CPU      string // systemd CPUQuota, e.g. "200%"; empty means no cap
	Required bool   // fail the start instead of warning when limits cannot be applied
}

// Config is the effective result.
type Config struct {
	Leader       string
	Tools        []string
	Env          []string
	InheritEnv   bool
	InheritPath  bool
	AllowUserns  bool
	MaxPortRange int
	Limits       Limits
}

// Defaults returns the built-in configuration. Memory and CPU stay unset: a default cap would kill
// legitimate builds, so it is the user's decision.
func Defaults() Config {
	return Config{Leader: `ctrl-\`, MaxPortRange: 1024, Limits: Limits{Pids: 4096}}
}

// Resolve applies layers in order (lowest precedence first) on top of the defaults: a set scalar replaces
// the earlier value, lists extend without duplicates.
func Resolve(layers ...Layer) Config {
	c := Defaults()
	for _, l := range layers {
		if l.Leader != nil {
			c.Leader = *l.Leader
		}
		if l.InheritEnv != nil {
			c.InheritEnv = *l.InheritEnv
		}
		if l.InheritPath != nil {
			c.InheritPath = *l.InheritPath
		}
		if l.AllowUserns != nil {
			c.AllowUserns = *l.AllowUserns
		}
		if l.MaxPortRange != nil {
			c.MaxPortRange = *l.MaxPortRange
		}
		if lim := l.Limits; lim != nil {
			if lim.Pids != nil {
				c.Limits.Pids = *lim.Pids
			}
			if lim.Memory != nil {
				c.Limits.Memory = *lim.Memory
			}
			if lim.CPU != nil {
				c.Limits.CPU = *lim.CPU
			}
			if lim.Required != nil {
				c.Limits.Required = *lim.Required
			}
		}
		c.Tools = extend(c.Tools, l.Tools)
		c.Env = extend(c.Env, l.Env)
	}
	return c
}

func extend(base, add []string) []string {
	seen := make(map[string]bool, len(base))
	for _, s := range base {
		seen[s] = true
	}
	for _, s := range add {
		if !seen[s] {
			seen[s] = true
			base = append(base, s)
		}
	}
	return base
}

var (
	leaderRe = regexp.MustCompile(`^ctrl-[\x21-\x7e]$`)
	memoryRe = regexp.MustCompile(`^([1-9][0-9]*[KMGT]?|[1-9][0-9]?%|100%)$`)
	cpuRe    = regexp.MustCompile(`^[1-9][0-9]{0,4}%$`)
	envRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Parse decodes and validates one config file. src is only used in error messages, which always name the
// file and the key.
func Parse(src string, data []byte) (Layer, error) {
	var l Layer
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		var miss *toml.StrictMissingError
		var de *toml.DecodeError
		switch {
		case errors.As(err, &miss):
			return Layer{}, fmt.Errorf("%s: unknown key %q", src, strings.Join(miss.Errors[0].Key(), "."))
		case errors.As(err, &de):
			row, _ := de.Position()
			if k := de.Key(); len(k) > 0 {
				return Layer{}, fmt.Errorf("%s: key %q (line %d): %s", src, strings.Join(k, "."), row, de.String())
			}
			return Layer{}, fmt.Errorf("%s: line %d: %s", src, row, de.String())
		}
		return Layer{}, fmt.Errorf("%s: %w", src, err)
	}
	if err := l.validate(src); err != nil {
		return Layer{}, err
	}
	return l, nil
}

func (l Layer) validate(src string) error {
	bad := func(key, why string) error { return fmt.Errorf("%s: key %q: %s", src, key, why) }
	if l.Leader != nil && !leaderRe.MatchString(*l.Leader) {
		return bad("leader", `must look like "ctrl-\" (ctrl- plus one printable character)`)
	}
	for _, t := range l.Tools {
		if !filepath.IsAbs(t) || filepath.Clean(t) != t {
			return bad("tools", fmt.Sprintf("%q must be a clean absolute path", t))
		}
	}
	for _, e := range l.Env {
		if !envRe.MatchString(e) {
			return bad("env", fmt.Sprintf("%q is not a valid variable name", e))
		}
	}
	if l.MaxPortRange != nil && (*l.MaxPortRange < 1 || *l.MaxPortRange > 65535) {
		return bad("max_port_range", "must be between 1 and 65535")
	}
	if lim := l.Limits; lim != nil {
		if lim.Pids != nil && (*lim.Pids < 16 || *lim.Pids > 4194304) {
			return bad("limits.pids", "must be between 16 and 4194304")
		}
		if lim.Memory != nil && !memoryRe.MatchString(*lim.Memory) {
			return bad("limits.memory", `must be a size such as "8G" or a percentage such as "50%"`)
		}
		if lim.CPU != nil && !cpuRe.MatchString(*lim.CPU) {
			return bad("limits.cpu", `must be a quota such as "200%"`)
		}
	}
	return nil
}
