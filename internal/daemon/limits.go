package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Limits are the resource limits applied to the whole session through a systemd user scope.
type Limits struct {
	Pids     int    // TasksMax
	Memory   string // MemoryMax, empty for no cap
	CPU      string // CPUQuota, empty for no cap
	Required bool   // fail the start when limits cannot be applied
}

// LimitsStatus is what `isolait status` shows about limits.
type LimitsStatus struct {
	Available     bool   `json:"available"`
	Reason        string `json:"reason,omitempty"` // why not, when unavailable
	PidsCurrent   int64  `json:"pids_current"`
	PidsMax       int64  `json:"pids_max"` // 0: unlimited
	MemoryCurrent uint64 `json:"memory_current"`
	MemoryMax     uint64 `json:"memory_max"` // 0: unlimited
}

// ScopeArgs are the systemd-run arguments that run `exe _spawn` in a transient user scope named for the
// session with the given limits. The scope lives as long as any process in it, so it outlives the short-lived
// `_spawn` and ends with the session's daemon.
func ScopeArgs(unit string, l Limits, exe string) []string {
	a := []string{"--user", "--scope", "--quiet", "--collect", "--unit=" + unit, "-p", "TasksMax=" + strconv.Itoa(l.Pids)}
	if l.Memory != "" {
		a = append(a, "-p", "MemoryMax="+l.Memory)
	}
	if l.CPU != "" {
		a = append(a, "-p", "CPUQuota="+l.CPU)
	}
	return append(a, "--", exe, "_spawn")
}

// ReadUsage reads pids and memory usage and limits for the cgroup that selfCgroup names (a line of
// /proc/self/cgroup, "0::/user.slice/.../isolait-x.scope") below the cgroup2 mount at fsRoot.
func ReadUsage(fsRoot, selfCgroup string) LimitsStatus {
	path := strings.TrimPrefix(strings.TrimSpace(selfCgroup), "0::")
	if path == strings.TrimSpace(selfCgroup) || path == "" {
		return LimitsStatus{Reason: "not in a cgroup v2 hierarchy"}
	}
	dir := filepath.Join(fsRoot, path)
	var st LimitsStatus
	var err error
	if st.PidsCurrent, err = readInt(dir, "pids.current"); err != nil {
		return LimitsStatus{Reason: "cannot read " + filepath.Join(dir, "pids.current")}
	}
	st.PidsMax, _ = readInt(dir, "pids.max")
	mc, _ := readInt(dir, "memory.current")
	mm, _ := readInt(dir, "memory.max")
	st.MemoryCurrent, st.MemoryMax = uint64(mc), uint64(mm)
	st.Available = true
	return st
}

// readInt parses a cgroup file holding one number; "max" (no limit) and unreadable files give 0.
func readInt(dir, name string) (int64, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	if s == "max" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return n, nil
}

// SelfUsage reads the usage of the cgroup this process is in.
func SelfUsage() LimitsStatus {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return LimitsStatus{Reason: err.Error()}
	}
	return ReadUsage("/sys/fs/cgroup", strings.SplitN(string(b), "\n", 2)[0])
}
