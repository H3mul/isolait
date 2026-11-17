package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/H3mul/isolait/internal/ctl"
	"github.com/H3mul/isolait/internal/mounts"
	"github.com/H3mul/isolait/internal/plan"
	"github.com/H3mul/isolait/internal/sandbox"
	"github.com/H3mul/isolait/internal/session"
)

// SpecFD is the descriptor the launcher passes the spec pipe as.
const SpecFD = 3

// RunFromFD reads the spec from SpecFD and runs the session. It is the body of the hidden `isolait daemon`
// command, executed inside the broker's namespaces.
func RunFromFD() error {
	var spec Spec
	if err := json.NewDecoder(os.NewFile(SpecFD, "spec")).Decode(&spec); err != nil {
		return fmt.Errorf("reading session spec: %w", err)
	}
	err := Run(spec)
	if err != nil {
		// stdout and stderr go to the session log; the launcher also looks here for the reason
		os.WriteFile(filepath.Join(session.Dir(spec.RuntimeBase, spec.ID), "error"), []byte(err.Error()+"\n"), 0o600)
	}
	return err
}

type sessionState struct {
	mu       sync.Mutex
	state    string
	spec     Spec
	plan     *plan.Plan
	bins     sandbox.Binaries
	envNames []string
}

func (s *sessionState) status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{ID: s.spec.ID, State: s.state, PID: os.Getpid(), Started: s.spec.Started, Workdir: s.spec.Workdir,
		Roots: s.bins.Roots, Ports: []int{}, EnvNames: s.envNames, Warnings: s.bins.Warnings}
	for _, e := range s.plan.Entries() {
		if e.Kind == plan.Workspace {
			mode := "rw"
			if e.RO {
				mode = "ro"
			}
			st.Mounts = append(st.Mounts, MountInfo{Path: e.Dst, Src: e.Src, Mode: mode})
		}
	}
	return st
}

// Run builds the sandbox for spec, serves the control socket until the session ends, then cleans up.
// It must run in the broker's mount namespace.
func Run(spec Spec) error {
	dir := session.Dir(spec.RuntimeBase, spec.ID)
	if err := os.WriteFile(filepath.Join(dir, "pid"), []byte(fmt.Sprintln(os.Getpid())), 0o600); err != nil {
		return err
	}
	stage := filepath.Join(dir, "stage")
	empty := filepath.Join(dir, "empty")
	for _, d := range []string{stage, empty} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return err
		}
	}
	agentName := session.Base(spec.Agent[0])
	home := filepath.Join(spec.StateDir, "homes", agentName)
	for _, d := range []string{spec.StateDir, filepath.Join(spec.StateDir, "homes"), home} {
		if err := session.EnsurePrivateDir(d); err != nil {
			return err
		}
	}
	if err := syscall.Mount("tmpfs", stage, "tmpfs", 0, "mode=0755"); err != nil {
		return fmt.Errorf("mounting the stage: %w", err)
	}
	if err := syscall.Mount("", stage, "", syscall.MS_SHARED, ""); err != nil {
		syscall.Unmount(stage, syscall.MNT_DETACH)
		return fmt.Errorf("making the stage shared: %w", err)
	}
	defer syscall.Unmount(stage, syscall.MNT_DETACH) // error paths; the normal path unmounts before removing the directory

	bins, err := sandbox.ResolveBinaries(sandbox.BinOptions{Agent: spec.Agent[0], HostPath: spec.HostPath,
		InheritPath: spec.InheritPath, Tools: spec.Tools, Home: spec.HostHome})
	if err != nil {
		return err
	}
	env, err := sandbox.BuildEnv(spec.HostEnv, spec.EnvNames, spec.InheritEnv,
		map[string]string{"HOME": spec.HostHome, "USER": spec.User, "LOGNAME": spec.User, "PATH": bins.Path()})
	if err != nil {
		return err
	}
	bs := sandbox.Spec{HostHome: spec.HostHome, AgentHome: home, Stage: stage, AllowUserns: spec.AllowUserns,
		Env: env, UID: spec.UID, GID: spec.GID, InitExe: spec.InitExe, InitArgs: spec.InitArgs, Bwrap: spec.Bwrap}
	p, err := sandbox.BuildPlan(bs)
	if err != nil {
		return err
	}
	if err := sandbox.AddBinaries(p, bins); err != nil {
		return err
	}
	masked, err := mounts.MountWorkspace(stage, spec.Name, spec.Workdir, spec.RO, empty)
	if err != nil {
		return err
	}
	real, _ := filepath.EvalSymlinks(spec.Workdir)
	dst, err := sandbox.AddWorkspace(p, spec.Name, real, spec.RO, masked, empty)
	if err != nil {
		return err
	}
	bs.Chdir = dst

	box, cl, err := sandbox.Launch(bs, p, os.Stderr)
	if err != nil {
		return err
	}
	defer cl.Close()

	st := &sessionState{state: "idle", spec: spec, plan: p, bins: bins}
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		st.envNames = append(st.envNames, k)
	}
	sort.Strings(st.envNames)

	srv, err := ctl.Listen(session.SocketPath(spec.RuntimeBase, spec.ID))
	if err != nil {
		box.Kill()
		return err
	}
	exited := make(chan struct{})
	go func() { box.Wait(); close(exited) }()
	stopping := make(chan struct{})
	var once sync.Once
	go srv.Serve(func(r ctl.Request) (any, error) {
		switch r.Op {
		case "ping":
			return "pong", nil
		case "status":
			return st.status(), nil
		case "stop":
			once.Do(func() { close(stopping) })
			return "stopping", nil
		}
		return nil, fmt.Errorf("unknown operation %q", r.Op)
	})

	select {
	case <-stopping:
		st.mu.Lock()
		st.state = "stopping"
		st.mu.Unlock()
		cl.Shutdown()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			box.Kill()
		}
	case <-exited: // init gone: the session ends with it
	}
	srv.Close()
	syscall.Unmount(stage, syscall.MNT_DETACH) // lazy: takes the workspace and mask mounts below it along
	return session.Remove(spec.RuntimeBase, spec.ID)
}
