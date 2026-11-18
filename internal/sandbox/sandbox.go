package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"

	"github.com/H3mul/isolait/internal/plan"
)

// renderArgs is Args; tests replace it to inject a misconfiguration and prove the mount check catches it.
var renderArgs = Args

// Sandbox is a running bwrap. PID 1 inside it is the command passed to Start.
type Sandbox struct {
	Cmd      *exec.Cmd
	ChildPID int // PID of the sandbox's PID 1 as seen from the broker
	ShimPID  int // the init shim's own PID inside the sandbox (set by Launch; 1 when it is PID 1)
	Plan     *plan.Plan
	Denied   int // number of system calls the session's seccomp filter denies
}

// Start launches bwrap with the baseline for s, running argv as PID 1 of the sandbox. It must run in the
// broker's mount namespace. extra files become fds 4, 5, ... in the sandbox (fd 3 is bwrap's info pipe);
// stdin/stdout/stderr may be nil (discarded).
func Start(s Spec, p *plan.Plan, argv []string, extra []*os.File, stdin io.Reader, stdout, stderr io.Writer) (*Sandbox, error) {
	if len(argv) == 0 {
		return nil, errors.New("sandbox: empty command")
	}
	bwrap := s.Bwrap
	if bwrap == "" {
		var err error
		if bwrap, err = exec.LookPath("bwrap"); err != nil {
			return nil, errors.New("bwrap not found in PATH")
		}
	}
	r, w, err := os.Pipe() // bwrap writes {"child-pid": N} here once the sandbox exists
	if err != nil {
		return nil, err
	}
	defer r.Close()

	files := append([]*os.File{w}, extra...) // w becomes fd 3, extra fd 4 onward
	flags := []string{"--info-fd", "3"}
	var releaseR, releaseW *os.File
	if s.OnNetns != nil {
		if releaseR, releaseW, err = os.Pipe(); err != nil {
			return nil, err
		}
		defer releaseR.Close()
		defer releaseW.Close()
		files = append(files, releaseR)
		flags = append(flags, "--block-fd", strconv.Itoa(3+len(files)-1))
	}
	// the deny list is always applied; a failure to build or pass it is a start error, never a silent skip
	prog, n, err := SeccompProgram()
	if err != nil {
		return nil, err
	}
	secR, secW, err := os.Pipe() // bwrap reads the program from this fd until EOF; it is far below the pipe buffer
	if err != nil {
		return nil, err
	}
	defer secR.Close()
	if _, err := secW.Write(prog); err != nil {
		secW.Close()
		return nil, fmt.Errorf("seccomp: %w", err)
	}
	secW.Close()
	files = append(files, secR)
	flags = append(flags, "--seccomp", strconv.Itoa(3+len(files)-1))
	args := renderArgs(s, p, flags...)
	args = append(args, "--")
	args = append(args, argv...)
	cmd := exec.Command(bwrap, args...)
	cmd.Env = []string{} // bwrap's own environment is irrelevant; the sandbox gets --clearenv plus --setenv
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.ExtraFiles = files
	if err := cmd.Start(); err != nil {
		w.Close()
		return nil, err
	}
	w.Close() // bwrap holds the only write end now; EOF means it has finished reporting (or died)

	var info struct {
		ChildPID int `json:"child-pid"`
	}
	if err := json.NewDecoder(r).Decode(&info); err != nil || info.ChildPID == 0 {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, fmt.Errorf("sandbox did not start (no child pid from bwrap): %v", err)
	}
	if s.OnNetns != nil {
		// the sandbox exists in its namespaces but is blocked: bring up its network, then let it go
		if err := s.OnNetns(info.ChildPID); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return nil, err
		}
		if _, err := releaseW.Write([]byte{1}); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return nil, fmt.Errorf("releasing the sandbox: %w", err)
		}
	}
	return &Sandbox{Cmd: cmd, ChildPID: info.ChildPID, Plan: p, Denied: n}, nil
}

// Wait waits for the sandbox's PID 1 to exit.
func (sb *Sandbox) Wait() error { return sb.Cmd.Wait() }
