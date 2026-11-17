package sandbox

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/H3mul/isolait/internal/initshim"
	"github.com/H3mul/isolait/internal/mountcheck"
	"github.com/H3mul/isolait/internal/plan"
)

// Launch starts the sandbox with the init shim as PID 1, waits for the shim to come up (which means bwrap
// has finished setting up every mount), and compares the live mount table with the plan before anything
// else may run in it. On any failure or mismatch the sandbox is killed and the error says what differed.
func Launch(s Spec, p *plan.Plan, stderr io.Writer) (*Sandbox, *initshim.Client, error) {
	d, shimEnd, err := initshim.Socketpair()
	if err != nil {
		return nil, nil, err
	}
	args := s.InitArgs
	if args == nil {
		args = []string{"init"}
	}
	box, err := Start(s, p, append([]string{InitPath}, args...), []*os.File{shimEnd}, nil, nil, stderr)
	shimEnd.Close()
	if err != nil {
		d.Close()
		return nil, nil, err
	}
	cl, err := initshim.NewClient(d)
	if err != nil {
		box.Kill()
		return nil, nil, err
	}
	abort := func(err error) (*Sandbox, *initshim.Client, error) {
		cl.Close()
		box.Kill()
		return nil, nil, err
	}
	pid, err := cl.WaitHello(10 * time.Second)
	if err != nil {
		return abort(fmt.Errorf("sandbox start: %w", err))
	}
	box.ShimPID = pid
	if err := mountcheck.Verify(box.ChildPID, p); err != nil {
		return abort(err)
	}
	return box, cl, nil
}

// Kill terminates the sandbox and waits for bwrap to exit.
func (sb *Sandbox) Kill() {
	if sb.Cmd.Process != nil {
		sb.Cmd.Process.Kill()
	}
	sb.Cmd.Wait()
}
