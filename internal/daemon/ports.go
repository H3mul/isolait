package daemon

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/H3mul/isolait/internal/ctl"
	"github.com/H3mul/isolait/internal/netd"
	"github.com/H3mul/isolait/internal/session"
)

// PortResult is the answer to an allow or deny: the ports this call changed and every port open afterwards.
type PortResult struct {
	Changed []int `json:"changed"`
	Open    []int `json:"open"`
}

// portOp applies a grant or revoke to the network engine. A grant is all or nothing: if one port of a range
// cannot be opened, the ones this call opened are closed again. A revoke closes whichever of the ports are open.
func portOp(e *netEngine, allow bool, spec string) (PortResult, error) {
	ports, err := netd.ParsePorts(spec)
	if err != nil {
		return PortResult{}, err
	}
	var changed []int
	if allow {
		open, err := openPorts(e)
		if err != nil {
			return PortResult{}, err
		}
		was := map[int]bool{}
		for _, p := range open {
			was[p] = true
		}
		for _, p := range ports {
			if was[int(p)] {
				continue
			}
			if _, err := e.command("allow " + strconv.Itoa(int(p))); err != nil {
				for _, c := range changed {
					e.command("deny " + strconv.Itoa(c))
				}
				return PortResult{}, err
			}
			changed = append(changed, int(p))
		}
	} else {
		for _, p := range ports {
			_, err := e.command("deny " + strconv.Itoa(int(p)))
			switch {
			case err == nil:
				changed = append(changed, int(p))
			case strings.HasSuffix(err.Error(), "is not open"):
			default:
				return PortResult{Changed: changed}, err
			}
		}
		if len(changed) == 0 {
			return PortResult{}, fmt.Errorf("no open grant matches %s", spec)
		}
	}
	open, err := openPorts(e)
	return PortResult{Changed: changed, Open: open}, err
}

// openPorts asks the engine which ports are open.
func openPorts(e *netEngine) ([]int, error) {
	out, err := e.command("list")
	if err != nil {
		return nil, err
	}
	p := []int{}
	for _, f := range strings.Fields(out) {
		n, _ := strconv.Atoi(f)
		p = append(p, n)
	}
	return p, nil
}

// AllowPorts opens a port or range ("8080", "3000-3010") on the running session's loopback.
func AllowPorts(base, id, spec string) (PortResult, error) {
	return portCall(base, id, "allow-ports", spec)
}

// DenyPorts closes the open grants in a port or range, ending their connections.
func DenyPorts(base, id, spec string) (PortResult, error) {
	return portCall(base, id, "deny-ports", spec)
}

func portCall(base, id, op, spec string) (PortResult, error) {
	resp, err := ctl.Call(session.SocketPath(base, id), ctl.Request{Op: op, Args: []string{spec}})
	if err != nil {
		return PortResult{}, err
	}
	var r PortResult
	return r, json.Unmarshal(resp.Data, &r)
}
