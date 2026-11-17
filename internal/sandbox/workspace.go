package sandbox

import "github.com/H3mul/isolait/internal/plan"

// AddWorkspace records a broker-mounted workspace (and its .isolait mask, if one was layered on it) in the
// plan, so the mountinfo checks know about it. The mounts themselves are made by mounts.MountWorkspace.
func AddWorkspace(p *plan.Plan, name, src string, ro, masked bool, emptyDir string) (dst string, err error) {
	dst = Workspaces + "/" + name
	if err := p.Add(plan.Entry{Kind: plan.Workspace, Src: src, Dst: dst, RO: ro}); err != nil {
		return "", err
	}
	if masked {
		if err := p.Add(plan.Entry{Kind: plan.Mask, Src: emptyDir, Dst: dst + "/.isolait", RO: true}); err != nil {
			return "", err
		}
	}
	return dst, nil
}
