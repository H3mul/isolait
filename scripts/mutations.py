#!/usr/bin/env python3
"""Prove the security tests bite: apply each mutation to a scratch copy of the repo and require a test to fail.

Every row of docs/security-tests.md names a mutation that must fail its guard test. This script runs them, so
the claim is checked by code, not by memory. A mutation that no test catches (SURVIVED), a target string that
no longer exists in the source (DRIFT) or a mutation that does not compile (BUILD) fails the run.

    python3 scripts/mutations.py            # run everything (about a minute; needs the security tier's host features)
    python3 scripts/mutations.py --list
    python3 scripts/mutations.py M07 M13    # run some

The working tree is never modified: mutations are applied to a temporary copy.

Deliberately absent: removing the `os.Getpid() == 1` guard before kill(-1) in internal/initshim/shim.go. Run
anywhere but a PID namespace that line would signal every process the user owns; initshim's
TestShutdownLeavesUnrelatedProcessesAlone guards it, and it must never be exercised by mutation.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# id, file, exact text to replace, replacement, package, -run pattern, needs -tags security, timeout seconds
M = [
    ("M01", "internal/broker/broker.go", "syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,", "syscall.CLONE_NEWUSER,",
     "./internal/broker", "TestCommandRecipe|TestBrokerNamespace", True, 90),
    ("M02", "internal/sandbox/baseline.go", 'a = append(a, "--disable-userns")', "_ = a",
     "./internal/sandbox", "TestHardeningFlags|TestBaselineIsolation|TestNestedUsernsOptIn", True, 120),
    ("M03", "internal/sandbox/baseline.go", ' "--unshare-net",', "",
     "./internal/sandbox", "TestHardeningFlags|TestBaselineIsolation", True, 120),
    ("M04", "internal/sandbox/baseline.go", '"--die-with-parent", ', "",
     "./internal/sandbox", "TestHardeningFlags", False, 60),
    ("M05", "internal/sandbox/env.go", "if inherit {", "if true {",
     "./internal/sandbox", "TestBuildEnv", False, 60),
    ("M06", "internal/sandbox/binaries.go", "if o.InheritPath {", "if true {",
     "./internal/sandbox", "TestInheritPathFilter|TestAgentBehindSymlink", False, 60),
    ("M07", "internal/sandbox/binaries.go", "if !m.covers(resolved) {", "if false {",
     "./internal/sandbox", "TestAgentBehindSymlink|TestBinaryExposure", True, 120),
    ("M08", "internal/mounts/mounts.go", "a.set |= attrRdonly", "_ = attrRdonly",
     "./internal/mounts", "TestWorkspaceMountPrimitive", True, 90),
    ("M09", "internal/mounts/mounts.go", "openTreeClone|syscall.O_CLOEXEC|atEmptyPath", "openTreeClone|syscall.O_CLOEXEC|atEmptyPath|0x8000",
     "./internal/mounts", "TestWorkspaceMountPrimitive", True, 90),
    ("M10", "internal/mounts/mounts.go", "hasIsolait, err := HasIsolaitDir(real)", "hasIsolait, err := false, error(nil)",
     "./internal/mounts", "TestWorkspaceMountPrimitive", True, 90),
    ("M11", "internal/sandbox/launch.go", "if err := mountcheck.Verify(box.ChildPID, p); err != nil {",
     "if err := func() error { _ = mountcheck.Verify; return nil }(); err != nil {",
     "./internal/sandbox", "TestStartVerificationAbortsOnMisconfiguration", True, 120),
    ("M12", "internal/mountcheck/mountcheck.go", "want := func(flag string) {\n\t\tif !m.Opts[flag] {", "want := func(flag string) {\n\t\tif false && !m.Opts[flag] {",
     "./internal/mountcheck", "TestMismatchesAreReported|TestWorkspaceAndMaskEntries", False, 60),
    ("M13", "internal/config/load.go", "if !ok {", "if false && !ok {",
     "./internal/config", "TestUntrustedWorkspaceConfigIgnoredEntirely|TestTrustAppliesAndModificationRevokes", False, 60),
    ("M14", "internal/config/load.go", "os.O_RDONLY|syscall.O_NOFOLLOW", "os.O_RDONLY",
     "./internal/config", "TestWorkspaceSymlinksRefused", False, 60),
    ("M15", "internal/daemon/client.go", "if !session.ValidID(sid) {", "if false {",
     "./internal/daemon", "TestResolveTarget", False, 60),
    ("M16", "internal/cli/session.go", "if related(real, dir) {", "if false {",
     "./internal/cli", "TestCheckWorkdir", False, 60),
    ("M17", "internal/session/session.go", "case fi.Mode().Perm()&0o077 != 0:", "case false:",
     "./internal/session", "TestEnsurePrivateDirRefusals", False, 60),
    ("M18", "internal/plan/plan.go", "if o.Dst == e.Dst {", "if false {",
     "./internal/plan", "TestAddRejects", False, 60),
    ("M19", "internal/daemon/limits.go", ', "-p", "TasksMax=" + strconv.Itoa(l.Pids)}', "}",
     "./internal/daemon", "TestScopeArgs", False, 60),
    ("M20", "internal/daemon/limits.go", 'if l.Memory != "" {', "if false {",
     "./internal/daemon", "TestScopeArgs", False, 60),
    ("M21", "internal/initshim/shim.go", "pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)", "pid, err := 0, error(nil)\n\t\t_ = ws",
     "./internal/initshim", "TestSpawnExitCodeAndOutput", False, 90),
    ("M22", "internal/daemon/run.go", "return session.Remove(spec.RuntimeBase, spec.ID)", "return nil",
     "./internal/daemon", "TestSessionLifecycle", True, 150),
    ("M23", "internal/term/sanitize.go", "ok := s.n <= maxOSC && len(body) >= 2 && body[0] == '8' && body[1] == ';'", "ok := true",
     "./internal/term", "TestSanitizeTable|TestRandomStreamsNeverLeakForbiddenSequences", False, 60),
    ("M24", "internal/term/sanitize.go", "if final == 't' {", "if false {",
     "./internal/term", "TestSanitizeTable|TestRandomStreamsNeverLeakForbiddenSequences", False, 60),
    ("M25", "internal/term/sanitize.go", "case b == 'P' || b == '_' || b == '^' || b == 'X':", "case false:",
     "./internal/term", "TestSanitizeTable|TestRandomStreamsNeverLeakForbiddenSequences", False, 60),
    ("M26", "internal/term/sanitize.go", 'case "2004":', 'case "2004x":',
     "./internal/term", "TestSanitizeTable|TestModesAreTracked", False, 60),
    ("M27", "internal/term/sanitize.go", "s.out = s.out[:0]\n\tfor _, b := range p {", "s.out = s.out[:0]\n\ts.st = gnd\n\tfor _, b := range p {",
     "./internal/term", "TestSplitReadsGiveTheSameOutput|TestRandomStreamsNeverLeakForbiddenSequences", False, 60),
    ("M28", "internal/daemon/terminals.go", "\tif dst != nil {\n\t\tdst.send(attach.Frame{Type: attach.Data", "\tif dst == nil {\n\t\tselect {} // an unattended agent is no longer drained\n\t}\n\tif dst != nil {\n\t\tdst.send(attach.Frame{Type: attach.Data",
     "./internal/daemon", "TestUnattendedAgentNeverBlocksOnOutput", False, 60),
    ("M29", "internal/daemon/terminals.go", "if t.attached != nil {\n\t\tt.mu.Unlock()\n\t\tc.gate.Unlock()\n\t\tc.conn.SendJSON(attach.Hello, attach.Reply{Error: \"this session already", "if false {\n\t\tt.mu.Unlock()\n\t\tc.gate.Unlock()\n\t\tc.conn.SendJSON(attach.Hello, attach.Reply{Error: \"this session already",
     "./internal/daemon", "TestSecondAgentClientIsRejected", False, 60),
    ("M30", "internal/daemon/terminals.go", "if modes.AltScreen {", "if modes.AltScreen && false {",
     "./internal/daemon", "TestDetachKeepsAgentRunningAndReattachRestoresModes", False, 60),
    ("M31", "internal/daemon/terminals.go", "t.pump(c, p)\n\t// the client is gone (detach, closed terminal): an exec session does not outlive it\n\tt.cl.Signal(p.id, int(syscall.SIGHUP))\n\ttime.AfterFunc(2*time.Second, func() { t.cl.Signal(p.id, int(syscall.SIGKILL)) })", "t.pump(c, p)",
     "./internal/daemon", "TestExecDoesNotOutliveItsClient", False, 60),
    ("M32", "internal/daemon/terminals.go", "if !termRe.MatchString(termName) {", "if false {",
     "./internal/daemon", "TestTermIsSanitizedAndSizeClamped", False, 60),
    ("M33", "internal/daemon/terminals.go", "if cols < 1 || cols > 1000 {", "if false {",
     "./internal/daemon", "TestTermIsSanitizedAndSizeClamped", False, 60),
    ("M34", "internal/daemon/terminals.go", "dst.conn.SendJSON(attach.Exit, attach.ExitInfo{Code: e.Code, Signal: e.Signal})", "_ = e",
     "./internal/daemon", "TestAgentExitIsReportedAndReattachRestartsIt", False, 60),
]


def run_one(work, m):
    mid, rel, old, new, pkg, pattern, sec, tmo = m
    path = os.path.join(work, rel)
    with open(path) as f:
        original = f.read()
    if original.count(old) != 1:
        return "DRIFT", f"expected exactly one occurrence of {old!r} in {rel}, found {original.count(old)}", 0.0
    with open(path, "w") as f:
        f.write(original.replace(old, new))
    cmd = ["go", "test", "-count=1", "-run", pattern, pkg]
    if sec:
        cmd[2:2] = ["-tags", "security"]
    start = time.time()
    try:
        r = subprocess.run(cmd, cwd=work, capture_output=True, text=True, timeout=tmo)
        out, code = r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired as e:
        out, code = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""), 124
    finally:
        with open(path, "w") as f:
            f.write(original)
    took = time.time() - start
    if code == 0:
        return "SURVIVED", "tests passed with the mutation applied", took
    if re.search(r"\[build failed\]|\[setup failed\]|^# ", out, re.M) and "--- FAIL" not in out:
        return "BUILD", "the mutation does not compile:\n" + out[-600:], took
    if "--- FAIL" in out or code == 124:
        why = next((l.strip() for l in out.splitlines() if l.strip().startswith("--- FAIL")), "timed out (a hang counts as caught)")
        return "caught", why, took
    return "BUILD", "failed without a test failure:\n" + out[-600:], took


def main(argv):
    if "--list" in argv:
        for mid, rel, old, new, pkg, pattern, sec, _ in M:
            print(f"{mid}  {rel}: {old!r} -> {new!r}   [{pkg} -run {pattern}{' (security)' if sec else ''}]")
        return 0
    wanted = [a for a in argv if not a.startswith("-")]
    todo = [m for m in M if not wanted or m[0] in wanted]
    with tempfile.TemporaryDirectory(prefix="isolait-mut-") as work:
        shutil.copytree(REPO, work, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git", "isolait", ".claude"))
        bad = 0
        for m in todo:
            verdict, detail, took = run_one(work, m)
            print(f"{m[0]}  {verdict:8} {took:5.1f}s  {m[1]}  {detail.splitlines()[0] if detail else ''}")
            if verdict != "caught":
                bad += 1
                print("      " + detail.replace("\n", "\n      "))
    print(f"\n{len(todo) - bad}/{len(todo)} mutations caught")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
