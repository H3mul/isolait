# Configuration

isolait reads TOML from two tiers. Precedence, highest first:

1. command-line flags
2. `<workspace>/.isolait/config` (the directory you start the session in), **only if trusted**
3. `$XDG_CONFIG_HOME/isolait/config` (default `~/.config/isolait/config`)
4. built-in defaults

Scalars override; lists extend without duplicates. Unknown keys and malformed values are errors that name the
file and key, and a session does not start on a config error. Only the starting workspace's `.isolait/config`
is read: never sub-directories, never directories added later with `isolait mount`.

## Keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `leader` | string | `ctrl-\` | Leader key: `ctrl-` plus a letter or one of `@ \ ] ^ _`; Escape, Enter, Tab, Backspace, Ctrl-C and Ctrl-D are refused |
| `tools` | list of paths | none | Extra read-only tool roots; clean absolute paths |
| `env` | list of names | none | Host environment variables forwarded into the sandbox |
| `inherit_env` | bool | `false` | Forward the whole host environment (opt-in, discouraged) |
| `inherit_path` | bool | `false` | Add filtered host `PATH` entries to the sandbox `PATH` |
| `allow_userns` | bool | `false` | Allow nested user namespaces inside the sandbox (weakens isolation) |
| `max_port_range` | int | `1024` | Largest port range one `allow port` may open (1 to 65535) |
| `limits.pids` | int | `4096` | Most processes and threads in the whole session (16 to 4194304) |
| `limits.memory` | string | unset | Memory cap for the whole session: a size such as `"8G"` or a percentage such as `"50%"` |
| `limits.cpu` | string | unset | CPU quota for the whole session, e.g. `"200%"` (two cores) |
| `limits.required` | bool | `false` | Fail `start` instead of warning when limits cannot be applied |

Example with every key:

```toml
leader = "ctrl-\\"
tools = ["/opt/toolchain"]
env = ["TERM", "LANG"]
inherit_env = false
inherit_path = false
allow_userns = false
max_port_range = 1024

[limits]
pids = 4096
memory = "8G"
cpu = "200%"
required = false
```

## Resource limits

Each session runs in its own systemd user scope, so a fork bomb or runaway memory use in the sandbox is
bounded: `limits.pids` always applies by default; memory and CPU are only capped when you set them (a default
cap would kill legitimate builds). Limits are best effort: on a host without a systemd user manager (for
example WSL2 without `systemd=true`) the session still starts, with a warning, and `isolait status` shows
`limits: unavailable (<reason>)`. Set `limits.required = true` to refuse to start instead.

## Trust

A repository can ship its own `.isolait/config`, so a workspace config is ignored entirely (no partial
application) until you run:

```
isolait trust [workspace]
```

It prints the file, then records the SHA-256 of its content in `$XDG_STATE_HOME/isolait/trust.json`
(default `~/.local/state/isolait/`, mode 0600). Trust is bound to content, not path: editing the file, or
replacing it with different content at the same path, makes it untrusted again until you re-run `trust`.
Identical content in another workspace is trusted too. `isolait start` prints a warning when it ignores an
untrusted config. `trust` refuses a file that would not load.

## Isolation of the config itself

The global config directory, isolait's state and runtime directories and every `.isolait` directory are never
visible to the sandbox. A workspace `.isolait` that is a symlink, or whose `config` is a symlink, is refused.
