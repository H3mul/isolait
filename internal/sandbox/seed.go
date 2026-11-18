package sandbox

import (
	"io/fs"
	"os"
	"path/filepath"
)

// SkelDir is the skeleton the agent home is seeded from.
const SkelDir = "/etc/skel"

// embeddedSkel is used when the skeleton directory has no regular files: a minimal Ubuntu-like bash setup.
var embeddedSkel = map[string]string{
	".profile": `# ~/.profile: executed by bash for login shells.
if [ -n "$BASH_VERSION" ] && [ -f "$HOME/.bashrc" ]; then
    . "$HOME/.bashrc"
fi
`,
	".bashrc": `# ~/.bashrc: executed by bash for interactive non-login shells.
case $- in
    *i*) ;;
      *) return;;
esac

HISTCONTROL=ignoreboth
shopt -s histappend
HISTSIZE=1000
HISTFILESIZE=2000
shopt -s checkwinsize

alias ls='ls --color=auto'
alias grep='grep --color=auto'
PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
`,
	".bash_logout": "# ~/.bash_logout: executed by bash when a login shell exits.\n",
}

// SeedHome creates the files of skel (the embedded set when skel has none) that are missing from home.
// Existing files are never touched and nothing is read from the user's real home.
func SeedHome(home, skel string) error {
	found := false
	err := filepath.WalkDir(skel, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == skel {
				return nil // no skeleton directory
			}
			return err
		}
		rel, _ := filepath.Rel(skel, p)
		dst := filepath.Join(home, rel)
		switch {
		case d.IsDir():
			if rel == "." {
				return nil
			}
			return os.MkdirAll(dst, 0o755)
		case d.Type().IsRegular():
			found = true
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return writeIfMissing(dst, b)
		}
		return nil // symlinks and special files are not copied
	})
	if err != nil || found {
		return err
	}
	for name, body := range embeddedSkel {
		if err := writeIfMissing(filepath.Join(home, name), []byte(body)); err != nil {
			return err
		}
	}
	return nil
}

func writeIfMissing(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
