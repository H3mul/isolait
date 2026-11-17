package mounts

import "testing"

func TestNames(t *testing.T) {
	for in, want := range map[string]string{
		"/home/u/api":        "api",
		"/home/u/my project": "my-project",
		"/home/u/.hidden":    "hidden",
		"/":                  "workspace",
		"/home/u/é☃":         "workspace",
		"/a/we..ird":         "workspace",
		"/a/Sub.dir_1-x":     "Sub.dir_1-x",
	} {
		if got := NameFor(in); got != want {
			t.Errorf("NameFor(%q)=%q want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", ".x", "a/b", "..", "a..b", "-x", string(make([]byte, 65))} {
		if ValidName(bad) {
			t.Errorf("ValidName(%q) should be false", bad)
		}
	}
	if !ValidName("api") || !ValidName("a.b-c_d") {
		t.Error("valid names rejected")
	}
}
