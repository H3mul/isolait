package sandbox

import "testing"

func TestEveryDeniedSyscallResolves(t *testing.T) {
	if _, err := seccompDenies(); err != nil {
		t.Fatal(err)
	}
	// absent must be real: a name listed as absent that does resolve means the table is stale
	for n := range absentSyscalls {
		if _, ok := syscallNumbers[n]; ok {
			t.Errorf("%s is marked absent but resolves on this architecture", n)
		}
	}
}

func TestMisspeltSyscallIsAnError(t *testing.T) {
	denyTable[0].names = append(denyTable[0].names, "keyctll")
	defer func() { denyTable[0].names = denyTable[0].names[:3] }()
	if _, err := seccompDenies(); err == nil {
		t.Fatal("a misspelt name was accepted")
	}
}
