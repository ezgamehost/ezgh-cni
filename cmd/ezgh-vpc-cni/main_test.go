package main

import (
	"os"
	"path/filepath"
	"testing"
)

// install puts both plugins of the conflist into the CNI directory, executable.
func TestInstallCopiesBoth(t *testing.T) {
	src, dir := t.TempDir(), t.TempDir()
	self, portmap := filepath.Join(src, "self"), filepath.Join(src, "portmap")
	os.WriteFile(self, []byte("vpc-cni"), 0o755)
	os.WriteFile(portmap, []byte("portmap"), 0o755)
	if err := installInto(dir, self, portmap); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"ezgh-vpc-cni": "vpc-cni", "portmap": "portmap"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		st, _ := os.Stat(filepath.Join(dir, name))
		if err != nil || string(b) != want || st.Mode().Perm() != 0o755 {
			t.Fatalf("%s: %q %v %v", name, b, err, st.Mode())
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) != 0 {
		t.Fatal(left)
	}
}
