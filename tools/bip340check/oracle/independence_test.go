package oracle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func graph(dir, root string) error {
	goexe := os.Getenv("CURATOR_GO")
	if goexe == "" {
		goexe = "go"
	}
	cmd := exec.Command(goexe, "list", "-deps", "-json", ".")
	cmd.Dir = dir
	raw, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("go list failed: %w", err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	for {
		var p struct {
			ImportPath string
			Standard   bool
		}
		err := d.Decode(&p)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if !p.Standard && p.ImportPath != root {
			return fmt.Errorf("non-stdlib transitive import: %s", p.ImportPath)
		}
	}
	return nil
}

// This walks the actual oracle production import closure. The fixture control
// proves a transitive non-stdlib dependency is rejected, beside a stdlib-only
// positive. No btcec/decred or product helper may enter the reference closure.
func TestOracleTransitiveIndependence(t *testing.T) {
	if err := graph(".", "github.com/relux-works/swarma-envelope/tools/bip340check/oracle"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	put := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, path)), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, path), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	put("go.mod", "module example.invalid/oracle-control\n\ngo 1.26.0\n")
	put("root.go", "package control\nimport _ \"crypto/sha256\"\n")
	if err := graph(dir, "example.invalid/oracle-control"); err != nil {
		t.Fatal("valid graph control", err)
	}
	put("root.go", "package control\nimport _ \"example.invalid/oracle-control/relay\"\n")
	put("relay/relay.go", "package relay\nimport _ \"example.invalid/oracle-control/forbidden\"\n")
	put("forbidden/forbidden.go", "package forbidden\n")
	err := graph(dir, "example.invalid/oracle-control")
	if err == nil || !strings.Contains(err.Error(), "non-stdlib transitive import: example.invalid/oracle-control/forbidden") {
		t.Fatalf("intended transitive failure missing: %v", err)
	}
	t.Log(err)
}
