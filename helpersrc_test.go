package rig

import (
	"go/parser"
	"go/token"
	"io/fs"
	"strconv"
	"strings"
	"testing"
)

// The helper is compiled inside an image build with no module downloads, so
// it may import only the standard library and its own embedded packages.
func TestHelperSourceUsesOnlyTheStandardLibrary(t *testing.T) {
	allowed := map[string]bool{}
	for _, p := range HelperPackages {
		allowed[ModulePath+"/"+p] = true
	}

	files := 0
	err := fs.WalkDir(HelperSource, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		files++
		src, err := HelperSource.ReadFile(path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			first := strings.SplitN(p, "/", 2)[0]
			if strings.Contains(first, ".") && !allowed[p] {
				t.Errorf("%s imports %q; helper code must use only the standard library", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("no helper source embedded")
	}
}

// Every embedded package must actually be present, or the in-image build
// would fail with a missing import.
func TestHelperPackagesAreEmbedded(t *testing.T) {
	for _, p := range HelperPackages {
		entries, err := fs.ReadDir(HelperSource, p)
		if err != nil || len(entries) == 0 {
			t.Errorf("package %s is not embedded: %v", p, err)
		}
	}
}
