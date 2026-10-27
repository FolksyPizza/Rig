package main

import "testing"

func TestSplitContainerRef(t *testing.T) {
	tests := []struct {
		in        string
		container string
		path      string
		ok        bool
	}{
		{"my-sandbox:/workspace/out.txt", "my-sandbox", "/workspace/out.txt", true},
		{"rig-demo:/home/sandbox", "rig-demo", "/home/sandbox", true},

		// Host paths must never be mistaken for container references.
		{"./data.csv", "", "", false},
		{"/abs/path", "", "", false},
		{"~/data.csv", "", "", false},
		{"data.csv", "", "", false},

		// A colon alone is not enough: the path side must be absolute, which
		// is what `docker cp` requires anyway.
		{"weird:relative/path", "", "", false},
		{":/no/name", "", "", false},
		{"name:", "", "", false},
	}

	for _, tc := range tests {
		ref, ok := splitContainerRef(tc.in)
		if ok != tc.ok {
			t.Errorf("splitContainerRef(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && (ref.container != tc.container || ref.path != tc.path) {
			t.Errorf("splitContainerRef(%q) = %+v, want {%q %q}", tc.in, ref, tc.container, tc.path)
		}
	}
}

func TestSafeText(t *testing.T) {
	cases := map[string]string{
		"blocked example.org":          "blocked example.org",
		"clear\x1b[2Jscreen":           "clear\\u001b[2Jscreen",
		"title\x1b]0;pwned\x07":        "title\\u001b]0;pwned\\u0007",
		"line\nbreak":                  "line\\u000abreak",
		"bidi \u202egnp.exe":           "bidi \\u202egnp.exe",
		"c1 \u009b31m":                 "c1 \\u009b31m",
		"tab\there":                    "tab here",
		"accents café ✓":               "accents café ✓",
		string([]byte{'b', 0xff, 'd'}): "b\uFFFDd",
	}
	for in, want := range cases {
		if got := safeText(in); got != want {
			t.Errorf("safeText(%q) = %q, want %q", in, got, want)
		}
	}
}
