package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

var verbRe = regexp.MustCompile(`%(?:\[\d+\])?[-+# 0]*\d*(?:\.\d+)?[a-zA-Z]`)

// Every language has every key, with the same placeholders.
func TestLocalesComplete(t *testing.T) {
	src := dicts[Source]
	if len(src) == 0 {
		t.Fatal("no source texts")
	}
	for lang, d := range dicts {
		for k, v := range src {
			tr, ok := d[k]
			if !ok {
				t.Errorf("%s: missing %s", lang, k)
				continue
			}
			if k == "meta.name" {
				continue
			}
			if a, b := strings.Join(verbRe.FindAllString(v, -1), " "), strings.Join(verbRe.FindAllString(tr, -1), " "); a != b {
				t.Errorf("%s: %s: placeholders %q, %s has %q", lang, k, b, Source, a)
			}
			// interface texts go into HTML as they are
			if strings.HasPrefix(k, "ui.") && strings.ContainsAny(tr, `<>"&`) {
				t.Errorf("%s: %s must not contain <, >, \" or &: %q", lang, k, tr)
			}
		}
		for k := range d {
			if _, ok := src[k]; !ok {
				t.Errorf("%s: %s is not in the %s file", lang, k, Source)
			}
		}
	}
}

func cyrillic(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cyrillic, r) {
			return true
		}
	}
	return false
}

// Texts that are not shown to the user and must stay as they are: patterns
// matching what servers, VPN clients and Windows print.
var allowed = map[string]bool{
	"internal/agent/conn.go":        true, // secretPromptRe: prompt words
	"internal/app/connect.go":       true, // passwordPromptRe: prompt words
	"internal/providers/wsl.go":     true, // answer patterns for server prompts
	"internal/winutil/autostart.go": true, // schtasks output
	"internal/hyperv/hyperv.go":     true, // PowerShell script
	"internal/install/install.go":   true, // PowerShell script
}

var allowedText = regexp.MustCompile(`\(\?i\)|не удается найти|\$name=%\[1\]s|CreateShortcut`)

// No user-visible Russian is left in the code, and every key used exists.
func TestNoTextsInCode(t *testing.T) {
	root := filepath.Join("..", "..")
	used := map[string]bool{}
	keyRe := regexp.MustCompile(`^[a-z]+\.[A-Za-z0-9.]+$`)
	fset := token.NewFileSet()
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if n := info.Name(); p != root && (strings.HasPrefix(n, ".") || n == "dist" || n == "build") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Error(err)
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "T" && len(call.Args) > 0 {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "i18n" {
						if l, ok := call.Args[0].(*ast.BasicLit); ok {
							k, _ := strconv.Unquote(l.Value)
							used[k] = true
						}
					}
				}
			}
			l, ok := n.(*ast.BasicLit)
			if !ok || l.Kind != token.STRING {
				return true
			}
			s, _ := strconv.Unquote(l.Value)
			if cyrillic(s) && !(allowed[rel] && allowedText.MatchString(s)) && !strings.Contains(s, "/home/vpner/Desktop/") {
				t.Errorf("%s: text in code, move it to the locales: %q", fset.Position(l.Pos()), s)
			}
			return true
		})
		return nil
	})
	html, err := os.ReadFile(filepath.Join(root, "internal", "web", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if cyrillic(string(html)) {
		t.Error("index.html: texts must come from the locales (tr(), data-i18n)")
	}
	// keys are tr("ui.x"), data-i18n="ui.x" and keys chosen by a condition
	for _, m := range regexp.MustCompile(`"(ui\.[A-Za-z0-9.]+)"`).FindAllStringSubmatch(string(html), -1) {
		used[m[1]] = true
	}
	for k := range used {
		if !keyRe.MatchString(k) {
			continue
		}
		if _, ok := dicts[Source][k]; !ok {
			t.Errorf("key %s is used but not in the locales", k)
		}
	}
	for k := range dicts[Source] {
		if !used[k] && k != "meta.name" {
			t.Errorf("key %s is not used anywhere", k)
		}
	}
}

func TestT(t *testing.T) {
	SetLang("en")
	defer SetLang(Source)
	if got := T("meta.name"); got != "English" {
		t.Errorf("T = %q", got)
	}
	if got := T("no.such.key"); got != "no.such.key" {
		t.Errorf("missing key = %q", got)
	}
}
