// Package i18n holds the program's texts in every language. Code refers to
// a text by its key (T("app.routingIsOn")); locales/<lang>.json map keys to
// texts. Adding a language is adding a file.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync/atomic"
)

//go:embed locales/*.json
var files embed.FS

// Source is the language every key must exist in.
const Source = "ru"

var (
	dicts = map[string]map[string]string{}
	cur   atomic.Value // string
)

func init() {
	entries, err := files.ReadDir("locales")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		b, err := files.ReadFile("locales/" + e.Name())
		if err != nil {
			panic(err)
		}
		d := map[string]string{}
		if err := json.Unmarshal(b, &d); err != nil {
			panic(fmt.Sprintf("i18n: %s: %v", e.Name(), err))
		}
		dicts[strings.TrimSuffix(e.Name(), path.Ext(e.Name()))] = d
	}
	cur.Store(Source)
}

// Languages lists the available languages, sorted.
func Languages() []string {
	out := make([]string, 0, len(dicts))
	for l := range dicts {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// Has reports whether a language is available.
func Has(lang string) bool { _, ok := dicts[lang]; return ok }

// Resolve turns a setting ("" = like the system) into an available language.
func Resolve(setting string) string {
	if Has(setting) {
		return setting
	}
	if l := System(); Has(l) {
		return l
	}
	return "en"
}

// SetLang switches the language of everything produced from now on.
func SetLang(lang string) {
	if Has(lang) {
		cur.Store(lang)
	}
}

// Lang is the current language.
func Lang() string { return cur.Load().(string) }

// T returns the text of key in the current language (falling back to the
// source language, then to the key itself), formatted with args if any.
func T(key string, args ...any) string {
	s, ok := dicts[Lang()][key]
	if !ok {
		if s, ok = dicts[Source][key]; !ok {
			s = key
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// Name is the language's own name ("Русский", "English").
func Name(lang string) string {
	if n := dicts[lang]["meta.name"]; n != "" {
		return n
	}
	return lang
}

// Dict returns the texts of a language whose keys start with prefix.
func Dict(lang, prefix string) map[string]string {
	out := map[string]string{}
	for k, v := range dicts[lang] {
		if strings.HasPrefix(k, prefix) {
			out[k] = v
		}
	}
	return out
}
