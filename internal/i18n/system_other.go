//go:build !windows

package i18n

import (
	"os"
	"strings"
)

// System is the language from the environment ("ru", "en", ...).
func System() string {
	for _, v := range []string{"VPNER_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if l := os.Getenv(v); len(l) >= 2 {
			return strings.ToLower(l[:2])
		}
	}
	return "en"
}
