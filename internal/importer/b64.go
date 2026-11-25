package importer

import (
	"vpner/internal/i18n"

	"encoding/base64"
	"errors"
	"strings"
)

func b64(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New(i18n.T("importer.notBase64"))
}
