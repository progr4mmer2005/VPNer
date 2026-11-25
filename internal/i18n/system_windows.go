//go:build windows

package i18n

import "golang.org/x/sys/windows"

var procGetUserDefaultUILanguage = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage")

// System is the language of the Windows interface ("ru", "en", ...).
func System() string {
	id, _, _ := procGetUserDefaultUILanguage.Call()
	switch id & 0x3ff { // primary language id
	case 0x19:
		return "ru"
	case 0x09:
		return "en"
	}
	return "en"
}
