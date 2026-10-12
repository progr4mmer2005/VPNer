//go:build windows

package winutil

import (
	"encoding/xml"
	"os/exec"
	"strings"
)

func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return strings.ReplaceAll(b.String(), "'", "&apos;")
}

// Notify shows a Windows toast notification (best effort, non-blocking).
func Notify(title, text string) {
	toast := "<toast><visual><binding template='ToastGeneric'><text>" + xmlEscape(title) + "</text><text>" + xmlEscape(text) +
		"</text></binding></visual><audio src='ms-winsoundevent:Notification.Reminder'/></toast>"
	script := `[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml('` + strings.ReplaceAll(toast, "'", "''") + `')
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::new($x))`
	hidden(exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)).Start()
}
