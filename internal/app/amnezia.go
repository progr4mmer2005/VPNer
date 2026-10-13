package app

import (
	"fmt"
	"strings"

	"vpner/internal/amnezia"
	"vpner/internal/config"
)

// provisionAmnezia creates VPNer's own client on the user's Amnezia server
// for "full access" connections that do not have one yet.
func (a *App) provisionAmnezia(c *config.Connection) error {
	if c.Type != "amnezia-server" || strings.TrimSpace(c.S("config")) != "" {
		return nil
	}
	k, err := amnezia.ParseAdminKey(c.S("key"))
	if err != nil {
		return err
	}
	name := strings.TrimSpace(c.P("clientName"))
	if name == "" {
		name = "VPNer"
	}
	a.progress("Создаю пользователя «"+name+"» на сервере Amnezia", 0, -1)
	defer a.clearProgress()
	res, err := amnezia.AddClient(k, name, c.P("hostKey"), func(s string) { a.Log.Infof("app", "Amnezia: %s", s) })
	if err != nil {
		return fmt.Errorf("сервер Amnezia: %w", err)
	}
	if c.Secrets == nil {
		c.Secrets = map[string]string{}
	}
	c.Secrets["config"] = res.Config
	c.Params["clientId"] = res.ClientID
	c.Params["clientIp"] = res.IP
	c.Params["hostKey"] = res.HostKey
	return nil
}

// removeAmneziaClient deletes VPNer's client from the server (best effort).
func (a *App) removeAmneziaClient(c config.Connection) {
	if c.Type != "amnezia-server" || c.P("clientId") == "" {
		return
	}
	k, err := amnezia.ParseAdminKey(c.S("key"))
	if err != nil {
		return
	}
	if err := amnezia.RemoveClient(k, c.P("clientId"), c.P("hostKey")); err != nil {
		a.Log.Warnf("app", "не удалось удалить пользователя VPNer с сервера Amnezia: %v", err)
		return
	}
	a.Log.Infof("app", "пользователь VPNer удалён с сервера Amnezia")
}
