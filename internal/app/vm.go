package app

import (
	"vpner/internal/providers"
)

// VMRuntime is implemented by connection types that run inside a dedicated
// virtual machine.
type VMRuntime = providers.VMProvider

func (a *App) connectVM(id string, p VMRuntime) error {
	return a.vmConnect(id, p)
}

func (a *App) stopVM(id string) {
	a.vmStop(id)
}
