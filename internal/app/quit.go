package app

// AskQuit is called when the user chooses "Выход". If nothing is running it
// returns false (quit right away); otherwise the UI shows a confirmation
// with "Отключиться и выйти" / "Не выходить".
func (a *App) AskQuit() bool {
	a.mu.Lock()
	busy := a.running || a.starting
	a.quitAsk = busy
	a.mu.Unlock()
	a.notify()
	return busy
}

// CancelQuit hides the confirmation.
func (a *App) CancelQuit() {
	a.mu.Lock()
	a.quitAsk = false
	a.mu.Unlock()
	a.notify()
}
