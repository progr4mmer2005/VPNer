package app

import (
	"sync"
	"testing"
)

// Clicking Connect again while a connection is still starting (the engine
// downloading, a VM being created) must not start it a second time: before,
// every click created one more VM.
func TestConnectRunsOnce(t *testing.T) {
	a := &App{}
	if !a.beginConnect("vm") {
		t.Fatal("the first start must run")
	}
	var wg sync.WaitGroup
	started := 0
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a.beginConnect("vm") {
				mu.Lock()
				started++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if started != 0 {
		t.Fatalf("%d more starts ran while the first one was running", started)
	}
	if !a.beginConnect("other") {
		t.Error("another connection must not wait for this one")
	}
	a.endConnect("vm")
	if !a.beginConnect("vm") {
		t.Error("after the first start ends, a new one must run")
	}
}
