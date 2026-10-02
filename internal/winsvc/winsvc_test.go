package winsvc

import "testing"

func TestRunOutsideServiceManagerRunsDirectly(t *testing.T) {
	called := false
	if code := Run(func() int { called = true; return 7 }); code != 7 || !called {
		t.Fatal(code, called)
	}
	if Active() {
		t.Fatal("not running under the service manager")
	}
	if Context() == nil || Context().Err() != nil {
		t.Fatal("base context must be live")
	}
}
