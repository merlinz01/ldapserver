package ldapserver_test

import (
	"testing"

	"github.com/merlinz01/ldapserver"
)

func TestServerLifecycle(t *testing.T) {
	s := ldapserver.NewLDAPServer(nil)
	go func() {
		err := s.ListenAndServe("localhost:389")
		if err != nil {
			t.Error("Error listening:", err)
		}
	}()
	s.Shutdown()
}
