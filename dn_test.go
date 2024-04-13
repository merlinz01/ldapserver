package ldapserver_test

import (
	"testing"

	"github.com/merlinz01/ldapserver"
)

func TestEncodeDN(t *testing.T) {
	type dnTest struct {
		dnStr string
		dn    ldapserver.DN
	}
	tests := []dnTest{
		{"uid=jdoe,ou=users,dc=example,dc=com",
			ldapserver.DN{{{"uid", "jdoe"}}, {{"ou", "users"}}, {{"dc", "example"}}, {{"dc", "com"}}}},
		{"UID=jsmith,DC=example,DC=net",
			ldapserver.DN{{{"UID", "jsmith"}}, {{"DC", "example"}}, {{"DC", "net"}}}},
		{"OU=Sales+CN=J.  Smith,DC=example,DC=net",
			ldapserver.DN{{{"OU", "Sales"}, {"CN", "J.  Smith"}}, {{"DC", "example"}}, {{"DC", "net"}}}},
		{"CN=James \\\"Jim\\\" Smith,DC=example,DC=net",
			ldapserver.DN{{{"CN", "James \"Jim\" Smith"}}, {{"DC", "example"}}, {{"DC", "net"}}}},
		{"CN=Before\\0DAfter,DC=example,DC=net",
			ldapserver.DN{{{"CN", "Before\rAfter"}}, {{"DC", "example"}}, {{"DC", "net"}}}},
		{"1.3.6.1.4.1.1466.0=#04024869",
			ldapserver.DN{{{"1.3.6.1.4.1.1466.0", "\x48\x69"}}}},
		{"CN=Lu\xC4\\8Di\xC4\\87",
			ldapserver.DN{{{"CN", "Lu\xC4\x8Di\xC4\x87"}}}},
		{"uid=jdoe,ou=C\\+\\+ Developers,dc=example,dc=com",
			ldapserver.DN{{{"uid", "jdoe"}}, {{"ou", "C++ Developers"}}, {{"dc", "example"}}, {{"dc", "com"}}}},
		{"cn=John Doe\\, Jr.,ou=Developers,dc=example,dc=com",
			ldapserver.DN{{{"cn", "John Doe, Jr."}}, {{"ou", "Developers"}}, {{"dc", "example"}}, {{"dc", "com"}}}},
		{"cn=\\\"John A. Doe\\, Sr.\\, C\\\\C\\+\\+ Developer\\\"+givenName=John+sn=Doe,ou=Developers,dc=example,dc=com",
			ldapserver.DN{{{"cn", `"John A. Doe, Sr., C\C++ Developer"`}, {"givenName", "John"}, {"sn", "Doe"}}, {{"ou", "Developers"}}, {{"dc", "example"}}, {{"dc", "com"}}}},
	}
	for _, dn := range tests {
		pdn, err := ldapserver.ParseDN(dn.dnStr)
		if err != nil {
			t.Fatalf("Error parsing DN: %s", err)
		} else if !pdn.Equal(dn.dn) {
			t.Errorf("Expected %s", dn.dn)
			t.Fatalf("Got      %s", pdn)
		} else if pdn.String() != dn.dnStr {
			t.Errorf("Expected %s", dn.dnStr)
			t.Fatalf("Got      %s", pdn.String())
		}
	}
}
