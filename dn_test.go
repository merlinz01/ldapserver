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
			ldapserver.DN{{{"dc", "com"}}, {{"dc", "example"}}, {{"ou", "users"}}, {{"uid", "jdoe"}}}},
		{"UID=jsmith,DC=example,DC=net",
			ldapserver.DN{{{"DC", "net"}}, {{"DC", "example"}}, {{"UID", "jsmith"}}}},
		{"CN=J.  Smith+OU=Sales,DC=example,DC=net",
			ldapserver.DN{{{"DC", "net"}}, {{"DC", "example"}}, {{"CN", "J.  Smith"}, {"OU", "Sales"}}}},
		{"CN=James \\\"Jim\\\" Smith,DC=example,DC=net",
			ldapserver.DN{{{"DC", "net"}}, {{"DC", "example"}}, {{"CN", "James \"Jim\" Smith"}}}},
		{"CN=Before\\0DAfter,DC=example,DC=net",
			ldapserver.DN{{{"DC", "net"}}, {{"DC", "example"}}, {{"CN", "Before\rAfter"}}}},
		{"1.3.6.1.4.1.1466.0=#04024869",
			ldapserver.DN{{{"1.3.6.1.4.1.1466.0", "\x48\x69"}}}},
		{"CN=Lu\xC4\\8Di\xC4\\87",
			ldapserver.DN{{{"CN", "Lu\xC4\x8Di\xC4\x87"}}}},
		{"uid=jdoe,ou=C\\+\\+ Developers,dc=example,dc=com",
			ldapserver.DN{{{"dc", "com"}}, {{"dc", "example"}}, {{"ou", "C++ Developers"}}, {{"uid", "jdoe"}}}},
		{"cn=John Doe\\, Jr.,ou=Developers,dc=example,dc=com",
			ldapserver.DN{{{"dc", "com"}}, {{"dc", "example"}}, {{"ou", "Developers"}}, {{"cn", "John Doe, Jr."}}}},
		{"cn=\\\"John A. Doe\\, Sr.\\, C\\\\C\\+\\+ Developer\\\"+givenName=John+sn=Doe,ou=Developers,dc=example,dc=com",
			ldapserver.DN{{{"dc", "com"}}, {{"dc", "example"}}, {{"ou", "Developers"}}, {{"cn", `"John A. Doe, Sr., C\C++ Developer"`}, {"givenName", "John"}, {"sn", "Doe"}}}},
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

func TestDNIsChild(t *testing.T) {
	type childTest struct {
		child   string
		parent  string
		isChild bool
	}
	childTests := []childTest{
		{"uid=jdoe,ou=users,dc=example,dc=com", "ou=users,dc=example,dc=com", true},
		{"ou=users,dc=example,dc=com", "dc=example,dc=com", true},
		{"dc=example,dc=com", "dc=com", true},
		{"dc=com", "", true},
		{"", "dc=com", false},
		{"", "", false},
		{"uid=jdoe,ou=users,dc=example,dc=com", "", false},
		{"uid=jdoe,ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com", false},
		{"ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=org", false},
		{"uid=jdoe,ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com,dc=org", false},
	}
	for _, test := range childTests {
		parent, err := ldapserver.ParseDN(test.parent)
		if err != nil {
			t.Fatalf("Error parsing parent DN: %s", err)
		}
		child, err := ldapserver.ParseDN(test.child)
		if err != nil {
			t.Fatalf("Error parsing child DN: %s", err)
		}
		if child.IsChild(parent) != test.isChild {
			t.Errorf("Expected %t, got %t for \"%s\" is child of \"%s\"", test.isChild, !test.isChild, test.child, test.parent)
		}
	}
}

func TestDNIsParent(t *testing.T) {
	type parentTest struct {
		parent  string
		child   string
		isChild bool
	}
	parentTests := []parentTest{
		{"ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com", true},
		{"dc=example,dc=com", "ou=users,dc=example,dc=com", true},
		{"dc=com", "dc=example,dc=com", true},
		{"", "dc=com", true},
		{"dc=com", "", false},
		{"", "", false},
		{"dc=com", "uid=jdoe,ou=users,dc=example,dc=com", false},
		{"uid=jdoe,ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com", false},
		{"uid=jdoe,ou=users,dc=example,dc=com,dc=org", "uid=jdoe,ou=users,dc=example,dc=com", false},
	}
	for _, test := range parentTests {
		parent, err := ldapserver.ParseDN(test.parent)
		if err != nil {
			t.Fatalf("Error parsing parent DN: %s", err)
		}
		child, err := ldapserver.ParseDN(test.child)
		if err != nil {
			t.Fatalf("Error parsing child DN: %s", err)
		}
		if parent.IsParent(child) != test.isChild {
			t.Errorf("Expected %t, got %t for \"%s\" is parent of \"%s\"", test.isChild, !test.isChild, test.parent, test.child)
		}
	}
}

func TestDNIsSuperior(t *testing.T) {
	type superiorTest struct {
		superior string
		inferior string
		isSuper  bool
	}
	superiorTests := []superiorTest{
		{"ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com", true},
		{"dc=example,dc=com", "ou=users,dc=example,dc=com", true},
		{"dc=com", "dc=example,dc=com", true},
		{"dc=com", "uid=jdoe,ou=users,dc=example,dc=com", true},
		{"", "dc=com", true},
		{"dc=com", "", false},
		{"", "", false},
		{"uid=jdoe,ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com", false},
		{"ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com,dc=org", false},
		{"ou=users,dc=example,dc=com,dc=org", "uid=jdoe,ou=users,dc=example,dc=com", false},
	}
	for _, test := range superiorTests {
		superior, err := ldapserver.ParseDN(test.superior)
		if err != nil {
			t.Fatalf("Error parsing superior DN: %s", err)
		}
		inferior, err := ldapserver.ParseDN(test.inferior)
		if err != nil {
			t.Fatalf("Error parsing inferior DN: %s", err)
		}
		if superior.IsSuperior(inferior) != test.isSuper {
			t.Errorf("Expected %t, got %t for \"%s\" is superior of \"%s\"", test.isSuper, !test.isSuper, test.superior, test.inferior)
		}
	}
}

func TestDNIsSubordinate(t *testing.T) {
	type subordinateTest struct {
		subordinate string
		superior    string
		isSub       bool
	}
	subordinateTests := []subordinateTest{
		{"uid=jdoe,ou=users,dc=example,dc=com", "ou=users,dc=example,dc=com", true},
		{"ou=users,dc=example,dc=com", "dc=example,dc=com", true},
		{"dc=example,dc=com", "dc=com", true},
		{"dc=com", "", true},
		{"", "dc=com", false},
		{"", "", false},
		{"uid=jdoe,ou=users,dc=example,dc=com", "", true},
		{"uid=jdoe,ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com", false},
		{"ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=org", false},
		{"uid=jdoe,ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com,dc=org", false},
	}
	for _, test := range subordinateTests {
		subordinate, err := ldapserver.ParseDN(test.subordinate)
		if err != nil {
			t.Fatalf("Error parsing subordinate DN: %s", err)
		}
		superior, err := ldapserver.ParseDN(test.superior)
		if err != nil {
			t.Fatalf("Error parsing superior DN: %s", err)
		}
		if subordinate.IsSubordinate(superior) != test.isSub {
			t.Errorf("Expected %t, got %t for \"%s\" is subordinate of \"%s\"", test.isSub, !test.isSub, test.subordinate, test.superior)
		}
	}
}

func TestDNIsSibling(t *testing.T) {
	type siblingTest struct {
		dn1   string
		dn2   string
		isSib bool
	}
	siblingTests := []siblingTest{
		{"uid=jdoe,ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com", true},
		{"ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com", false},
		{"uid=jdoe,ou=users,dc=example,dc=com", "ou=users,dc=example,dc=com", false},
		{"ou=printers,dc=example,dc=com", "ou=users,dc=example,dc=com", true},
		{"ou=users,dc=example,dc=com", "ou=printers,dc=example,dc=com", true},
		{"ou=users,dc=example,dc=com", "ou=users,dc=example,dc=org", false},
		{"ou=users,dc=example,dc=com", "ou=users,dc=example,dc=com,dc=org", false},
		{"", "", true},
		{"", "dc=com", false},
		{"dc=com", "dc=org", true},
	}
	for _, test := range siblingTests {
		dn1, err := ldapserver.ParseDN(test.dn1)
		if err != nil {
			t.Fatalf("Error parsing DN1: %s", err)
		}
		dn2, err := ldapserver.ParseDN(test.dn2)
		if err != nil {
			t.Fatalf("Error parsing DN2: %s", err)
		}
		if dn1.IsSibling(dn2) != test.isSib {
			t.Errorf("Expected %t, got %t for \"%s\" is sibling of \"%s\"", test.isSib, !test.isSib, test.dn1, test.dn2)
		}
	}
}

func TestDNCommonAncestor(t *testing.T) {
	type ancestorTest struct {
		dn1 string
		dn2 string
		ca  string
	}
	ancestorTests := []ancestorTest{
		{"uid=jdoe,ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com"},
		{"uid=jdoe,ou=users,dc=example,dc=com", "ou=users,dc=example,dc=com", "ou=users,dc=example,dc=com"},
		{"ou=users,dc=example,dc=com", "uid=jdoe,ou=users,dc=example,dc=com", "ou=users,dc=example,dc=com"},
		{"ou=users,dc=example,dc=com", "ou=users,dc=example,dc=com", "ou=users,dc=example,dc=com"},
		{"ou=users,dc=example,dc=com", "ou=printers,dc=example,dc=com", "dc=example,dc=com"},
		{"ou=printers,dc=example,dc=com", "ou=users,dc=example,dc=com", "dc=example,dc=com"},
		{"ou=users,dc=example,dc=com", "ou=users,dc=example,dc=org", ""},
		{"ou=users,dc=example,dc=com", "ou=users,dc=example,dc=com,dc=org", ""},
		{"", "", ""},
		{"", "dc=com", ""},
		{"dc=com", "dc=org", ""},
	}
	for _, test := range ancestorTests {
		dn1, err := ldapserver.ParseDN(test.dn1)
		if err != nil {
			t.Fatalf("Error parsing DN1: %s", err)
		}
		dn2, err := ldapserver.ParseDN(test.dn2)
		if err != nil {
			t.Fatalf("Error parsing DN2: %s", err)
		}
		ca, err := ldapserver.ParseDN(test.ca)
		if err != nil {
			t.Fatalf("Error parsing common ancestor: %s", err)
		}
		dnca := dn1.CommonSuperior(dn2)
		if !dnca.Equal(ca) {
			t.Errorf("Expected \"%s\", got \"%s\" for common ancestor of \"%s\" and \"%s\"", ca, dnca, test.dn1, test.dn2)
		}
	}
}
