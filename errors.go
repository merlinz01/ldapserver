package ldapserver

import "fmt"

// Type for errors returned by this library.
// Supports errors.Is() to test for specific errors while also displaying instance-specific error info.
type LDAPError struct {
	message  string
	infoKey  string
	infoData string
}

func (e *LDAPError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.infoKey == "" {
		return e.message
	}
	return e.message + ": " + e.infoKey + " = " + e.infoData
}

// Returns true if both are LDAPError and have the same message
func (e *LDAPError) Is(other error) bool {
	le, ok := other.(*LDAPError)
	return ok && le.message == e.message
}

// Returns a new error object with the specified info
func (e *LDAPError) WithInfo(key string, value any) *LDAPError {
	sval := fmt.Sprintf("%v", value)
	return &LDAPError{e.message, key, sval}
}

// Predefined errors for this library
var ErrInvalidBoolean = &LDAPError{message: "invalid boolean data"}
var ErrInvalidLDAPMessage = &LDAPError{message: "invalid LDAP message"}
var ErrInvalidMessageID = &LDAPError{message: "invalid message ID"}
var ErrInvalidOID = &LDAPError{message: "invalid OID"}
var ErrIntegerTooLarge = &LDAPError{message: "integer too large"}
var ErrTLSAlreadySetUp = &LDAPError{message: "TLS already set up"}
var ErrTLSNotAvailable = &LDAPError{message: "TLS not available"}
var ErrWrongElementType = &LDAPError{message: "wrong element type"}
var ErrWrongSequenceLength = &LDAPError{message: "wrong sequence length"}
