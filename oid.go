package ldapserver

import "regexp"

// LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
//                          -- [RFC4512]
// numericoid = number 1*( DOT number )
// number = [0-9]+
type OID string

// Defined OIDs
const (
	OIDNoAttribute           OID = "1.1"
	OIDNoticeOfDisconnection OID = "1.3.6.1.4.1.1466.20036"
	OIDPasswordModify        OID = "1.3.6.1.4.1.4203.1.11.1"
	OIDStartTLS              OID = "1.3.6.1.4.1.1466.20037"
)

var validOID = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// Make sure the OID conforms to the specification
func (oid OID) Validate() error {
	if !validOID.Match([]byte(oid)) {
		return ErrInvalidOID.WithInfo("oid", oid)
	}
	return nil
}
