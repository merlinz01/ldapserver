package ldapserver

import "regexp"

// LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
//
//	-- [RFC4512]
//
// numericoid = number 1*( DOT number )
// number = [0-9]+
type OID string

// Defined OIDs
const (
	OIDAlias                   OID = "2.5.6.1"
	OIDAliasedObjectName       OID = "2.5.4.1"
	OIDAltServer               OID = "1.3.6.1.4.1.1466.101.120.6"
	OIDAttributeTypes          OID = "2.5.21.5"
	OIDCreateTimestamp         OID = "2.5.18.1"
	OIDCreatorsName            OID = "2.5.18.3"
	OIDDITContentRules         OID = "2.5.21.2"
	OIDDITStructureRules       OID = "2.5.21.1"
	OIDExtensibleObject        OID = "1.3.6.1.4.1.1466.101.120.111"
	OIDGoverningStructureRule  OID = "2.5.21.10"
	OIDLDAPSyntaxes            OID = "1.3.6.1.4.1.1466.101.120.16"
	OIDMatchingRuleUse         OID = "2.5.21.8"
	OIDMatchingRules           OID = "2.5.21.4"
	OIDModifiersName           OID = "2.5.18.4"
	OIDModifyTimestamp         OID = "2.5.18.2"
	OIDNameForms               OID = "2.5.21.7"
	OIDNamingContexts          OID = "1.3.6.1.4.1.1466.101.120.5"
	OIDNoAttribute             OID = "1.1"
	OIDNoticeOfDisconnection   OID = "1.3.6.1.4.1.1466.20036"
	OIDObjectClass             OID = "2.5.4.0"
	OIDObjectClasses           OID = "2.5.21.6"
	OIDPasswordModify          OID = "1.3.6.1.4.1.4203.1.11.1"
	OIDStartTLS                OID = "1.3.6.1.4.1.1466.20037"
	OIDStructuralObjectClass   OID = "2.5.21.9"
	OIDSubschema               OID = "2.5.20.1"
	OIDSubschemaSubentry       OID = "2.5.18.10"
	OIDSupportedControl        OID = "1.3.6.1.4.1.1466.101.120.13"
	OIDSupportedExtension      OID = "1.3.6.1.4.1.1466.101.120.7"
	OIDSupportedFeatures       OID = "1.3.6.1.4.1.4203.1.3.5"
	OIDSupportedLDAPVersion    OID = "1.3.6.1.4.1.1466.101.120.15"
	OIDSupportedSASLMechanisms OID = "1.3.6.1.4.1.1466.101.120.14"
	OIDTop                     OID = "2.5.6.0"
)

var validOID = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// Make sure the OID conforms to the specification
func (oid OID) Validate() error {
	if !validOID.Match([]byte(oid)) {
		return ErrInvalidOID.WithInfo("oid", oid)
	}
	return nil
}
