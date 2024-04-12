package ldapserver_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/merlinz01/ldapserver"
)

func getBooleanSimple(data []byte, shouldbe bool) bool {
	b, err := ldapserver.BerGetBoolean(data)
	if err != nil {
		return !shouldbe
	}
	return b
}

func slicesEqual[T comparable](a []T, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i, ai := range a {
		if ai != b[i] {
			return false
		}
	}
	return true
}

func TestBerDecode(t *testing.T) {
	if ldapserver.BerType(0b00000000).Class() != ldapserver.BerClassUniversal {
		t.Error("invalid BER type reported")
	}
	if ldapserver.BerType(0b01000000).Class() != ldapserver.BerClassApplication {
		t.Error("invalid BER type reported")
	}
	if ldapserver.BerType(0b10000000).Class() != ldapserver.BerClassContextSpecific {
		t.Error("invalid BER type reported")
	}
	if ldapserver.BerType(0b11000000).Class() != ldapserver.BerClassPrivate {
		t.Error("invalid BER type reported")
	}
	if ldapserver.BerType(0b00100000).IsPrimitive() {
		t.Error("invalid primitive flag reported")
	}
	if !ldapserver.BerType(0b00000000).IsPrimitive() {
		t.Error("invalid primitive flag reported")
	}
	if ldapserver.BerType(0b00000000).IsConstructed() {
		t.Error("invalid constructed flag reported")
	}
	if !ldapserver.BerType(0b00100000).IsConstructed() {
		t.Error("invalid constructed flag reported")
	}
	if ldapserver.BerType(0b11111111).TagNumber() != 0b00011111 {
		t.Error("invalid tag number reported")
	}
	if ldapserver.BerType(0b00000000).TagNumber() != 0b00000000 {
		t.Error("invalid tag number reported")
	}
	if ldapserver.BerType(0b10101010).TagNumber() != 0b00001010 {
		t.Error("invalid tag number reported")
	}
	type sizetest struct {
		size uint32
		err  error
		repr []byte
	}
	for _, st := range []sizetest{
		{0x0, nil, []byte{0x00}},
		{0x1, nil, []byte{0x01}},
		{0x39, nil, []byte{0x39}},
		{0x7f, nil, []byte{0x7f}},
		{0x80, nil, []byte{0x81, 0x80}},
		{0x81, nil, []byte{0x81, 0x81}},
		{0xff, nil, []byte{0x81, 0xff}},
		{0xff, nil, []byte{0x82, 0x00, 0xff}},
		{0xff, nil, []byte{0x83, 0x00, 0x00, 0xff}},
		{0xff00ff00, nil, []byte{0x84, 0xff, 0x00, 0xff, 0x00}},
		{0, ldapserver.ErrIntegerTooLarge, []byte{0x85, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{0, ldapserver.ErrIntegerTooLarge, []byte{0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	} {
		size, err := ldapserver.BerReadSize(bytes.NewReader(st.repr))
		if size != st.size {
			t.Error("invalid size read")
		}
		if !errors.Is(err, st.err) {
			t.Error("Expected error", st.err, ", got error", err)
		}
	}
	type elementTest struct {
		res  ldapserver.BerRawElement
		repr []byte
		err  error
	}
	for _, et := range []elementTest{
		{ldapserver.BerRawElement{ldapserver.BerTypeNull, []byte{}}, []byte{0x05, 0x00}, nil},
		{ldapserver.BerRawElement{ldapserver.TypeUnbindRequestOp, []byte{}}, []byte{0x42, 0x00}, nil},
		{ldapserver.BerRawElement{ldapserver.BerTypeBoolean, []byte{0x00}}, []byte{0x01, 0x01, 0x00}, nil},
		{ldapserver.BerRawElement{ldapserver.BerTypeBoolean, []byte{0xff}}, []byte{0x01, 0x01, 0xff}, nil},
		{ldapserver.BerRawElement{ldapserver.BerTypeOctetString, []byte("Hello!")}, []byte{0x04, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21}, nil},
	} {
		elmt, err := ldapserver.BerReadElement(bytes.NewReader(et.repr))
		if elmt.Type != et.res.Type {
			t.Error("invalid type read")
		}
		if !bytes.Equal(elmt.Data, et.res.Data) {
			t.Error("invalid data read")
		}
		if err != et.err {
			t.Error("Expected error", et.err, ", got error", err)
		}
	}
	if getBooleanSimple([]byte{0x00}, false) {
		t.Error("invalid boolean read")
	}
	if !getBooleanSimple([]byte{0x01}, true) {
		t.Error("invalid boolean read")
	}
	if !getBooleanSimple([]byte{0xff}, true) {
		t.Error("invalid boolean read")
	}
	BerGetInteger := func(data []byte) int64 {
		res, err := ldapserver.BerGetInteger(data)
		if err != nil {
			t.Error("Error reading integer:", err.Error())
		}
		return res
	}
	if BerGetInteger([]byte{0x00}) != 0 {
		t.Error("invalid integer read")
	}
	if BerGetInteger([]byte{0x32}) != 50 {
		t.Error("invalid integer read")
	}
	if BerGetInteger([]byte{0x00, 0xc3, 0x50}) != 50000 {
		t.Error("invalid integer read")
	}
	if BerGetInteger([]byte{0xcf, 0xc7}) != -12345 {
		t.Error("invalid integer read")
	}
	_, err := ldapserver.BerGetInteger([]byte{0x12, 0x34, 0x56, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00})
	if !errors.Is(err, ldapserver.ErrIntegerTooLarge) {
		t.Error("Expected error", ldapserver.ErrIntegerTooLarge, ", got error", err)
	}
	if ldapserver.BerGetOctetString([]byte{}) != "" {
		t.Error("invalid octet string read")
	}
	if ldapserver.BerGetOctetString([]byte("This is a test!")) != "This is a test!" {
		t.Error("invalid octet string read")
	}
	seq, err := ldapserver.BerGetSequence(
		[]byte{0x04, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x01, 0x01, 0xff, 0x02, 0x01, 0x05})
	if err != nil {
		t.Error(err)
	}
	if len(seq) != 3 {
		t.Error("wrong length of sequence", len(seq))
	}
	if seq[0].Type != ldapserver.BerTypeOctetString && ldapserver.BerGetOctetString(seq[0].Data) != "Hello!" {
		t.Error("wrong first item of sequence", seq[0])
	}
	if seq[1].Type != ldapserver.BerTypeBoolean && getBooleanSimple(seq[1].Data, true) != true {
		t.Error("wrong second item of sequence", seq[1])
	}
	if seq[2].Type != ldapserver.BerTypeInteger && BerGetInteger(seq[2].Data) != 5 {
		t.Error("wrong third item of sequence", seq[2])
	}
	deleteRequest := []byte{
		0x30, 0x35, 0x02, 0x01, 0x05, 0x4a, 0x11, 0x64, 0x63, 0x3d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
		0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d, 0xa0, 0x1d, 0x30, 0x1b, 0x04, 0x16, 0x31, 0x2e,
		0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x31, 0x33, 0x35, 0x35, 0x36, 0x2e, 0x31, 0x2e, 0x34,
		0x2e, 0x38, 0x30, 0x35, 0x01, 0x01, 0xff}
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(deleteRequest))
	if err != nil {
		t.Error("Failed to parse LDAP message:", err)
	}
	if m.MessageID != 5 {
		t.Error("invalid message ID")
	}
	if m.ProtocolOp.Type != ldapserver.TypeDeleteRequestOp {
		t.Error("invalid protocol op type")
	}
	// m.ProtocolOp.Data should be "dc=example,dc=com"
	if len(m.Controls) != 1 {
		t.Error("invalid number of controls")
	}
	if m.Controls[0].OID != "1.2.840.113556.1.4.805" {
		t.Error("invalid control OID")
	}
	if m.Controls[0].Criticality != true {
		t.Error("invalid criticality")
	}
	if m.Controls[0].ControlValue != "" {
		t.Error("invalid control value")
	}
	emptySuccess := []byte{0x30, 0x0c, 0x02, 0x01, 0x03, 0x69, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	m, err = ldapserver.ReadLDAPMessage(bytes.NewReader(emptySuccess))
	if err != nil {
		t.Error("Failed to read LDAPMessage:", err)
	}
	if m.MessageID != 3 {
		t.Error("invalid message ID")
	}
	if m.ProtocolOp.Type != ldapserver.TypeAddResponseOp {
		t.Error("invalid protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Error("invalid number of controls")
	}
	r, err := ldapserver.GetResult(m.ProtocolOp.Data)
	if err != nil {
		t.Error("Failed to parse LDAPResult:", err)
	}
	if r.ResultCode != ldapserver.ResultSuccess {
		t.Error("invalid result code")
	}
	if r.MatchedDN != "" {
		t.Error("invalid matchedDN")
	}
	if r.DiagnosticMessage != "" {
		t.Error("invalid diagnostic message")
	}
	if len(r.Referral) != 0 {
		t.Error("invalid referral")
	}
	noSuchObject := []byte{
		0x30, 0x81, 0x9d,
		0x02, 0x01, 0x03,
		0x69, 0x81, 0x97,
		0x0a, 0x01, 0x20,
		0x04, 0x1d, 0x6f, 0x75, 0x3d, 0x50, 0x65, 0x6f, 0x70, 0x6c,
		0x65, 0x2c, 0x20, 0x64, 0x63, 0x3d, 0x65, 0x78,
		0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x20, 0x64,
		0x63, 0x3d, 0x63, 0x6f, 0x6d,
		0x04, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x75, 0x69,
		0x64, 0x3d, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6e,
		0x67, 0x31, 0x2c, 0x20, 0x6f, 0x75, 0x3d, 0x6d,
		0x69, 0x73, 0x73, 0x69, 0x6e, 0x67, 0x32, 0x2c,
		0x20, 0x6f, 0x75, 0x3d, 0x50, 0x65, 0x6f, 0x70,
		0x6c, 0x65, 0x2c, 0x20, 0x64, 0x63, 0x3d, 0x65,
		0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x20,
		0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d, 0x20, 0x63,
		0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65,
		0x20, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
		0x20, 0x62, 0x65, 0x63, 0x61, 0x75, 0x73, 0x65,
		0x20, 0x69, 0x74, 0x73, 0x20, 0x70, 0x61, 0x72,
		0x65, 0x6e, 0x74, 0x20, 0x64, 0x6f, 0x65, 0x73,
		0x20, 0x6e, 0x6f, 0x74, 0x20, 0x65, 0x78, 0x69,
		0x73, 0x74, 0x2e,
	}
	m, err = ldapserver.ReadLDAPMessage(bytes.NewReader(noSuchObject))
	if err != nil {
		t.Error("Failed to read LDAPMessage:", err)
	}
	if m.MessageID != 3 {
		t.Error("invalid message ID")
	}
	if len(m.Controls) != 0 {
		t.Error("wrong number of controls")
	}
	if m.ProtocolOp.Type != ldapserver.TypeAddResponseOp {
		t.Error("invalid protocol op type")
	}
	r, err = ldapserver.GetResult(m.ProtocolOp.Data)
	if err != nil {
		t.Error("Failed to read LDAPResult:", err)
	}
	if r.ResultCode != ldapserver.LDAPResultNoSuchObject {
		t.Error("wrong result code")
	}
	if r.MatchedDN != "ou=People, dc=example, dc=com" {
		t.Error("wrong matched DN:", r.MatchedDN)
	}
	if r.DiagnosticMessage != "Entry uid=missing1, ou=missing2, ou=People, dc=example, dc=com cannot be created because its parent does not exist." {
		t.Error("wrong diagnostic message:", r.DiagnosticMessage)
	}
	if len(r.Referral) != 0 {
		t.Error("wrong referral")
	}
	referral := []byte{
		0x30, 0x81, 0xcf,
		0x02, 0x01, 0x03,
		0x69, 0x81, 0xc9,
		0x0a, 0x01, 0x0a,
		0x04, 0x00,
		0x04, 0x2f, 0x54, 0x68, 0x69, 0x73, 0x20, 0x73, 0x65, 0x72,
		0x76, 0x65, 0x72, 0x20, 0x69, 0x73, 0x20, 0x72,
		0x65, 0x61, 0x64, 0x2d, 0x6f, 0x6e, 0x6c, 0x79,
		0x2e, 0x20, 0x20, 0x54, 0x72, 0x79, 0x20, 0x61,
		0x20, 0x64, 0x69, 0x66, 0x66, 0x65, 0x72, 0x65,
		0x6e, 0x74, 0x20, 0x6f, 0x6e, 0x65, 0x2e,
		0xa3, 0x81, 0x90,
		0x04, 0x46, 0x6c, 0x64, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x61,
		0x6c, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x74, 0x65,
		0x31, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
		0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x3a, 0x33, 0x38,
		0x39, 0x2f, 0x75, 0x69, 0x64, 0x3d, 0x6a, 0x64,
		0x6f, 0x65, 0x2c, 0x6f, 0x75, 0x3d, 0x52, 0x65,
		0x6d, 0x6f, 0x74, 0x65, 0x2c, 0x64, 0x63, 0x3d,
		0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c,
		0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d,
		0x04, 0x46, 0x6c, 0x64, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x61,
		0x6c, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x74, 0x65,
		0x32, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
		0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x3a, 0x33, 0x38,
		0x39, 0x2f, 0x75, 0x69, 0x64, 0x3d, 0x6a, 0x64,
		0x6f, 0x65, 0x2c, 0x6f, 0x75, 0x3d, 0x52, 0x65,
		0x6d, 0x6f, 0x74, 0x65, 0x2c, 0x64, 0x63, 0x3d,
		0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c,
		0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d,
	}
	m, err = ldapserver.ReadLDAPMessage(bytes.NewReader(referral))
	if err != nil {
		t.Error("Failed to read LDAPMessage:", err)
	}
	if m.MessageID != 3 {
		t.Error("wrong message ID")
	}
	if len(m.Controls) != 0 {
		t.Error("wrong number of controls")
	}
	if m.ProtocolOp.Type != ldapserver.TypeAddResponseOp {
		t.Error("wrong protocol op type")
	}
	r, err = ldapserver.GetResult(m.ProtocolOp.Data)
	if err != nil {
		t.Error("Failed to get LDAPResult:", err)
	}
	if r.ResultCode != ldapserver.LDAPResultReferral {
		t.Error("wrong result code")
	}
	if r.MatchedDN != "" {
		t.Error("wrong matched DN")
	}
	if r.DiagnosticMessage != "This server is read-only.  Try a different one." {
		t.Error("wrong diagnostic message:", r.DiagnosticMessage)
	}
	if len(r.Referral) != 2 {
		t.Error("wrong referral length", len(r.Referral))
	}
	if r.Referral[0] != "ldap://alternate1.example.com:389/uid=jdoe,ou=Remote,dc=example,dc=com" {
		t.Error("wrong first referral", r.Referral[0])
	}
	if r.Referral[1] != "ldap://alternate2.example.com:389/uid=jdoe,ou=Remote,dc=example,dc=com" {
		t.Error("wrong first referral", r.Referral[1])
	}
}
func TestParseAddRequest(t *testing.T) {
	addrequest := []byte{
		0x30, 0x49,
		0x02, 0x01, 0x02,
		0x68, 0x44,
		0x04, 0x11, 0x64, 0x63, 0x3d, 0x65, 0x78, 0x61, 0x6d, 0x70,
		0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f,
		0x6d,
		0x30, 0x2f,
		0x30, 0x1c,
		0x04, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c,
		0x61, 0x73, 0x73,
		0x31, 0x0d,
		0x04, 0x03, 0x74, 0x6f, 0x70,
		0x04, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e,
		0x30, 0x0f,
		0x04, 0x02, 0x64, 0x63,
		0x31, 0x09,
		0x04, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
	}
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(addrequest))
	if err != nil {
		t.Error("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 2 {
		t.Error("wrong message ID")
	}
	if m.ProtocolOp.Type != ldapserver.TypeAddRequestOp {
		t.Error("wrong protocol op type")
	}
	r_add, err := ldapserver.GetAddRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Error("Failed to parse LDAPAddRequest", err)
	}
	if r_add.Entry != "dc=example,dc=com" {
		t.Error("wrong entry", r_add.Entry)
	}
	if len(r_add.Attributes) != 2 {
		t.Error("wrong number of attributes")
	}
	if r_add.Attributes[0].Description != "objectClass" {
		t.Error("wrong attribute description")
	}
	if !slicesEqual(r_add.Attributes[0].Values, []string{"top", "domain"}) {
		t.Error("wrong attribute values")
	}
	if r_add.Attributes[1].Description != "dc" {
		t.Error("wrong attribute description")
	}
	if !slicesEqual(r_add.Attributes[1].Values, []string{"example"}) {
		t.Error("wrong attribute values")
	}
}

func TestParseAnonymousSimpleBindRequest(t *testing.T) {
	bindrequest := []byte{
		0x30, 0x0c,
		0x02, 0x01, 0x01,
		0x60, 0x07,
		0x02, 0x01, 0x03,
		0x04, 0x00,
		0x80, 0x00,
	}
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(bindrequest))
	if err != nil {
		t.Error("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 1 {
		t.Error("wrong message id")
	}
	if m.ProtocolOp.Type != ldapserver.TypeBindRequestOp {
		t.Error("wrong protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Error("wrong number of controls")
	}
	req, err := ldapserver.GetBindRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Error("Failed to parse bind request:", err)
	}
	if req.Version != 3 {
		t.Error("wrong protocol version")
	}
	if req.Name != "" {
		t.Error("wrong bind DN")
	}
	if req.AuthType != ldapserver.AuthenticationTypeSimple {
		t.Error("wrong auth type")
	}
	if req.Credentials.(string) != "" {
		t.Error("wrong password", req.Credentials)
	}
}

func TestParseAuthenticatedSimpleBindRequest(t *testing.T) {
	bindrequest := []byte{
		0x30, 0x39,
		0x02, 0x01, 0x01,
		0x60, 0x34,
		0x02, 0x01, 0x03,
		0x04, 0x24, 0x75, 0x69, 0x64, 0x3d, 0x6a, 0x64, 0x6f, 0x65,
		0x2c, 0x6f, 0x75, 0x3d, 0x50, 0x65, 0x6f, 0x70,
		0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x65, 0x78,
		0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63,
		0x3d, 0x63, 0x6f, 0x6d,
		0x80, 0x09, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x31, 0x32, 0x33,
	}
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(bindrequest))
	if err != nil {
		t.Error("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 1 {
		t.Error("wrong message id")
	}
	if m.ProtocolOp.Type != ldapserver.TypeBindRequestOp {
		t.Error("wrong protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Error("wrong number of controls")
	}
	req, err := ldapserver.GetBindRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Error("Failed to parse bind request:", err)
	}
	if req.Version != 3 {
		t.Error("wrong protocol version")
	}
	if req.Name != "uid=jdoe,ou=People,dc=example,dc=com" {
		t.Error("wrong bind DN")
	}
	if req.AuthType != ldapserver.AuthenticationTypeSimple {
		t.Error("wrong auth type")
	}
	if req.Credentials.(string) != "secret123" {
		t.Error("wrong password", req.Credentials)
	}
}
func TestParseSASLCRAMMD5InitialBindRequest(t *testing.T) {
	bindrequest := []byte{
		0x30, 0x16,
		0x02, 0x01, 0x01,
		0x60, 0x11,
		0x02, 0x01, 0x03,
		0x04, 0x00,
		0xa3, 0x0a,
		0x04, 0x08, 0x43, 0x52, 0x41, 0x4d, 0x2d, 0x4d, 0x44, 0x35,
	}
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(bindrequest))
	if err != nil {
		t.Error("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 1 {
		t.Error("wrong message id")
	}
	if m.ProtocolOp.Type != ldapserver.TypeBindRequestOp {
		t.Error("wrong protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Error("wrong number of controls")
	}
	req, err := ldapserver.GetBindRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Error("Failed to parse bind request:", err)
	}
	if req.Version != 3 {
		t.Error("wrong protocol version")
	}
	if req.Name != "" {
		t.Error("wrong bind DN")
	}
	if req.AuthType != ldapserver.AuthenticationTypeSASL {
		t.Error("wrong auth type")
	}
	cr := req.Credentials.(*ldapserver.SASLCredentials)
	if cr.Mechanism != "CRAM-MD5" {
		t.Error("wrong mechanism")
	}
	if cr.Credentials != "" {
		t.Error("wrong credentials", req.Credentials)
	}
}
func TestParseSASLCRAMMD5BindRequest(t *testing.T) {
	bindrequest := []byte{
		0x30, 0x3f,
		0x02, 0x01, 0x02,
		0x60, 0x3a,
		0x02, 0x01, 0x03,
		0x04, 0x00,
		0xa3, 0x33,
		0x04, 0x08, 0x43, 0x52, 0x41, 0x4d, 0x2d, 0x4d, 0x44, 0x35,
		0x04, 0x27, 0x75, 0x3a, 0x6a, 0x64, 0x6f, 0x65, 0x20, 0x64,
		0x35, 0x32, 0x31, 0x31, 0x36, 0x63, 0x38, 0x37,
		0x63, 0x33, 0x31, 0x64, 0x39, 0x63, 0x63, 0x37,
		0x34, 0x37, 0x36, 0x30, 0x30, 0x66, 0x39, 0x34,
		0x38, 0x36, 0x64, 0x32, 0x61, 0x31, 0x64,
	}
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(bindrequest))
	if err != nil {
		t.Error("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 2 {
		t.Error("wrong message id")
	}
	if m.ProtocolOp.Type != ldapserver.TypeBindRequestOp {
		t.Error("wrong protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Error("wrong number of controls")
	}
	req, err := ldapserver.GetBindRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Error("Failed to parse bind request:", err)
	}
	if req.Version != 3 {
		t.Error("wrong protocol version")
	}
	if req.Name != "" {
		t.Error("wrong bind DN")
	}
	if req.AuthType != ldapserver.AuthenticationTypeSASL {
		t.Error("wrong auth type")
	}
	cr := req.Credentials.(*ldapserver.SASLCredentials)
	if cr.Mechanism != "CRAM-MD5" {
		t.Error("wrong mechanism")
	}
	if cr.Credentials != "u:jdoe d52116c87c31d9cc747600f9486d2a1d" {
		t.Error("wrong credentials", req.Credentials)
	}
}
