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

func getIntegerSimple(data []byte, shouldbe int64) int64 {
	i, err := ldapserver.BerGetInteger(data)
	if err != nil {
		return shouldbe - 1
	}
	return i
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

func TestBerTypes(t *testing.T) {
	if ldapserver.BerType(0b00000000).Class() != ldapserver.BerClassUniversal {
		t.Fatal("invalid BER type reported")
	}
	if ldapserver.BerType(0b01000000).Class() != ldapserver.BerClassApplication {
		t.Fatal("invalid BER type reported")
	}
	if ldapserver.BerType(0b10000000).Class() != ldapserver.BerClassContextSpecific {
		t.Fatal("invalid BER type reported")
	}
	if ldapserver.BerType(0b11000000).Class() != ldapserver.BerClassPrivate {
		t.Fatal("invalid BER type reported")
	}
	if ldapserver.BerType(0b00100000).IsPrimitive() {
		t.Fatal("invalid primitive flag reported")
	}
	if !ldapserver.BerType(0b00000000).IsPrimitive() {
		t.Fatal("invalid primitive flag reported")
	}
	if ldapserver.BerType(0b00000000).IsConstructed() {
		t.Fatal("invalid constructed flag reported")
	}
	if !ldapserver.BerType(0b00100000).IsConstructed() {
		t.Fatal("invalid constructed flag reported")
	}
	if ldapserver.BerType(0b11111111).TagNumber() != 0b00011111 {
		t.Fatal("invalid tag number reported")
	}
	if ldapserver.BerType(0b00000000).TagNumber() != 0b00000000 {
		t.Fatal("invalid tag number reported")
	}
	if ldapserver.BerType(0b10101010).TagNumber() != 0b00001010 {
		t.Fatal("invalid tag number reported")
	}
}
func TestBerSizes(t *testing.T) {
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
			t.Fatal("invalid size read")
		}
		if !errors.Is(err, st.err) {
			t.Fatal("Expected error", st.err, ", got error", err)
		}
	}
}

func TestBerReadElement(t *testing.T) {
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
			t.Fatal("invalid type read")
		}
		if !bytes.Equal(elmt.Data, et.res.Data) {
			t.Fatal("invalid data read")
		}
		if err != et.err {
			t.Fatal("Expected error", et.err, ", got error", err)
		}
	}
}

func TestBerBoolean(t *testing.T) {
	if getBooleanSimple([]byte{0x00}, false) {
		t.Fatal("invalid boolean read")
	}
	if !getBooleanSimple([]byte{0x01}, true) {
		t.Fatal("invalid boolean read")
	}
	if !getBooleanSimple([]byte{0xff}, true) {
		t.Fatal("invalid boolean read")
	}
}

func TestBerInteger(t *testing.T) {
	BerGetInteger := func(data []byte) int64 {
		res, err := ldapserver.BerGetInteger(data)
		if err != nil {
			t.Fatal("Error reading integer:", err.Error())
		}
		return res
	}
	if BerGetInteger([]byte{0x00}) != 0 {
		t.Fatal("invalid integer read")
	}
	if BerGetInteger([]byte{0x32}) != 50 {
		t.Fatal("invalid integer read")
	}
	if BerGetInteger([]byte{0x00, 0xc3, 0x50}) != 50000 {
		t.Fatal("invalid integer read")
	}
	if BerGetInteger([]byte{0xcf, 0xc7}) != -12345 {
		t.Fatal("invalid integer read")
	}
	_, err := ldapserver.BerGetInteger([]byte{0x12, 0x34, 0x56, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00})
	if !errors.Is(err, ldapserver.ErrIntegerTooLarge) {
		t.Fatal("Expected error", ldapserver.ErrIntegerTooLarge, ", got error", err)
	}
}

func TestBerOctetString(t *testing.T) {
	if ldapserver.BerGetOctetString([]byte{}) != "" {
		t.Fatal("invalid octet string read")
	}
	if ldapserver.BerGetOctetString([]byte("This is a test!")) != "This is a test!" {
		t.Fatal("invalid octet string read")
	}
}

func TestBerSequence(t *testing.T) {
	seq, err := ldapserver.BerGetSequence(
		[]byte{0x04, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x01, 0x01, 0xff, 0x02, 0x01, 0x05})
	if err != nil {
		t.Fatal(err)
	}
	if len(seq) != 3 {
		t.Fatal("wrong length of sequence", len(seq))
	}
	if seq[0].Type != ldapserver.BerTypeOctetString && ldapserver.BerGetOctetString(seq[0].Data) != "Hello!" {
		t.Fatal("wrong first item of sequence", seq[0])
	}
	if seq[1].Type != ldapserver.BerTypeBoolean && getBooleanSimple(seq[1].Data, true) != true {
		t.Fatal("wrong second item of sequence", seq[1])
	}
	if seq[2].Type != ldapserver.BerTypeInteger && getIntegerSimple(seq[2].Data, 5) != 5 {
		t.Fatal("wrong third item of sequence", seq[2])
	}
}

func TestParseDeleteRequest(t *testing.T) {
	deleteRequest := []byte{
		0x30, 0x35, 0x02, 0x01, 0x05, 0x4a, 0x11, 0x64, 0x63, 0x3d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
		0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d, 0xa0, 0x1d, 0x30, 0x1b, 0x04, 0x16, 0x31, 0x2e,
		0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x31, 0x33, 0x35, 0x35, 0x36, 0x2e, 0x31, 0x2e, 0x34,
		0x2e, 0x38, 0x30, 0x35, 0x01, 0x01, 0xff}
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(deleteRequest))
	if err != nil {
		t.Fatal("Failed to parse LDAP message:", err)
	}
	if m.MessageID != 5 {
		t.Fatal("invalid message ID")
	}
	if m.ProtocolOp.Type != ldapserver.TypeDeleteRequestOp {
		t.Fatal("invalid protocol op type")
	}
	// m.ProtocolOp.Data should be "dc=example,dc=com"
	if len(m.Controls) != 1 {
		t.Fatal("invalid number of controls")
	}
	if m.Controls[0].OID != "1.2.840.113556.1.4.805" {
		t.Fatal("invalid control OID")
	}
	if m.Controls[0].Criticality != true {
		t.Fatal("invalid criticality")
	}
	if m.Controls[0].ControlValue != "" {
		t.Fatal("invalid control value")
	}
}

func TestParseEmptySuccessResult(t *testing.T) {
	emptySuccess := []byte{0x30, 0x0c, 0x02, 0x01, 0x03, 0x69, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(emptySuccess))
	if err != nil {
		t.Fatal("Failed to read LDAPMessage:", err)
	}
	if m.MessageID != 3 {
		t.Fatal("invalid message ID")
	}
	if m.ProtocolOp.Type != ldapserver.TypeAddResponseOp {
		t.Fatal("invalid protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Fatal("invalid number of controls")
	}
	r, err := ldapserver.GetResult(m.ProtocolOp.Data)
	if err != nil {
		t.Fatal("Failed to parse LDAPResult:", err)
	}
	if r.ResultCode != ldapserver.ResultSuccess {
		t.Fatal("invalid result code")
	}
	if r.MatchedDN != "" {
		t.Fatal("invalid matchedDN")
	}
	if r.DiagnosticMessage != "" {
		t.Fatal("invalid diagnostic message")
	}
	if len(r.Referral) != 0 {
		t.Fatal("invalid referral")
	}
}

func TestParseNoSuchObjectResult(t *testing.T) {
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
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(noSuchObject))
	if err != nil {
		t.Fatal("Failed to read LDAPMessage:", err)
	}
	if m.MessageID != 3 {
		t.Fatal("invalid message ID")
	}
	if len(m.Controls) != 0 {
		t.Fatal("wrong number of controls")
	}
	if m.ProtocolOp.Type != ldapserver.TypeAddResponseOp {
		t.Fatal("invalid protocol op type")
	}
	r, err := ldapserver.GetResult(m.ProtocolOp.Data)
	if err != nil {
		t.Fatal("Failed to read LDAPResult:", err)
	}
	if r.ResultCode != ldapserver.LDAPResultNoSuchObject {
		t.Fatal("wrong result code")
	}
	if r.MatchedDN != "ou=People, dc=example, dc=com" {
		t.Fatal("wrong matched DN:", r.MatchedDN)
	}
	if r.DiagnosticMessage != "Entry uid=missing1, ou=missing2, ou=People, dc=example, dc=com cannot be created because its parent does not exist." {
		t.Fatal("wrong diagnostic message:", r.DiagnosticMessage)
	}
	if len(r.Referral) != 0 {
		t.Fatal("wrong referral")
	}
}

func TestParseReferralResult(t *testing.T) {
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
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(referral))
	if err != nil {
		t.Fatal("Failed to read LDAPMessage:", err)
	}
	if m.MessageID != 3 {
		t.Fatal("wrong message ID")
	}
	if len(m.Controls) != 0 {
		t.Fatal("wrong number of controls")
	}
	if m.ProtocolOp.Type != ldapserver.TypeAddResponseOp {
		t.Fatal("wrong protocol op type")
	}
	r, err := ldapserver.GetResult(m.ProtocolOp.Data)
	if err != nil {
		t.Fatal("Failed to get LDAPResult:", err)
	}
	if r.ResultCode != ldapserver.LDAPResultReferral {
		t.Fatal("wrong result code")
	}
	if r.MatchedDN != "" {
		t.Fatal("wrong matched DN")
	}
	if r.DiagnosticMessage != "This server is read-only.  Try a different one." {
		t.Fatal("wrong diagnostic message:", r.DiagnosticMessage)
	}
	if len(r.Referral) != 2 {
		t.Fatal("wrong referral length", len(r.Referral))
	}
	if r.Referral[0] != "ldap://alternate1.example.com:389/uid=jdoe,ou=Remote,dc=example,dc=com" {
		t.Fatal("wrong first referral", r.Referral[0])
	}
	if r.Referral[1] != "ldap://alternate2.example.com:389/uid=jdoe,ou=Remote,dc=example,dc=com" {
		t.Fatal("wrong first referral", r.Referral[1])
	}
}

func TestParseAbandonRequest(t *testing.T) {
	abandonRequest := []byte{0x30, 0x06, 0x02, 0x01, 0x06, 0x50, 0x01, 0x05}
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(abandonRequest))
	if err != nil {
		t.Fatal("Failed to read LDAPMessage:", err)
	}
	if m.MessageID != 6 {
		t.Fatal("wrong message ID")
	}
	if m.ProtocolOp.Type != ldapserver.TypeAbandonRequestOp {
		t.Fatal("wrong protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Fatal("wrong number of controls")
	}
	messageID, err := ldapserver.BerGetInteger(m.ProtocolOp.Data)
	if err != nil {
		t.Fatal("Failed to read integer:", err)
	}
	if messageID != 5 {
		t.Fatal("wrong abandon ID")
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
		t.Fatal("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 2 {
		t.Fatal("wrong message ID")
	}
	if m.ProtocolOp.Type != ldapserver.TypeAddRequestOp {
		t.Fatal("wrong protocol op type")
	}
	r_add, err := ldapserver.GetAddRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Fatal("Failed to parse LDAPAddRequest", err)
	}
	if r_add.Entry != "dc=example,dc=com" {
		t.Fatal("wrong entry", r_add.Entry)
	}
	if len(r_add.Attributes) != 2 {
		t.Fatal("wrong number of attributes")
	}
	if r_add.Attributes[0].Description != "objectClass" {
		t.Fatal("wrong attribute description")
	}
	if !slicesEqual(r_add.Attributes[0].Values, []string{"top", "domain"}) {
		t.Fatal("wrong attribute values")
	}
	if r_add.Attributes[1].Description != "dc" {
		t.Fatal("wrong attribute description")
	}
	if !slicesEqual(r_add.Attributes[1].Values, []string{"example"}) {
		t.Fatal("wrong attribute values")
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
		t.Fatal("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 1 {
		t.Fatal("wrong message id")
	}
	if m.ProtocolOp.Type != ldapserver.TypeBindRequestOp {
		t.Fatal("wrong protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Fatal("wrong number of controls")
	}
	req, err := ldapserver.GetBindRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Fatal("Failed to parse bind request:", err)
	}
	if req.Version != 3 {
		t.Fatal("wrong protocol version")
	}
	if req.Name != "" {
		t.Fatal("wrong bind DN")
	}
	if req.AuthType != ldapserver.AuthenticationTypeSimple {
		t.Fatal("wrong auth type")
	}
	if req.Credentials.(string) != "" {
		t.Fatal("wrong password", req.Credentials)
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
		t.Fatal("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 1 {
		t.Fatal("wrong message id")
	}
	if m.ProtocolOp.Type != ldapserver.TypeBindRequestOp {
		t.Fatal("wrong protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Fatal("wrong number of controls")
	}
	req, err := ldapserver.GetBindRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Fatal("Failed to parse bind request:", err)
	}
	if req.Version != 3 {
		t.Fatal("wrong protocol version")
	}
	if req.Name != "uid=jdoe,ou=People,dc=example,dc=com" {
		t.Fatal("wrong bind DN")
	}
	if req.AuthType != ldapserver.AuthenticationTypeSimple {
		t.Fatal("wrong auth type")
	}
	if req.Credentials.(string) != "secret123" {
		t.Fatal("wrong password", req.Credentials)
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
		t.Fatal("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 1 {
		t.Fatal("wrong message id")
	}
	if m.ProtocolOp.Type != ldapserver.TypeBindRequestOp {
		t.Fatal("wrong protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Fatal("wrong number of controls")
	}
	req, err := ldapserver.GetBindRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Fatal("Failed to parse bind request:", err)
	}
	if req.Version != 3 {
		t.Fatal("wrong protocol version")
	}
	if req.Name != "" {
		t.Fatal("wrong bind DN")
	}
	if req.AuthType != ldapserver.AuthenticationTypeSASL {
		t.Fatal("wrong auth type")
	}
	cr := req.Credentials.(*ldapserver.SASLCredentials)
	if cr.Mechanism != "CRAM-MD5" {
		t.Fatal("wrong mechanism")
	}
	if cr.Credentials != "" {
		t.Fatal("wrong credentials", req.Credentials)
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
		t.Fatal("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 2 {
		t.Fatal("wrong message id")
	}
	if m.ProtocolOp.Type != ldapserver.TypeBindRequestOp {
		t.Fatal("wrong protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Fatal("wrong number of controls")
	}
	req, err := ldapserver.GetBindRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Fatal("Failed to parse bind request:", err)
	}
	if req.Version != 3 {
		t.Fatal("wrong protocol version")
	}
	if req.Name != "" {
		t.Fatal("wrong bind DN")
	}
	if req.AuthType != ldapserver.AuthenticationTypeSASL {
		t.Fatal("wrong auth type")
	}
	cr := req.Credentials.(*ldapserver.SASLCredentials)
	if cr.Mechanism != "CRAM-MD5" {
		t.Fatal("wrong mechanism")
	}
	if cr.Credentials != "u:jdoe d52116c87c31d9cc747600f9486d2a1d" {
		t.Fatal("wrong credentials", req.Credentials)
	}
}

func TestParseModifyRequest(t *testing.T) {
	modifyrequest := []byte{
		0x30, 0x81, 0x80,
		0x02, 0x01, 0x02,
		0x66, 0x7b,
		0x04, 0x24, 0x75, 0x69, 0x64, 0x3d, 0x6a, 0x64, 0x6f, 0x65,
		0x2c, 0x6f, 0x75, 0x3d, 0x50, 0x65, 0x6f, 0x70,
		0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x65, 0x78,
		0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63,
		0x3d, 0x63, 0x6f, 0x6d,
		0x30, 0x53,
		0x30, 0x18,
		0x0a, 0x01, 0x01,
		0x30, 0x13,
		0x04, 0x09, 0x67, 0x69, 0x76, 0x65, 0x6e, 0x4e, 0x61, 0x6d,
		0x65,
		0x31, 0x06,
		0x04, 0x04, 0x4a, 0x6f, 0x68, 0x6e,
		0x30, 0x1c,
		0x0a, 0x01, 0x00,
		0x30, 0x17,
		0x04, 0x09, 0x67, 0x69, 0x76, 0x65, 0x6e, 0x4e, 0x61, 0x6d,
		0x65,
		0x31, 0x0a,
		0x04, 0x08, 0x4a, 0x6f, 0x6e, 0x61, 0x74, 0x68, 0x61, 0x6e,
		0x30, 0x19,
		0x0a, 0x01, 0x02,
		0x30, 0x14,
		0x04, 0x02, 0x63, 0x6e,
		0x31, 0x0e,
		0x04, 0x0c, 0x4a, 0x6f, 0x6e, 0x61, 0x74, 0x68, 0x61, 0x6e,
		0x20, 0x44, 0x6f, 0x65,
	}
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(modifyrequest))
	if err != nil {
		t.Fatal("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 2 {
		t.Fatal("wrong message id")
	}
	if m.ProtocolOp.Type != ldapserver.TypeModifyRequestOp {
		t.Fatal("wrong protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Fatal("wrong number of controls")
	}
	req, err := ldapserver.GetModifyRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Fatal("Failed to parse modify request:", err)
	}
	if req.Object != "uid=jdoe,ou=People,dc=example,dc=com" {
		t.Fatal("wrong object")
	}
	if len(req.Changes) != 3 {
		t.Fatal("wrong number of modifications")
	}
	if req.Changes[0].Operation != ldapserver.ModifyDelete {
		t.Fatal("wrong operation")
	}
	if req.Changes[0].Modification.Description != "givenName" {
		t.Fatal("wrong attribute")
	}
	if !slicesEqual(req.Changes[0].Modification.Values, []string{"John"}) {
		t.Fatal("wrong values")
	}
	if req.Changes[1].Operation != ldapserver.ModifyAdd {
		t.Fatal("wrong operation")
	}
	if req.Changes[1].Modification.Description != "givenName" {
		t.Fatal("wrong attribute")
	}
	if !slicesEqual(req.Changes[1].Modification.Values, []string{"Jonathan"}) {
		t.Fatal("wrong values")
	}
	if req.Changes[2].Operation != ldapserver.ModifyReplace {
		t.Fatal("wrong operation")
	}
	if req.Changes[2].Modification.Description != "cn" {
		t.Fatal("wrong attribute")
	}
	if !slicesEqual(req.Changes[2].Modification.Values, []string{"Jonathan Doe"}) {
		t.Fatal("wrong values")
	}
}

func TestParseModifyDNRenameRequest(t *testing.T) {
	modifyDNRequest := []byte{
		0x30, 0x3c,
		0x02, 0x01, 0x02,
		0x6c, 0x37,
		0x04, 0x24, 0x75, 0x69, 0x64, 0x3d, 0x6a, 0x64, 0x6f, 0x65,
		0x2c, 0x6f, 0x75, 0x3d, 0x50, 0x65, 0x6f, 0x70,
		0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x65, 0x78,
		0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63,
		0x3d, 0x63, 0x6f, 0x6d,
		0x04, 0x0c, 0x75, 0x69, 0x64, 0x3d, 0x6a, 0x6f, 0x68, 0x6e,
		0x2e, 0x64, 0x6f, 0x65,
		0x01, 0x01, 0xff,
	}
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(modifyDNRequest))
	if err != nil {
		t.Fatal("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 2 {
		t.Fatal("wrong message id")
	}
	if m.ProtocolOp.Type != ldapserver.TypeModifyDNRequestOp {
		t.Fatal("wrong protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Fatal("wrong number of controls")
	}
	req, err := ldapserver.GetModifyDNRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Fatal("Failed to parse modify DN request:", err)
	}
	if req.Object != "uid=jdoe,ou=People,dc=example,dc=com" {
		t.Fatal("wrong object")
	}
	if req.NewRDN != "uid=john.doe" {
		t.Fatal("wrong new RDN")
	}
	if req.DeleteOldRDN != true {
		t.Fatal("wrong delete old RDN")
	}
	if req.NewSuperior != "" {
		t.Fatal("wrong new superior")
	}
}

func TestParseModifyDNMoveRequest(t *testing.T) {
	moveRequest := []byte{
		0x30, 0x5c,
		0x02, 0x01, 0x03,
		0x6c, 0x57,
		0x04, 0x28, 0x75, 0x69, 0x64, 0x3d, 0x6a, 0x6f, 0x68, 0x6e,
		0x2e, 0x64, 0x6f, 0x65, 0x2c, 0x6f, 0x75, 0x3d,
		0x50, 0x65, 0x6f, 0x70, 0x6c, 0x65, 0x2c, 0x64,
		0x63, 0x3d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
		0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d,
		0x04, 0x0c, 0x75, 0x69, 0x64, 0x3d, 0x6a, 0x6f, 0x68, 0x6e,
		0x2e, 0x64, 0x6f, 0x65,
		0x01, 0x01, 0x00,
		0x80, 0x1a, 0x6f, 0x75, 0x3d, 0x55, 0x73, 0x65, 0x72, 0x73,
		0x2c, 0x64, 0x63, 0x3d, 0x65, 0x78, 0x61, 0x6d,
		0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63,
		0x6f, 0x6d,
	}
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(moveRequest))
	if err != nil {
		t.Fatal("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 3 {
		t.Fatal("wrong message id")
	}
	if m.ProtocolOp.Type != ldapserver.TypeModifyDNRequestOp {
		t.Fatal("wrong protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Fatal("wrong number of controls")
	}
	req, err := ldapserver.GetModifyDNRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Fatal("Failed to parse modify DN request:", err)
	}
	if req.Object != "uid=john.doe,ou=People,dc=example,dc=com" {
		t.Fatal("wrong object")
	}
	if req.NewRDN != "uid=john.doe" {
		t.Fatal("wrong new RDN")
	}
	if req.DeleteOldRDN != false {
		t.Fatal("wrong delete old RDN")
	}
	if req.NewSuperior != "ou=Users,dc=example,dc=com" {
		t.Fatal("wrong new superior")
	}
}

func TestParseModifyDNRenameAndMoveRequest(t *testing.T) {
	renameAndMoveRequest := []byte{
		0x30, 0x58,
		0x02, 0x01, 0x02,
		0x6c, 0x53,
		0x04, 0x24, 0x75, 0x69, 0x64, 0x3d, 0x6a, 0x64, 0x6f, 0x65,
		0x2c, 0x6f, 0x75, 0x3d, 0x50, 0x65, 0x6f, 0x70,
		0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x65, 0x78,
		0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63,
		0x3d, 0x63, 0x6f, 0x6d,
		0x04, 0x0c, 0x75, 0x69, 0x64, 0x3d, 0x6a, 0x6f, 0x68, 0x6e,
		0x2e, 0x64, 0x6f, 0x65,
		0x01, 0x01, 0xff,
		0x80, 0x1a, 0x6f, 0x75, 0x3d, 0x55, 0x73, 0x65, 0x72, 0x73,
		0x2c, 0x64, 0x63, 0x3d, 0x65, 0x78, 0x61, 0x6d,
		0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63,
		0x6f, 0x6d,
	}
	m, err := ldapserver.ReadLDAPMessage(bytes.NewReader(renameAndMoveRequest))
	if err != nil {
		t.Fatal("Failed to parse LDAPMessage:", err)
	}
	if m.MessageID != 2 {
		t.Fatal("wrong message id")
	}
	if m.ProtocolOp.Type != ldapserver.TypeModifyDNRequestOp {
		t.Fatal("wrong protocol op type")
	}
	if len(m.Controls) != 0 {
		t.Fatal("wrong number of controls")
	}
	req, err := ldapserver.GetModifyDNRequest(m.ProtocolOp.Data)
	if err != nil {
		t.Fatal("Failed to parse modify DN request:", err)
	}
	if req.Object != "uid=jdoe,ou=People,dc=example,dc=com" {
		t.Fatal("wrong object")
	}
	if req.NewRDN != "uid=john.doe" {
		t.Fatal("wrong new RDN")
	}
	if req.DeleteOldRDN != true {
		t.Fatal("wrong delete old RDN")
	}
	if req.NewSuperior != "ou=Users,dc=example,dc=com" {
		t.Fatal("wrong new superior")
	}
}
