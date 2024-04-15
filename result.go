package ldapserver

import "bytes"

// LDAP result code
type LDAPResultCode uint32

// Defined result codes
const (
	ResultSuccess                  LDAPResultCode = 0
	LDAPResultOperationsError      LDAPResultCode = 1
	LDAPResultProtocolError        LDAPResultCode = 2
	LDAPResultTimeLimitExceeded    LDAPResultCode = 3
	LDAPResultSizeLimitExceeded    LDAPResultCode = 4
	LDAPResultCompareFalse         LDAPResultCode = 5
	LDAPResultCompareTrue          LDAPResultCode = 6
	ResultAuthMethodNotSupported   LDAPResultCode = 7
	LDAPResultStrongerAuthRequired LDAPResultCode = 8
	// 9 reserved
	LDAPResultReferral                     LDAPResultCode = 10
	LDAPResultAdminLimitExceeded           LDAPResultCode = 11
	LDAPResultUnavailableCriticalExtension LDAPResultCode = 12
	LDAPResultConfidentialityRequired      LDAPResultCode = 13
	LDAPResultSaslBindInProgress           LDAPResultCode = 14
	// 15 ???
	LDAPResultNoSuchAttribute        LDAPResultCode = 16
	LDAPResultUndefinedAttributeType LDAPResultCode = 17
	LDAPResultInappropriateMatching  LDAPResultCode = 18
	LDAPResultConstraintViolation    LDAPResultCode = 19
	LDAPResultAttributeOrValueExists LDAPResultCode = 20
	LDAPResultInvalidAttributeSyntax LDAPResultCode = 21
	// 22-31 unused
	LDAPResultNoSuchObject    LDAPResultCode = 32
	LDAPResultAliasProblem    LDAPResultCode = 33
	LDAPResultInvalidDNSyntax LDAPResultCode = 34
	// 35 reserved
	LDAPResultAliasDereferencingProblem LDAPResultCode = 36
	// 37-47 unused
	LDAPResultInappropriateAuthentication LDAPResultCode = 48
	LDAPResultInvalidCredentials          LDAPResultCode = 49
	LDAPResultInsufficientAccessRights    LDAPResultCode = 50
	LDAPResultBusy                        LDAPResultCode = 51
	LDAPResultUnavailable                 LDAPResultCode = 52
	LDAPResultUnwillingToPerform          LDAPResultCode = 53
	LDAPResultLoopDetect                  LDAPResultCode = 54
	// 55-63 unused
	LDAPResultNamingViolation           LDAPResultCode = 64
	LDAPResultObjectClassViolation      LDAPResultCode = 65
	LDAPResultNotAllowedOnNonLeaf       LDAPResultCode = 66
	LDAPResultNotAllowedOnRDN           LDAPResultCode = 67
	LDAPResultEntryAlreadyExists        LDAPResultCode = 68
	LDAPResultObjectClassModsProhibited LDAPResultCode = 69
	// 70 reserved
	LDAPResultAffectsMultibleDSAs LDAPResultCode = 70
	// 72-79 unused
	LDAPResultOther LDAPResultCode = 80
	// extensible, more codes possible
)

//	LDAPResult ::= SEQUENCE {
//			resultCode         ENUMERATED {
//	         -- Defined result codes --
//				...  },
//	     matchedDN          LDAPDN,
//	     diagnosticMessage  LDAPString,
//	     referral           [3] Referral OPTIONAL }
type Result struct {
	ResultCode        LDAPResultCode
	MatchedDN         string
	DiagnosticMessage string
	Referral          []string
}

//	IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
//	     responseName     [0] LDAPOID OPTIONAL,
//	     responseValue    [1] OCTET STRING OPTIONAL }
type IntermediateResponse struct {
	Name  string
	Value string
}

// Return a Result from BER-encoded data
func GetResult(data []byte) (*Result, error) {
	seq, err := BerGetSequence(data)
	if err != nil {
		return nil, err
	}
	if len(seq) != 3 && len(seq) != 4 {
		return nil, ErrWrongSequenceLength.WithInfo("LDAPResult sequence length", len(seq))
	}
	if seq[0].Type != BerTypeEnumerated {
		return nil, ErrWrongElementType.WithInfo("LDAPResult result code type", seq[0].Type)
	}
	resultCode, err := BerGetInteger(seq[0].Data)
	if err != nil {
		return nil, err
	}
	if seq[1].Type != BerTypeOctetString {
		return nil, ErrWrongElementType.WithInfo("LDAPResult matched DN type", seq[1].Type)
	}
	matchedDN := BerGetOctetString(seq[1].Data)
	if seq[2].Type != BerTypeOctetString {
		return nil, ErrWrongElementType.WithInfo("LDAPResult diagnostic message type", seq[2].Type)
	}
	diagnosticMsg := BerGetOctetString(seq[2].Data)
	var referral []string
	if len(seq) == 4 {
		if seq[3].Type.Class() != BerClassContextSpecific ||
			seq[3].Type.TagNumber() != 3 {
			return nil, ErrWrongElementType.WithInfo("LDAPResult referral type", seq[3].Type)
		}
		r_seq, err := BerGetSequence(seq[3].Data)
		if err != nil {
			return nil, err
		}
		for _, rr := range r_seq {
			referral = append(referral, BerGetOctetString(rr.Data))
		}
	}
	res := &Result{
		ResultCode:        LDAPResultCode(resultCode),
		MatchedDN:         matchedDN,
		DiagnosticMessage: diagnosticMsg,
		Referral:          referral,
	}
	return res, nil
}

// Return the BER-encoded struct (without element header)
func (r *Result) Encode() []byte {
	w := bytes.NewBuffer(nil)
	w.Write(BerEncodeEnumerated(int64(r.ResultCode)))
	w.Write(BerEncodeOctetString(r.MatchedDN))
	w.Write(BerEncodeOctetString(r.DiagnosticMessage))
	if len(r.Referral) > 0 {
		referrals := bytes.NewBuffer(nil)
		for _, ref := range r.Referral {
			referrals.Write(BerEncodeOctetString(ref))
		}
		w.Write(BerEncodeSequence(referrals.Bytes()))
	}
	return w.Bytes()
}

// Return the BER-encoded struct (without element header)
func (r *IntermediateResponse) Encode() []byte {
	w := bytes.NewBuffer(nil)
	if r.Name != "" {
		w.Write(BerEncodeElement(BerContextSpecificType(0, false), BerEncodeOctetString(r.Name)))
	}
	if r.Value != "" {
		w.Write(BerEncodeElement(BerContextSpecificType(1, false), BerEncodeOctetString(r.Value)))
	}
	return w.Bytes()
}

func (r LDAPResultCode) AsResult(diagnosticMessage string) *Result {
	res := &Result{
		ResultCode:        r,
		DiagnosticMessage: diagnosticMessage,
	}
	return res
}

// Result returned for protocol errors
var ProtocolError = &Result{
	ResultCode:        LDAPResultProtocolError,
	DiagnosticMessage: "the server could not understand the request",
}

// Result returned for unsupported requests
var UnsupportedOperation = &Result{
	ResultCode:        LDAPResultUnwillingToPerform,
	DiagnosticMessage: "the operation requested is not supported by the server",
}

// Result returned for denied permission
var PermissionDenied = &Result{
	ResultCode:        LDAPResultInsufficientAccessRights,
	DiagnosticMessage: "client has insufficient access rights to the requested resource",
}
