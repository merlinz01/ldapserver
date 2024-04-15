package ldapserver

import "bytes"

// LDAP result code
type LDAPResultCode uint32

// Defined result codes
const (
	ResultSuccess                LDAPResultCode = 0
	ResultOperationsError        LDAPResultCode = 1
	ResultProtocolError          LDAPResultCode = 2
	ResultTimeLimitExceeded      LDAPResultCode = 3
	ResultSizeLimitExceeded      LDAPResultCode = 4
	ResultCompareFalse           LDAPResultCode = 5
	ResultCompareTrue            LDAPResultCode = 6
	ResultAuthMethodNotSupported LDAPResultCode = 7
	ResultStrongerAuthRequired   LDAPResultCode = 8
	// 9 reserved
	ResultReferral                     LDAPResultCode = 10
	ResultAdminLimitExceeded           LDAPResultCode = 11
	ResultUnavailableCriticalExtension LDAPResultCode = 12
	ResultConfidentialityRequired      LDAPResultCode = 13
	ResultSaslBindInProgress           LDAPResultCode = 14
	// 15 ???
	ResultNoSuchAttribute        LDAPResultCode = 16
	ResultUndefinedAttributeType LDAPResultCode = 17
	ResultInappropriateMatching  LDAPResultCode = 18
	ResultConstraintViolation    LDAPResultCode = 19
	ResultAttributeOrValueExists LDAPResultCode = 20
	ResultInvalidAttributeSyntax LDAPResultCode = 21
	// 22-31 unused
	ResultNoSuchObject    LDAPResultCode = 32
	ResultAliasProblem    LDAPResultCode = 33
	ResultInvalidDNSyntax LDAPResultCode = 34
	// 35 reserved
	ResultAliasDereferencingProblem LDAPResultCode = 36
	// 37-47 unused
	ResultInappropriateAuthentication LDAPResultCode = 48
	ResultInvalidCredentials          LDAPResultCode = 49
	ResultInsufficientAccessRights    LDAPResultCode = 50
	ResultBusy                        LDAPResultCode = 51
	ResultUnavailable                 LDAPResultCode = 52
	ResultUnwillingToPerform          LDAPResultCode = 53
	ResultLoopDetect                  LDAPResultCode = 54
	// 55-63 unused
	ResultNamingViolation           LDAPResultCode = 64
	ResultObjectClassViolation      LDAPResultCode = 65
	ResultNotAllowedOnNonLeaf       LDAPResultCode = 66
	ResultNotAllowedOnRDN           LDAPResultCode = 67
	ResultEntryAlreadyExists        LDAPResultCode = 68
	ResultObjectClassModsProhibited LDAPResultCode = 69
	// 70 reserved
	ResultAffectsMultibleDSAs LDAPResultCode = 70
	// 72-79 unused
	ResultOther LDAPResultCode = 80
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
