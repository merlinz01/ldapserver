package ldapserver

import "bytes"

// Type of authentication type codes
type AuthenticationType uint8

// Defined authentication type codes
const (
	AuthenticationTypeSimple AuthenticationType = 0
	// 1-2 reserved
	AuthenticationTypeSASL AuthenticationType = 3
	// extensible, more possible
)

//	SaslCredentials ::= SEQUENCE {
//			mechanism	LDAPString,
//			credentials	OCTET STRING OPTIONAL }
type SASLCredentials struct {
	Mechanism   string
	Credentials string
}

//	BindRequest ::= [APPLICATION 0] SEQUENCE {
//			version         INTEGER (1 ..  127),
//			name            LDAPDN,
//			authentication	AuthenticationChoice }
//
//	AuthenticationChoice ::= CHOICE {
//			simple	[0] OCTET STRING,
//					-- 1 and 2 reserved
//			sasl    [3] SaslCredentials,
//			...  }
type BindRequest struct {
	Version  uint8
	Name     string
	AuthType AuthenticationType
	// For Simple, a string
	// For SASL, a pointer to a SASLCredentials struct
	Credentials any
}

//	BindResult ::= [APPLICATION 1] SEQUENCE {
//			COMPONENTS OF LDAPResult,
//			serverSaslCreds    [7] OCTET STRING OPTIONAL }
type BindResult struct {
	Result
	ServerSASLCredentials string
}

// Return a BindRequest from BER-encoded data
func GetBindRequest(data []byte) (*BindRequest, error) {
	seq, err := BerGetSequence(data)
	if err != nil {
		return nil, err
	}
	if len(seq) != 3 {
		return nil, ErrWrongSequenceLength.WithInfo("LDAPAddRequest sequence length", len(seq))
	}
	if seq[0].Type != BerTypeInteger {
		return nil, ErrWrongElementType.WithInfo("LDAPBindRequest version type", seq[0].Type)
	}
	version, err := BerGetInteger(seq[0].Data)
	if err != nil {
		return nil, err
	}
	if version < 1 || version > 127 {
		return nil, ErrInvalidLDAPMessage
	}
	if seq[1].Type != BerTypeOctetString {
		return nil, ErrWrongElementType.WithInfo("LDAPAddRequest name type", seq[1].Type)
	}
	name := BerGetOctetString(seq[1].Data)
	if seq[2].Type.Class() != BerClassContextSpecific {
		return nil, ErrWrongElementType.WithInfo("LDAPAddRequest auth type", seq[2].Type)
	}
	authtype := AuthenticationType(seq[2].Type.TagNumber())
	var credentials any
	switch authtype {
	case AuthenticationTypeSimple:
		credentials = BerGetOctetString(seq[2].Data)
	case AuthenticationTypeSASL:
		s_seq, err := BerGetSequence(seq[2].Data)
		if err != nil {
			return nil, err
		}
		if len(s_seq) != 1 && len(s_seq) != 2 {
			return nil, ErrWrongSequenceLength.WithInfo("SASLCredentials sequence length", len(s_seq))
		}
		if s_seq[0].Type != BerTypeOctetString {
			return nil, ErrWrongElementType.WithInfo("SASLCredentials mechanism type", s_seq[0].Type)
		}
		saslCredentials := ""
		if len(s_seq) == 2 {
			if s_seq[1].Type != BerTypeOctetString {
				return nil, ErrWrongElementType.WithInfo("SASLCredentials credentials type", s_seq[1].Type)
			}
			saslCredentials = BerGetOctetString(s_seq[1].Data)
		}
		credentials = &SASLCredentials{
			Mechanism:   BerGetOctetString(s_seq[0].Data),
			Credentials: saslCredentials,
		}
	default:
		credentials = nil
	}
	req := &BindRequest{
		Version:     uint8(version),
		Name:        name,
		AuthType:    authtype,
		Credentials: credentials,
	}
	return req, nil
}

// Returns the BER-encoded struct (without element header)
func (r *BindResult) Encode() []byte {
	if r.ServerSASLCredentials == "" {
		return r.Result.Encode()
	}
	b := bytes.NewBuffer(r.Result.Encode())
	b.Write(BerEncodeElement(BerContextSpecificType(7, false), BerEncodeOctetString(r.ServerSASLCredentials)))
	return b.Bytes()
}
