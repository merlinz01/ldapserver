package ldapserver

import "bytes"

// ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
// 		requestName 	[0] LDAPOID,
// 		requestValue    [1] OCTET STRING OPTIONAL }
type ExtendedRequest struct {
	Name  OID
	Value string
}

// ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
// 		COMPONENTS OF LDAPResult,
// 		responseName     [10] LDAPOID OPTIONAL,
// 		responseValue    [11] OCTET STRING OPTIONAL }
type ExtendedResult struct {
	Result
	ResponseName  OID
	ResponseValue string
}

// Return an ExtendedRequest from BER-encoded data
func GetExtendedRequest(data []byte) (*ExtendedRequest, error) {
	// TODO FIXME
	seq, err := BerGetSequence(data)
	if err != nil {
		return nil, err
	}
	if len(seq) != 1 && len(seq) != 2 {
		return nil, ErrWrongSequenceLength.WithInfo("LDAPExtendedRequest sequence length", len(seq))
	}
	if seq[0].Type.Class() != BerClassContextSpecific && seq[0].Type.TagNumber() != 0 {
		return nil, ErrWrongElementType.WithInfo("LDAPExtendedRequest name type", seq[0].Type)
	}
	oid := OID(BerGetOctetString(seq[0].Data))
	if err = oid.Validate(); err != nil {
		return nil, err
	}
	value := ""
	if len(seq) == 2 {
		if seq[1].Type.Class() != BerClassContextSpecific && seq[1].Type.TagNumber() != 1 {
			return nil, ErrWrongElementType.WithInfo("LDAPExtendedRequest value type", seq[1].Type)
		}
		value = BerGetOctetString(seq[1].Data)
	}
	req := &ExtendedRequest{
		Name:  oid,
		Value: value,
	}
	return req, nil
}

// Return the BER-encoded struct (without element header)
func (r *ExtendedResult) Encode() []byte {
	data := bytes.NewBuffer(r.Result.Encode())
	if r.ResponseName != "" {
		data.Write(BerEncodeElement(BerContextSpecificType(10, false), BerEncodeOctetString(string(r.ResponseName))))
	}
	if r.ResponseValue != "" {
		data.Write(BerEncodeElement(BerContextSpecificType(11, false), BerEncodeOctetString(r.ResponseValue)))
	}
	return data.Bytes()
}
