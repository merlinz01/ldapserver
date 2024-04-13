package ldapserver

// CompareRequest ::= [APPLICATION 14] SEQUENCE {
// 	entry   LDAPDN,
// 	ava     AttributeValueAssertion }
// AttributeValueAssertion ::= SEQUENCE {
// 	attributeDesc   AttributeDescription,
// 	assertionValue  AssertionValue }
// AttributeDescription ::= LDAPString
// AssertionValue ::= OCTET STRING
type CompareRequest struct {
	Object    string
	Attribute string
	Value     string
}

func GetCompareRequest(data []byte) (*CompareRequest, error) {
	seq, err := BerGetSequence(data)
	if err != nil {
		return nil, err
	}
	if len(seq) != 2 {
		return nil, ErrWrongSequenceLength.WithInfo("CompareRequest sequence length", len(seq))
	}
	if seq[0].Type != BerTypeOctetString {
		return nil, ErrWrongElementType.WithInfo("CompareRequest object type", seq[0].Type)
	}
	object := BerGetOctetString(seq[0].Data)
	if seq[1].Type != BerTypeSequence {
		return nil, ErrWrongElementType.WithInfo("CompareRequest ava type", seq[1].Type)
	}
	ava_seq, err := BerGetSequence(seq[1].Data)
	if err != nil {
		return nil, err
	}
	if len(ava_seq) != 2 {
		return nil, ErrWrongSequenceLength.WithInfo("CompareRequest ava sequence length", len(ava_seq))
	}
	if ava_seq[0].Type != BerTypeOctetString {
		return nil, ErrWrongElementType.WithInfo("CompareRequest attribute description type", ava_seq[0].Type)
	}
	description := BerGetOctetString(ava_seq[0].Data)
	if ava_seq[1].Type != BerTypeOctetString {
		return nil, ErrWrongElementType.WithInfo("CompareRequest assertion value type", ava_seq[1].Type)
	}
	value := BerGetOctetString(ava_seq[1].Data)
	return &CompareRequest{object, description, value}, nil
}
