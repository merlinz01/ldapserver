package ldapserver

// AddRequest ::= [APPLICATION 8] SEQUENCE {
//		entry           LDAPDN,
//		attributes      AttributeList }
// AttributeList ::= SEQUENCE OF attribute Attribute
type AddRequest struct {
	Entry      string
	Attributes []Attribute
}

// Returns an AddRequest from the BER-encoded data
func GetAddRequest(data []byte) (*AddRequest, error) {
	seq, err := BerGetSequence(data)
	if err != nil {
		return nil, err
	}
	if len(seq) != 2 {
		return nil, ErrWrongSequenceLength.WithInfo("LDAPAddRequest sequence length", len(seq))
	}
	if seq[0].Type != BerTypeOctetString {
		return nil, ErrWrongElementType.WithInfo("LDAPAddRequest entry type", seq[0].Type)
	}
	entry := BerGetOctetString(seq[0].Data)
	if seq[1].Type != BerTypeSequence {
		return nil, ErrWrongElementType.WithInfo("LDAPAddRequest attributes type", seq[1].Type)
	}
	a_seq, err := BerGetSequence(seq[1].Data)
	if err != nil {
		return nil, err
	}
	var attributes []Attribute
	for _, ra := range a_seq {
		if ra.Type != BerTypeSequence {
			return nil, ErrWrongElementType.WithInfo("LDAPAttribute type", ra.Type)
		}
		attr, err := GetAttribute(ra.Data)
		if err != nil {
			return nil, err
		}
		attributes = append(attributes, attr)
	}
	req := &AddRequest{
		Entry:      entry,
		Attributes: attributes,
	}
	return req, nil
}
