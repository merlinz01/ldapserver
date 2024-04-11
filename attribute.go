package ldapserver

import "bytes"

// AttributeDescription ::= LDAPString
//                          -- Constrained to <attributedescription>
//                          -- [RFC4512]
// AttributeValue ::= OCTET STRING
// PartialAttribute ::= SEQUENCE {
// 		type       AttributeDescription,
//      vals       SET OF value AttributeValue }
// Attribute ::= PartialAttribute(WITH COMPONENTS {
//      ...,
//      vals (SIZE(1..MAX))})
type Attribute struct {
	Description string
	Values      []string
}

// AttributeDescription ::= LDAPString
//                          -- Constrained to <attributedescription>
//                          -- [RFC4512]
// AttributeValue ::= OCTET STRING
// AttributeValueAssertion ::= SEQUENCE {
// 		attributeDesc   AttributeDescription,
//      assertionValue  AssertionValue }
type AttributeValueAssertion struct {
	Description string
	Value       string
}

// Returns an Attribute from BER-encoded data
func GetAttribute(data []byte) (attr Attribute, err error) {
	seq, err := BerGetSequence(data)
	if err != nil {
		return
	}
	if len(seq) < 2 {
		err = ErrWrongSequenceLength.WithInfo("LDAPAttribute sequence length", len(seq))
		return
	}
	if seq[0].Type != BerTypeOctetString {
		err = ErrWrongElementType.WithInfo("LDAPAttribute description type", seq[0].Type)
		return
	}
	attr.Description = BerGetOctetString(seq[0].Data)
	if seq[1].Type != BerTypeSet {
		err = ErrWrongElementType.WithInfo("LDAPAttribute vals type", seq[1].Type)
		return
	}
	v_set, err := BerGetSet(seq[1].Data)
	if err != nil {
		return
	}
	for _, rv := range v_set {
		if rv.Type != BerTypeOctetString {
			err = ErrWrongElementType.WithInfo("AttributeValue type", rv.Type)
			return
		}
		attr.Values = append(attr.Values, BerGetOctetString(rv.Data))
	}
	return
}

// Return an AttributeValueAssertion from BER-encoded data
func GetAttributeValueAssertion(data []byte) (*AttributeValueAssertion, error) {
	seq, err := BerGetSequence(data)
	if err != nil {
		return nil, err
	}
	if len(seq) != 2 {
		return nil, ErrWrongSequenceLength.WithInfo("AttributeValueAssertion sequence length", len(seq))
	}
	if seq[0].Type != BerTypeOctetString {
		return nil, ErrWrongElementType.WithInfo("AttributeValueAssertion attributeDesc type", seq[0].Type)
	}
	if seq[1].Type != BerTypeOctetString {
		return nil, ErrWrongElementType.WithInfo("AttributeValueAssertion assertionValue type", seq[1].Type)
	}
	return &AttributeValueAssertion{Description: BerGetOctetString(seq[0].Data), Value: BerGetOctetString(seq[1].Data)}, nil
}

// Return the BER-encoded struct (without element header)
func (a *Attribute) Encode() []byte {
	b := bytes.NewBuffer(nil)
	b.Write(BerEncodeOctetString(a.Description))
	vb := bytes.NewBuffer(nil)
	for _, v := range a.Values {
		vb.Write(BerEncodeOctetString(v))
	}
	b.Write(BerEncodeSet(vb.Bytes()))
	return b.Bytes()
}
