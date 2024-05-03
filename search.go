package ldapserver

import "bytes"

//	SearchRequest ::= [APPLICATION 3] SEQUENCE {
//			baseObject      LDAPDN,
//			scope           ENUMERATED {
//			 	baseObject              (0),
//			 	singleLevel             (1),
//			 	wholeSubtree            (2),
//			 	...  },
//			derefAliases    ENUMERATED {
//			 	neverDerefAliases       (0),
//			 	derefInSearching        (1),
//			 	derefFindingBaseObj     (2),
//			 	derefAlways             (3) },
//			sizeLimit       INTEGER (0 ..  maxInt),
//			timeLimit       INTEGER (0 ..  maxInt),
//			typesOnly       BOOLEAN,
//			filter          Filter,
//			attributes      AttributeSelection }
type SearchRequest struct {
	BaseObject   string
	Scope        SearchScope
	DerefAliases AliasDerefType
	SizeLimit    uint32
	TimeLimit    uint32
	TypesOnly    bool
	Filter       *Filter
	Attributes   []string
}

type SearchScope uint8

const (
	SearchScopeBaseObject   SearchScope = 0
	SearchScopeSingleLevel  SearchScope = 1
	SearchScopeWholeSubtree SearchScope = 2
	// Defined in a draft, not always supported
	SearchScopeSubordinateSubtree SearchScope = 3
	// extensible, more possible
)

type AliasDerefType uint8

const (
	AliasDerefNever          AliasDerefType = 0
	AliasDerefInSearching    AliasDerefType = 1
	AliasDerefFindingBaseObj AliasDerefType = 2
	AliasDerefAlways         AliasDerefType = 3
)

// SearchResultReference ::= [APPLICATION 19] SEQUENCE
//
//	SIZE (1..MAX) OF uri URI
type SearchResultReference []string

//	SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
//			objectName      LDAPDN,
//			attributes      PartialAttributeList }
//
// PartialAttributeList ::= SEQUENCE OF partialAttribute PartialAttribute
type SearchResultEntry struct {
	ObjectName string
	Attributes []Attribute
}

func GetSearchRequest(data []byte) (*SearchRequest, error) {
	seq, err := BerGetSequence(data)
	if err != nil {
		return nil, err
	}
	if len(seq) != 8 {
		return nil, ErrWrongSequenceLength.WithInfo("SearchRequest sequence length", len(seq))
	}
	if seq[0].Type != BerTypeOctetString {
		return nil, ErrWrongElementType.WithInfo("SearchRequest baseObject type", seq[0].Type)
	}
	baseObject := BerGetOctetString(seq[0].Data)
	if seq[1].Type != BerTypeEnumerated {
		return nil, ErrWrongElementType.WithInfo("SearchRequest scope type", seq[1].Type)
	}
	scope, err := BerGetEnumerated(seq[1].Data)
	if err != nil {
		return nil, err
	}
	if scope < 0 || scope > 128 {
		return nil, ErrIntegerTooLarge.WithInfo("SearchRequest scope", scope)
	}
	if seq[2].Type != BerTypeEnumerated {
		return nil, ErrWrongElementType.WithInfo("SearchRequest derefAliases type", seq[2].Type)
	}
	aliasderef, err := BerGetEnumerated(seq[2].Data)
	if err != nil {
		return nil, err
	}
	if aliasderef < 0 || aliasderef > 3 {
		return nil, ErrIntegerTooLarge.WithInfo("SearchRequest derefAliases", aliasderef)
	}
	if seq[3].Type != BerTypeInteger {
		return nil, ErrWrongElementType.WithInfo("SearchRequest sizeLimit type", seq[3].Type)
	}
	sizeLimit, err := BerGetInteger(seq[3].Data)
	if err != nil {
		return nil, err
	}
	if sizeLimit < 0 || sizeLimit > maxInt {
		return nil, ErrIntegerTooLarge.WithInfo("SearchRequest sizeLimit", sizeLimit)
	}
	if seq[4].Type != BerTypeInteger {
		return nil, ErrWrongElementType.WithInfo("SearchRequest timeLimit type", seq[4].Type)
	}
	timeLimit, err := BerGetInteger(seq[4].Data)
	if err != nil {
		return nil, err
	}
	if timeLimit < 0 || timeLimit > maxInt {
		return nil, ErrIntegerTooLarge.WithInfo("SearchRequest timeLimit", timeLimit)
	}
	if seq[5].Type != BerTypeBoolean {
		return nil, ErrWrongElementType.WithInfo("SearchRequest typesOnly type", seq[5].Type)
	}
	typesOnly, err := BerGetBoolean(seq[5].Data)
	if err != nil {
		return nil, err
	}
	filter, err := GetFilter(seq[6])
	if err != nil {
		return nil, err
	}
	if seq[7].Type != BerTypeSequence {
		return nil, ErrWrongElementType.WithInfo("SearchRequest attributes type", seq[7].Type)
	}
	attrs_seq, err := BerGetSequence(seq[7].Data)
	if err != nil {
		return nil, err
	}
	var attrs []string
	for _, a := range attrs_seq {
		if a.Type != BerTypeOctetString {
			return nil, ErrWrongElementType.WithInfo("SearchRequest attribute type", a.Type)
		}
		attrs = append(attrs, BerGetOctetString(a.Data))
	}
	req := &SearchRequest{
		BaseObject:   baseObject,
		Scope:        SearchScope(scope),
		DerefAliases: AliasDerefType(aliasderef),
		SizeLimit:    uint32(sizeLimit),
		TimeLimit:    uint32(timeLimit),
		TypesOnly:    typesOnly,
		Filter:       filter,
		Attributes:   attrs,
	}
	return req, nil
}

// Return the BER-encoded sequence (without element header)
func (s SearchResultReference) Encode() []byte {
	b := bytes.NewBuffer(nil)
	for _, r := range s {
		b.Write(BerEncodeOctetString(r))
	}
	return b.Bytes()
}

// Return the BER-encoded struct (without element header)
func (s *SearchResultEntry) Encode() []byte {
	b := bytes.NewBuffer(nil)
	b.Write(BerEncodeOctetString(s.ObjectName))
	ab := bytes.NewBuffer(nil)
	for _, attr := range s.Attributes {
		ab.Write(BerEncodeSequence(attr.Encode()))
	}
	b.Write(BerEncodeSequence(ab.Bytes()))
	return b.Bytes()
}
