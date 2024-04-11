package ldapserver

import "bytes"

// Defined filter types
const (
	FilterTypeAnd             uint8 = 0
	FilterTypeOr              uint8 = 1
	FilterTypeNot             uint8 = 2
	FilterTypeEqual           uint8 = 3
	FilterTypeSubstrings      uint8 = 4
	FilterTypeGreaterOrEqual  uint8 = 5
	FilterTypeLessOrEqual     uint8 = 6
	FilterTypePresent         uint8 = 7
	FilterTypeApproxMatch     uint8 = 8
	FilterTypeExtensibleMatch uint8 = 9
)

//	Filter ::= CHOICE {
//		and             [0] SET SIZE (1..MAX) OF filter Filter,
//		or              [1] SET SIZE (1..MAX) OF filter Filter,
//		not             [2] Filter,
//		equalityMatch   [3] AttributeValueAssertion,
//		substrings      [4] SubstringFilter,
//		greaterOrEqual  [5] AttributeValueAssertion,
//		lessOrEqual     [6] AttributeValueAssertion,
//		present         [7] AttributeDescription,
//		approxMatch     [8] AttributeValueAssertion,
//		extensibleMatch [9] MatchingRuleAssertion,
//		...  }
type Filter struct {
	Type uint8
	Data any
}

// SubstringFilter ::= SEQUENCE {
// 		type           AttributeDescription,
// 		substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
// 		 	initial [0] AssertionValue,  -- can occur at most once
// 		 	any     [1] AssertionValue,
// 		 	final   [2] AssertionValue } -- can occur at most once
// 		}
type SubstringFilter struct {
	Type    string
	Initial string
	Any     []string
	Final   string
}

// MatchingRuleAssertion ::= SEQUENCE {
// 		matchingRule    [1] MatchingRuleId OPTIONAL,
// 		type            [2] AttributeDescription OPTIONAL,
// 		matchValue      [3] AssertionValue,
// 		dnAttributes    [4] BOOLEAN DEFAULT FALSE }
type MatchingRuleAssertion struct {
	MatchingRule string
	Type         string
	MatchValue   string
	DNAttributes bool
}

// Return a Filter from a raw BER element
func GetFilter(raw BerRawElement) (*Filter, error) {
	if raw.Type.Class() != BerClassContextSpecific {
		return nil, ErrWrongElementType.WithInfo("Filter type", raw.Type)
	}
	f := &Filter{
		Type: raw.Type.TagNumber(),
	}
	switch f.Type {
	case FilterTypeAnd, FilterTypeOr:
		var filters []Filter
		seq, err := BerGetSequence(raw.Data)
		if err != nil {
			return nil, err
		}
		for _, rf := range seq {
			filter, err := GetFilter(rf)
			if err != nil {
				return nil, err
			}
			filters = append(filters, *filter)
		}
		f.Data = filters
	case FilterTypeNot:
		elmt, err := BerReadElement(bytes.NewReader(raw.Data))
		if err != nil {
			return nil, err
		}
		filter, err := GetFilter(elmt)
		if err != nil {
			return nil, err
		}
		f.Data = filter
	case FilterTypeEqual, FilterTypeGreaterOrEqual, FilterTypeLessOrEqual, FilterTypeApproxMatch:
		ass, err := GetAttributeValueAssertion(raw.Data)
		if err != nil {
			return nil, err
		}
		f.Data = ass
	case FilterTypeSubstrings:
		seq, err := BerGetSequence(raw.Data)
		if err != nil {
			return nil, err
		}
		if len(seq) != 2 {
			return nil, ErrWrongSequenceLength.WithInfo("SubstringFilter sequence length", len(seq))
		}
		if seq[0].Type != BerTypeOctetString {
			return nil, ErrWrongElementType.WithInfo("SubstringFilter type type", seq[0].Type)
		}
		sf := &SubstringFilter{Type: BerGetOctetString(seq[0].Data)}
		if seq[1].Type != BerTypeSequence {
			return nil, ErrWrongElementType.WithInfo("SubstringFilter substrings type", seq[1].Type)
		}
		seq, err = BerGetSequence(seq[1].Data)
		if err != nil {
			return nil, err
		}
		for _, rs := range seq {
			if rs.Type.Class() != BerClassContextSpecific {
				return nil, ErrWrongElementType.WithInfo("SubstringFilter substring type", rs.Type)
			}
			switch rs.Type.TagNumber() {
			case 0:
				if sf.Initial != "" {
					return nil, ErrWrongElementType.WithInfo("Multiple initial substrings", string(rs.Data))
				}
				sf.Initial = BerGetOctetString(rs.Data)
			case 1:
				sf.Any = append(sf.Any, BerGetOctetString(rs.Data))
			case 2:
				if sf.Final != "" {
					return nil, ErrWrongElementType.WithInfo("Multiple final substrings", string(rs.Data))
				}
				sf.Final = BerGetOctetString(rs.Data)
			default:
				return nil, ErrWrongElementType.WithInfo("SubstringFilter substring type", rs.Type)
			}
		}
		f.Data = sf
	case FilterTypePresent:
		f.Data = BerGetOctetString(raw.Data)
	case FilterTypeExtensibleMatch:
		seq, err := BerGetSequence(raw.Data)
		if err != nil {
			return nil, err
		}
		m := MatchingRuleAssertion{}
		i := 0
		if len(seq) > i && seq[i].Type == BerContextSpecificType(0, false) {
			m.MatchingRule = BerGetOctetString(seq[i].Data)
			i++
		}
		if len(seq) > i && seq[i].Type == BerContextSpecificType(1, false) {
			m.Type = BerGetOctetString(seq[i].Data)
			i++
		}
		if len(seq) <= i || len(seq) > i+2 {
			return nil, ErrWrongSequenceLength.WithInfo("MatchingRuleAssertion sequence length", len(seq))
		}
		if seq[i].Type != BerContextSpecificType(2, false) {
			return nil, ErrWrongElementType.WithInfo("MatchingRuleAssertion matchValue type", seq[i].Type)
		}
		m.MatchValue = BerGetOctetString(seq[i].Data)
		i++
		if i < len(seq) {
			if seq[i].Type != BerContextSpecificType(3, false) {
				return nil, ErrWrongElementType.WithInfo("MatchingRuleAssertion dnAttributes type", seq[i].Type)
			}
			dna, err := BerGetBoolean(seq[i].Data)
			if err != nil {
				return nil, err
			}
			m.DNAttributes = dna
		}
	default:
		f.Data = &raw
	}
	return f, nil
}
