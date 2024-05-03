package ldapserver

import (
	"bytes"
	"strings"
)

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
	FilterTypeAbsoluteTrue    uint8 = 0xa0
	FilterTypeAbsoluteFalse   uint8 = 0xa1
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

//	SubstringFilter ::= SEQUENCE {
//			type           AttributeDescription,
//			substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
//			 	initial [0] AssertionValue,  -- can occur at most once
//			 	any     [1] AssertionValue,
//			 	final   [2] AssertionValue } -- can occur at most once
//			}
type SubstringFilter struct {
	Attribute string
	Initial   string
	Any       []string
	Final     string
}

//	MatchingRuleAssertion ::= SEQUENCE {
//			matchingRule    [1] MatchingRuleId OPTIONAL,
//			type            [2] AttributeDescription OPTIONAL,
//			matchValue      [3] AssertionValue,
//			dnAttributes    [4] BOOLEAN DEFAULT FALSE }
type MatchingRuleAssertion struct {
	MatchingRule string
	Attribute    string
	Value        string
	DNAttributes bool
}

// Return a Filter from a raw BER element
func GetFilter(raw BerRawElement) (*Filter, error) {
	if raw.Type.Class() != BerClassContextSpecific {
		return nil, ErrWrongElementType.WithInfo("Filter type", raw.Type)
	}
	ftype := raw.Type.TagNumber()
	switch {
	case raw.Type == BerContextSpecificType(0, true) && len(raw.Data) == 0:
		ftype = FilterTypeAbsoluteTrue
	case raw.Type == BerContextSpecificType(1, true) && len(raw.Data) == 0:
		ftype = FilterTypeAbsoluteFalse
	}
	f := &Filter{
		Type: ftype,
	}
	switch ftype {
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
		sf := &SubstringFilter{Attribute: BerGetOctetString(seq[0].Data)}
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
		if len(seq) > i && seq[i].Type == BerContextSpecificType(1, false) {
			m.MatchingRule = BerGetOctetString(seq[i].Data)
			i++
		}
		if len(seq) > i && seq[i].Type == BerContextSpecificType(2, false) {
			m.Attribute = BerGetOctetString(seq[i].Data)
			i++
		}
		if len(seq) <= i || len(seq) > i+2 {
			return nil, ErrWrongSequenceLength.WithInfo("MatchingRuleAssertion sequence length", len(seq))
		}
		if seq[i].Type != BerContextSpecificType(3, false) {
			return nil, ErrWrongElementType.WithInfo("MatchingRuleAssertion matchValue type", seq[i].Type)
		}
		m.Value = BerGetOctetString(seq[i].Data)
		i++
		if i < len(seq) {
			if seq[i].Type != BerContextSpecificType(4, false) {
				return nil, ErrWrongElementType.WithInfo("MatchingRuleAssertion dnAttributes type", seq[i].Type)
			}
			dna, err := BerGetBoolean(seq[i].Data)
			if err != nil {
				return nil, err
			}
			m.DNAttributes = dna
		}
		f.Data = &m
	default:
		f.Data = &raw
	}
	return f, nil
}

// Return a string representation of the filter.
//
// NOTE: The output of this function is not valid LDAP if an unrecognized filter type is encountered.
// It outputs unrecognized types as (?<data>), where <data> is the raw data of the unrecognized filter.
func (f *Filter) String() string {
	res := strings.Builder{}
	f.writeToBuilder(&res)
	return res.String()
}

func (f *Filter) writeToBuilder(w *strings.Builder) {
	w.WriteRune('(')
	switch f.Type {
	case FilterTypeAnd:
		w.WriteRune('&')
		for _, filter := range f.Data.([]Filter) {
			filter.writeToBuilder(w)
		}
	case FilterTypeOr:
		w.WriteRune('|')
		for _, filter := range f.Data.([]Filter) {
			filter.writeToBuilder(w)
		}
	case FilterTypeNot:
		w.WriteRune('!')
		f.Data.(*Filter).writeToBuilder(w)
	case FilterTypeEqual:
		ava := f.Data.(*AttributeValueAssertion)
		w.WriteString(ava.Description)
		w.WriteRune('=')
		w.Write(encodeAssertionValue(ava.Value))
	case FilterTypeSubstrings:
		sf := f.Data.(*SubstringFilter)
		w.WriteString(sf.Attribute)
		w.WriteRune('=')
		if sf.Initial != "" {
			w.Write(encodeAssertionValue(sf.Initial))
		}
		w.WriteRune('*')
		for _, mid := range sf.Any {
			w.Write(encodeAssertionValue(mid))
			w.WriteRune('*')
		}
		if sf.Final != "" {
			w.Write(encodeAssertionValue(sf.Final))
		}
	case FilterTypeGreaterOrEqual:
		ava := f.Data.(*AttributeValueAssertion)
		w.WriteString(ava.Description)
		w.WriteString(">=")
		w.Write(encodeAssertionValue(ava.Value))
	case FilterTypeLessOrEqual:
		ava := f.Data.(*AttributeValueAssertion)
		w.WriteString(ava.Description)
		w.WriteString("<=")
		w.Write(encodeAssertionValue(ava.Value))
	case FilterTypePresent:
		w.WriteString(f.Data.(string))
		w.WriteString("=*")
	case FilterTypeApproxMatch:
		ava := f.Data.(*AttributeValueAssertion)
		w.WriteString(ava.Description)
		w.WriteString("~=")
		w.Write(encodeAssertionValue(ava.Value))
	case FilterTypeExtensibleMatch:
		mra := f.Data.(*MatchingRuleAssertion)
		w.WriteString(mra.Attribute)
		if mra.DNAttributes {
			w.WriteString(":dn")
		}
		if mra.MatchingRule != "" {
			w.WriteRune(':')
			w.WriteString(mra.MatchingRule)
		}
		w.WriteString(":=")
		w.Write(encodeAssertionValue(mra.Value))
	case FilterTypeAbsoluteTrue:
		w.WriteRune('&')
	case FilterTypeAbsoluteFalse:
		w.WriteRune('|')
	default:
		w.WriteRune('?')
		w.Write(encodeAssertionValue(string(f.Data.(*BerRawElement).Data)))
	}
	w.WriteRune(')')
}

var avEscapeMap = map[byte]string{
	'*':    "\\2a",
	'(':    "\\28",
	')':    "\\29",
	'\\':   "\\5c",
	'\x00': "\\00",
}

// Encode an assertion value according to RFC 4515
func encodeAssertionValue(value string) []byte {
	buf := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '*', '(', ')', '\\', '\x00':
			buf = append(buf, avEscapeMap[value[i]]...)
		default:
			buf = append(buf, value[i])
		}
	}
	return buf
}
