package ldapserver

import (
	"bytes"
	"strconv"
	"strings"
	"unicode"
)

type DN []RDN

type RDN []RDNAttribute

type RDNAttribute struct {
	Type  string
	Value string
}

func (d DN) String() string {
	s := ""
	for i, rdn := range d {
		if i > 0 {
			s += ","
		}
		s += rdn.String()
	}
	return s
}

func (d DN) Equal(other DN) bool {
	if len(d) != len(other) {
		return false
	}
	for i, rdn := range d {
		if !rdn.Equal(other[i]) {
			return false
		}
	}
	return true
}

func (r RDN) String() string {
	s := ""
	for i, attr := range r {
		if i > 0 {
			s += "+"
		}
		s += attr.String()
	}
	return s
}

func (r RDN) Equal(other RDN) bool {
	if len(r) != len(other) {
		return false
	}
	for i, attr := range r {
		if attr.Type != other[i].Type || attr.Value != other[i].Value {
			return false
		}
	}
	return true
}

func (a RDNAttribute) String() string {
	if OID(a.Type).Validate() == nil {
		buf := make([]byte, 1, len(a.Value)*2+1)
		buf[0] = '#'
		for _, b := range BerEncodeOctetString(a.Value) {
			s := strconv.FormatUint(uint64(b), 16)
			if len(s) == 1 {
				s = "0" + s
			}
			buf = append(buf, strings.ToUpper(s)...)
		}
		return a.Type + "=" + string(buf)
	} else {
		buf := make([]byte, 0, len(a.Value))
		for i, b := range []byte(a.Value) {
			switch b {
			case ' ':
				if i == 0 || i == len(a.Value)-1 {
					buf = append(buf, '\\', b)
				} else {
					buf = append(buf, b)
				}
			case '#':
				if i == 0 {
					buf = append(buf, '\\', b)
				} else {
					buf = append(buf, b)
				}
			case '"', '+', ',', ';', '<', '>', '\\', '=':
				buf = append(buf, '\\', b)
			case '\x00':
				buf = append(buf, '\\', '0', '0')
			default:
				if unicode.IsPrint(rune(b)) {
					buf = append(buf, b)
				} else {
					s := strconv.FormatUint(uint64(b), 16)
					if len(s) == 1 {
						s = "0" + s
					}
					s = "\\" + s
					buf = append(buf, strings.ToUpper(s)...)
				}
			}
		}
		return a.Type + "=" + string(buf)
	}
}

func ParseDN(s string) (DN, error) {
	var dn DN
	for _, rdn := range splitRDNs(s) {
		var r RDN
		for _, attr := range splitAttrs(rdn) {
			parts := splitAttr(attr)
			value, err := DecodeRDNAttributeValue(parts[1])
			if err != nil {
				return nil, err
			}
			r = append(r, RDNAttribute{Type: parts[0], Value: value})
		}
		dn = append(dn, r)
	}
	return dn, nil
}

func splitRDNs(s string) []string {
	if s == "" {
		return nil
	}
	a := make([]string, 0, 1)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			// Handle escaped comma
			slash_index := i - 1
			for slash_index >= 0 {
				if s[slash_index] != '\\' {
					break
				}
				slash_index--
			}
			if (i-slash_index)%2 == 1 {
				a = append(a, s[start:i])
				start = i + 1
			}
		}
	}
	a = append(a, s[start:])
	return a
}

func splitAttrs(s string) []string {
	if s == "" {
		return nil
	}
	a := make([]string, 0, 1)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '+' {
			// Handle escaped plus
			slash_index := i - 1
			for slash_index >= 0 {
				if s[slash_index] != '\\' {
					break
				}
				slash_index--
			}
			if (i-slash_index)%2 == 1 {
				a = append(a, s[start:i])
				start = i + 1
			}
		}
	}
	a = append(a, s[start:])
	return a
}

func splitAttr(s string) []string {
	return strings.SplitN(s, "=", 2)
}

func DecodeRDNAttributeValue(s string) (string, error) {
	if len(s) == 0 {
		return s, nil
	}
	if s[0] == '#' {
		buf := make([]byte, 0, len(s)/2)
		for i := 1; i < len(s); i += 2 {
			b := (s[i]-'0')<<4 + (s[i+1] - '0')
			buf = append(buf, b)
		}
		s, err := BerReadElement(bytes.NewReader(buf))
		if err != nil {
			return "", err
		}
		if s.Type != BerTypeOctetString {
			return "", ErrWrongElementType.WithInfo("RDNAttribute type", s.Type)
		}
		return BerGetOctetString(s.Data), nil
	}
	buf := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == '\\' {
			if i+1 < len(s) {
				b2 := s[i+1]
				switch b2 {
				case '"', '+', ',', ';', '<', '>', ' ', '\\', '=', '#':
					buf = append(buf, b2)
					i++
				default:
					if i+2 < len(s) {
						bi, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
						if err == nil {
							buf = append(buf, byte(bi))
							i += 2
						} else {
							buf = append(buf, b)
						}
					} else {
						buf = append(buf, b)
					}
				}
			}
		} else {
			buf = append(buf, b)
		}
	}
	return string(buf), nil
}