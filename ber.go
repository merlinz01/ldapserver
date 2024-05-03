package ldapserver

import (
	"bytes"
	"io"
)

// maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
const maxInt = 2147483647

// BER type code (first byte of any element)
type BerType uint8

// BER type classes
const (
	BerClassUniversal       = 0b00000000
	BerClassApplication     = 0b01000000
	BerClassContextSpecific = 0b10000000
	BerClassPrivate         = 0b11000000
)

// Construct a BER context-specific type code with the specified tag
func BerContextSpecificType(tag uint8, constructed bool) BerType {
	c := BerClassContextSpecific | BerType(tag)
	if constructed {
		return c | 0b00100000
	}
	return c
}

// Returns the type class (BerClassXXX)
func (t BerType) Class() uint8 {
	return uint8(t & 0b11000000)
}

// Returns true if the constructed bit is set
func (t BerType) IsConstructed() bool {
	return (t & 0b00100000) == 0b00100000
}

// Returns true if the constructed bit is not set
func (t BerType) IsPrimitive() bool {
	return (t & 0b00100000) == 0
}

// Returns the tag number of the type code
func (t BerType) TagNumber() uint8 {
	return uint8(t & 0b00011111)
}

// Basic BER types
const (
	BerTypeBoolean     BerType = 0b00000001
	BerTypeInteger     BerType = 0b00000010
	BerTypeOctetString BerType = 0b00000100
	BerTypeNull        BerType = 0b00000101
	BerTypeEnumerated  BerType = 0b00001010
	BerTypeSequence    BerType = 0b00110000
	BerTypeSet         BerType = 0b00110001
)

type BerRawElement struct {
	Type BerType
	Data []byte
}

// Read one byte from the io.Reader
func readByte(r io.Reader) (byte, error) {
	if br, ok := r.(io.ByteReader); ok {
		return br.ReadByte()
	}
	buf := make([]byte, 1)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return 0, err
	}
	if n < 1 {
		return 0, io.EOF
	}
	return buf[0], nil
}

// Read an element size from the given io.Reader
func BerReadSize(r io.Reader) (uint32, error) {
	b, err := readByte(r)
	if err != nil {
		return 0, err
	}
	// < 0x80 means the number as-is
	if b < 0x80 {
		return uint32(b), nil
	}
	// >= 0x80 means the first byte minus 0x80 is the number of bytes long the size is
	nbytes := b - 0x80
	if nbytes > 4 {
		// Don't support sizes that would overflow uint32
		return 0, ErrIntegerTooLarge.WithInfo("size length", nbytes)
	}
	// Read the integer from the next nbytes bytes
	var res uint32 = 0
	for i := 0; i < int(nbytes); i++ {
		b, err = readByte(r)
		if err != nil {
			return 0, err
		}
		res <<= 8
		res |= uint32(b)
	}
	return res, nil
}

// Read a raw element from the io.Reader
func BerReadElement(r io.Reader) (elmt BerRawElement, err error) {
	// First byte is type code
	tp, err := readByte(r)
	if err != nil {
		return
	}
	elmt.Type = BerType(tp)
	// Next byte(s) are data size
	length, err := BerReadSize(r)
	if err != nil {
		return
	}
	// Data is the next bytes with given length
	buf := make([]byte, length)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return
	}
	elmt.Data = buf
	return
}

// Return a bool from BER boolean element data
func BerGetBoolean(data []byte) (bool, error) {
	// Protect from a panic, but shouldn't happen
	if len(data) != 1 {
		return false, ErrInvalidBoolean.WithInfo("data length", len(data))
	}
	return data[0] != 0x00, nil
}

// Return an int64 from BER integer element data
func BerGetInteger(data []byte) (int64, error) {
	// Don't support integers that would overflow an int64
	if len(data) > 8 {
		return 0, ErrIntegerTooLarge.WithInfo("length", len(data))
	}
	// Credits to github.com/go-asn1-ber/asn1-ber
	var n int64 = 0
	for _, b := range data {
		n <<= 8
		n |= int64(b)
	}
	n <<= 64 - uint8(len(data))*8
	n >>= 64 - uint8(len(data))*8
	return n, nil
}

// Return an enumerated value from BER enumerated element data (alias for BerGetInteger)
var BerGetEnumerated = BerGetInteger

// Return a string from BER octet string element data
func BerGetOctetString(data []byte) string {
	return string(data)
}

// Return an array of raw elements from BER sequence element data
func BerGetSequence(data []byte) ([]BerRawElement, error) {
	elmts := make([]BerRawElement, 0, 1)
	reader := bytes.NewReader(data)
	for reader.Len() > 0 {
		elmt, err := BerReadElement(reader)
		if err != nil {
			return nil, err
		}
		elmts = append(elmts, elmt)
	}
	return elmts, nil
}

// Return an array of raw elements from BER sequence element data (alias for BerGetSequence)
var BerGetSet = BerGetSequence

// Return a BER-encoded boolean
func BerEncodeBoolean(b bool) []byte {
	if b {
		return []byte{byte(BerTypeBoolean), 1, 0xff}
	} else {
		return []byte{byte(BerTypeBoolean), 1, 0x00}
	}
}

// Return a BER-encoded integer without an element header
func BerEncodeIntegerRaw(i int64) []byte {
	numBytes := 1
	for i > 127 {
		numBytes++
		i >>= 8
	}
	for i < -128 {
		numBytes++
		i >>= 8
	}
	out := make([]byte, numBytes)
	var j int
	for ; numBytes > 0; numBytes-- {
		out[j] = byte(i >> uint((numBytes-1)*8))
		j++
	}
	return out
}

// Return a BER-encoded integer
func BerEncodeInteger(i int64) []byte {
	return BerEncodeElement(BerTypeInteger, BerEncodeIntegerRaw(i))
}

// Return a BER-encoded enumerated value
func BerEncodeEnumerated(i int64) []byte {
	return BerEncodeElement(BerTypeEnumerated, BerEncodeIntegerRaw(i))
}

// Return a BER-encoded element with the specified type code and data
func BerEncodeElement(etype BerType, data []byte) []byte {
	res := make([]byte, 1, len(data)+6)
	res[0] = byte(etype)
	size := len(data)
	if size < 0x80 {
		res = append(res, byte(size))
	} else if size <= 0xffff {
		res = append(res, 0x82, byte((size&0xff00)>>8), byte(size&0xff))
	} else if size <= 0xffffff {
		res = append(res, 0x83, byte((size&0xff0000)>>16), byte((size&0xff00)>>8), byte(size&0xff))
	} else if size <= 0xffffffff {
		res = append(res, 0x84, byte((size&0xff000000)>>24), byte((size&0xff0000)>>16), byte((size&0xff00)>>8), byte(size&0xff))
	} else {
		panic("size too large")
	}
	res = append(res, data...)
	return res
}

// Return a BER-encoded octet string
func BerEncodeOctetString(s string) []byte {
	return BerEncodeElement(BerTypeOctetString, []byte(s))
}

// Return a BER-encoded sequence with the provided data
func BerEncodeSequence(data []byte) []byte {
	return BerEncodeElement(BerTypeSequence, data)
}

// Return a BER-encoded set with the provided data
func BerEncodeSet(data []byte) []byte {
	return BerEncodeElement(BerTypeSet, data)
}
