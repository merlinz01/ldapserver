package ldapserver

import (
	"bytes"
	"errors"
	"io"
)

// MessageID ::= INTEGER (0 .. maxInt)
// maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
type MessageID uint32

// Controls ::= SEQUENCE OF control Control
//
//	Control ::= SEQUENCE {
//		controlType      LDAPOID,
//		criticality      BOOLEAN DEFAULT FALSE,
//		controlValue     OCTET STRING OPTIONAL }
type Control struct {
	OID          OID
	Criticality  bool
	ControlValue string
}

//	LDAPMessage ::= SEQUENCE {
//		messageID       MessageID,
//		protocolOp      CHOICE {
//			 bindRequest           BindRequest,
//			 bindResponse          BindResponse,
//			 unbindRequest         UnbindRequest,
//			 searchRequest         SearchRequest,
//			 searchResEntry        SearchResultEntry,
//			 searchResDone         SearchResultDone,
//			 searchResRef          SearchResultReference,
//			 modifyRequest         ModifyRequest,
//			 modifyResponse        ModifyResponse,
//			 addRequest            AddRequest,
//			 addResponse           AddResponse,
//			 delRequest            DelRequest,
//			 delResponse           DelResponse,
//			 modDNRequest          ModifyDNRequest,
//			 modDNResponse         ModifyDNResponse,
//			 compareRequest        CompareRequest,
//			 compareResponse       CompareResponse,
//			 abandonRequest        AbandonRequest,
//			 extendedReq           ExtendedRequest,
//			 extendedResp          ExtendedResponse,
//			 ...,
//			 intermediateResponse  IntermediateResponse },
//		controls       [0] Controls OPTIONAL }
type Message struct {
	MessageID  MessageID
	ProtocolOp BerRawElement
	Controls   []Control
}

// Read a Message from the io.Reader.
// Does not parse the ProtocolOp element data.
func ReadLDAPMessage(r io.Reader) (*Message, error) {
	// Read the element
	raw, err := BerReadElement(r)
	if err != nil {
		return nil, err
	}
	// LDAPMessage ::= SEQUENCE {
	if raw.Type != BerTypeSequence {
		// TLS client hello starts with \x16\x03
		if raw.Type == 0x16 && len(raw.Data) == 0x03 {
			return nil, errors.New("TLS connection to non-TLS server")
		}
		return nil, ErrWrongElementType.WithInfo("LDAPMessage type", raw.Type)
	}
	seq, err := BerGetSequence(raw.Data)
	if err != nil {
		return nil, err
	}
	// Sequence elements: messageID protocolOp [controls]
	if len(seq) != 2 && len(seq) != 3 {
		return nil, ErrWrongSequenceLength.WithInfo("LDAPMessage sequence length", len(seq))
	}
	// MessageID ::= INTEGER (0 .. maxInt)
	// maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
	if seq[0].Type != BerTypeInteger {
		return nil, ErrWrongElementType.WithInfo("LDAPMessage messageID type", seq[0].Type)
	}
	messageID, err := BerGetInteger(seq[0].Data)
	if err != nil {
		return nil, err
	}
	if messageID < 0 || messageID > 2147483647 {
		return nil, ErrInvalidMessageID.WithInfo("LDAPMessage messageID", messageID)
	}

	// protocolOp is not parsed here

	// controls [0] Controls OPTIONAL
	controls := []Control{}
	if len(seq) == 3 {
		if seq[2].Type != BerContextSpecificType(0, true) {
			return nil, ErrWrongElementType.WithInfo("LDAPControl type", seq[2].Type)
		}
		// Controls ::= SEQUENCE OF control Control
		c_seq, err := BerGetSequence(seq[2].Data)
		if err != nil {
			return nil, err
		}
		for _, c := range c_seq {
			// Control ::= SEQUENCE {
			if c.Type != BerTypeSequence {
				return nil, ErrWrongElementType.WithInfo("LDAPControl type", c.Type)
			}
			c_parts, err := BerGetSequence(c.Data)
			if err != nil {
				return nil, err
			}
			// Sequence elements: controlType [criticality] [controlValue]
			if len(c_parts) != 1 && len(c_parts) != 2 && len(c_parts) != 3 {
				return nil, ErrWrongSequenceLength.WithInfo("LDAPControl sequence length", len(c_parts))
			}
			// controlType LDAPOID
			if c_parts[0].Type != BerTypeOctetString {
				return nil, ErrWrongElementType.WithInfo("LDAPControl OID type", c_parts[0].Type)
			}
			oid := OID(BerGetOctetString(c_parts[0].Data))
			if err = oid.Validate(); err != nil {
				return nil, err
			}
			// criticality BOOLEAN DEFAULT FALSE
			criticality := false
			cvi := 2
			if len(c_parts) > 1 && c_parts[1].Type != BerTypeOctetString {
				if c_parts[1].Type != BerTypeBoolean {
					return nil, ErrWrongElementType.WithInfo("LDAPControl criticality type", c_parts[1].Type)
				}
				criticality, err = BerGetBoolean(c_parts[1].Data)
				if err != nil {
					return nil, err
				}
			} else {
				cvi = 1
			}
			// controlValue OCTET STRING OPTIONAL
			controlvalue := ""
			if len(c_parts) == cvi+1 {
				if c_parts[cvi].Type != BerTypeOctetString {
					return nil, ErrWrongElementType.WithInfo("LDAPControl control value type", c_parts[cvi].Type)
				}
				controlvalue = BerGetOctetString(c_parts[cvi].Data)
			}
			controls = append(controls, Control{OID: oid, Criticality: criticality, ControlValue: controlvalue})
		}
	}

	msg := &Message{
		MessageID:  MessageID(messageID),
		ProtocolOp: seq[1],
		Controls:   controls,
	}
	return msg, nil
}

// Return the BER-encoded representation of the Message (with element header)
func (msg *Message) EncodeWithHeader() []byte {
	data := bytes.NewBuffer(nil)
	data.Write(BerEncodeInteger(int64(msg.MessageID)))
	data.Write(BerEncodeElement(msg.ProtocolOp.Type, msg.ProtocolOp.Data))
	if len(msg.Controls) > 0 {
		csdata := bytes.NewBuffer(nil)
		for _, ctrl := range msg.Controls {
			cdata := bytes.NewBuffer(nil)
			cdata.Write(BerEncodeOctetString(string(ctrl.OID)))
			if ctrl.Criticality {
				cdata.Write(BerEncodeBoolean(ctrl.Criticality))
			}
			if ctrl.ControlValue != "" {
				cdata.Write(BerEncodeOctetString(ctrl.ControlValue))
			}
			csdata.Write(BerEncodeSequence(cdata.Bytes()))
		}
		data.Write(BerEncodeSequence(csdata.Bytes()))
	}
	return BerEncodeSequence(data.Bytes())
}
