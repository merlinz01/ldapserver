package ldapserver

// ModifyRequest ::= [APPLICATION 6] SEQUENCE {
// 	object   LDAPDN,
// 	changes  SEQUENCE OF change SEQUENCE {
// 		operation ENUMERATED {
// 			add     (0),
// 			delete  (1),
// 			replace (2) },
// 		modification Attribute }
type ModifyRequest struct {
	Object  string
	Changes []ModifyChange
}

type ModifyChange struct {
	Operation    ModifyOperation
	Modification Attribute
}

type ModifyOperation uint8

// Defined operations
const (
	ModifyAdd     ModifyOperation = 0
	ModifyDelete  ModifyOperation = 1
	ModifyReplace ModifyOperation = 2
	// extensible, more possible
)

// Return a ModifyRequest from BER-encoded data
func GetModifyRequest(data []byte) (*ModifyRequest, error) {
	seq, err := BerGetSequence(data)
	if err != nil {
		return nil, err
	}
	if len(seq) != 2 {
		return nil, ErrWrongSequenceLength.WithInfo("ModifyRequest sequence length", len(seq))
	}
	if seq[0].Type != BerTypeOctetString {
		return nil, ErrWrongElementType.WithInfo("ModifyRequest object type", seq[0].Type)
	}
	object := BerGetOctetString(seq[0].Data)
	if seq[1].Type != BerTypeSequence {
		return nil, ErrWrongElementType.WithInfo("ModifyRequest changes type", seq[1].Type)
	}
	ch_seq, err := BerGetSequence(seq[1].Data)
	if err != nil {
		return nil, err
	}
	var changes []ModifyChange
	for _, c := range ch_seq {
		if c.Type != BerTypeSequence {
			return nil, ErrWrongElementType.WithInfo("ModifyRequest change type", c.Type)
		}
		c_seq, err := BerGetSequence(c.Data)
		if err != nil {
			return nil, err
		}
		if len(c_seq) != 2 {
			return nil, ErrWrongSequenceLength.WithInfo("ModifyRequest change sequence length", len(c_seq))
		}
		if c_seq[0].Type != BerTypeEnumerated {
			return nil, ErrWrongElementType.WithInfo("ModifyRequest change operation type", c_seq[0].Type)
		}
		op, err := BerGetEnumerated(c_seq[0].Data)
		if err != nil {
			return nil, err
		}
		if c_seq[1].Type != BerTypeSequence {
			return nil, ErrWrongElementType.WithInfo("ModifyRequest change modification type", c_seq[1].Type)
		}
		attr, err := GetAttribute(c_seq[1].Data)
		if err != nil {
			return nil, err
		}
		changes = append(changes, ModifyChange{Operation: ModifyOperation(op), Modification: attr})
	}
	return &ModifyRequest{Object: object, Changes: changes}, nil
}
