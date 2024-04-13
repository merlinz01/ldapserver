package ldapserver

// ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
// 	entry        LDAPDN,
// 	newrdn       RelativeLDAPDN,
// 	deleteoldrdn BOOLEAN,
// 	newSuperior  [0] LDAPDN OPTIONAL }
type ModifyDNRequest struct {
	Object       string
	NewRDN       string
	DeleteOldRDN bool
	NewSuperior  string
}

// Return a ModifyDNRequest from BER-encoded data
func GetModifyDNRequest(data []byte) (*ModifyDNRequest, error) {
	seq, err := BerGetSequence(data)
	if err != nil {
		return nil, err
	}
	if len(seq) != 3 && len(seq) != 4 {
		return nil, ErrWrongSequenceLength.WithInfo("ModifyDNRequest sequence length", len(seq))
	}
	if seq[0].Type != BerTypeOctetString {
		return nil, ErrWrongElementType.WithInfo("ModifyDNRequest entry type", seq[0].Type)
	}
	entry := BerGetOctetString(seq[0].Data)
	if seq[1].Type != BerTypeOctetString {
		return nil, ErrWrongElementType.WithInfo("ModifyDNRequest new RDN type", seq[1].Type)
	}
	newRDN := BerGetOctetString(seq[1].Data)
	if seq[2].Type != BerTypeBoolean {
		return nil, ErrWrongElementType.WithInfo("ModifyDNRequest delete old RDN type", seq[2].Type)
	}
	deleteOldRDN, err := BerGetBoolean(seq[2].Data)
	if err != nil {
		return nil, err
	}
	newSuperior := ""
	if len(seq) == 4 {
		if seq[3].Type != BerContextSpecificType(0, false) {
			return nil, ErrWrongElementType.WithInfo("ModifyDNRequest new superior type", seq[3].Type)
		}
		newSuperior = BerGetOctetString(seq[3].Data)
	}
	return &ModifyDNRequest{entry, newRDN, deleteOldRDN, newSuperior}, nil
}
