package ldapserver

const (
	TypeBindRequestOp           BerType = 0b01100000
	TypeBindResponseOp          BerType = 0b01100001
	TypeUnbindRequestOp         BerType = 0b01000010
	TypeSearchRequestOp         BerType = 0b01100011
	TypeSearchResultEntryOp     BerType = 0b01100100
	TypeSearchResultDoneOp      BerType = 0b01100101
	TypeModifyRequestOp         BerType = 0b01100110
	TypeModifyResponseOp        BerType = 0b01100111
	TypeAddRequestOp            BerType = 0b01101000
	TypeAddResponseOp           BerType = 0b01101001
	TypeDeleteRequestOp         BerType = 0b01001010
	TypeDeleteResponseOp        BerType = 0b01101011
	TypeModifyDNRequestOp       BerType = 0b01101100
	TypeModifyDNResponseOp      BerType = 0b01101101
	TypeCompareRequestOp        BerType = 0b01101110
	TypeCompareResponseOp       BerType = 0b01101111
	TypeAbandonRequestOp        BerType = 0b01010000
	TypeSearchResultReferenceOp BerType = 0b01110011
	TypeExtendedRequestOp       BerType = 0b01110111
	TypeExtendedResponseOp      BerType = 0b01111000
	TypeIntermediateResponseOp  BerType = 0b01111001
)
