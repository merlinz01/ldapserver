package ldapserver

import (
	"errors"
	"log"
)

// Interface for LDAP server objects.
// Implementations should inherit BaseHandler for ease of use.
type Handler interface {
	// Abandon the message with the specified ID
	Abandon(*Conn, *Message, MessageID)
	// Perform an Add request
	Add(*Conn, *Message, *AddRequest)
	// Perform a Bind request
	Bind(*Conn, *Message, *BindRequest)
	// Perform a Compare request
	Compare(*Conn, *Message, *CompareRequest)
	// Perform a Delete request
	Delete(*Conn, *Message, string)
	// Perform an Extended request
	Extended(*Conn, *Message, *ExtendedRequest)
	// Perform a Modify request
	Modify(*Conn, *Message, *ModifyRequest)
	// Perform a ModifyDN request
	ModifyDN(*Conn, *Message, *ModifyDNRequest)
	// Perform a Search request
	Search(*Conn, *Message, *SearchRequest)
	// Handle unrecognized requests
	Other(*Conn, *Message)
}

// Basic server functionality.
// Returns UnsupportedOperation for most requests.
// Handles or dispatches common Extended requests.
type BaseHandler struct {
}

func (*BaseHandler) Abandon(conn *Conn, msg *Message, messageID MessageID) {
	// Abandon has no result
}

func (*BaseHandler) Add(conn *Conn, msg *Message, req *AddRequest) {
	conn.SendResult(msg.MessageID, nil, TypeAddResponseOp, UnsupportedOperation)
}

func (*BaseHandler) Bind(conn *Conn, msg *Message, req *BindRequest) {
	conn.SendResult(msg.MessageID, nil, TypeBindResponseOp, UnsupportedOperation)
}

func (*BaseHandler) Compare(conn *Conn, msg *Message, req *CompareRequest) {
	conn.SendResult(msg.MessageID, nil, TypeCompareResponseOp, UnsupportedOperation)
}

func (*BaseHandler) Delete(conn *Conn, msg *Message, dn string) {
	conn.SendResult(msg.MessageID, nil, TypeDeleteResponseOp, UnsupportedOperation)
}

func (*BaseHandler) Modify(conn *Conn, msg *Message, req *ModifyRequest) {
	conn.SendResult(msg.MessageID, nil, TypeModifyResponseOp, UnsupportedOperation)
}

func (*BaseHandler) ModifyDN(conn *Conn, msg *Message, req *ModifyDNRequest) {
	conn.SendResult(msg.MessageID, nil, TypeModifyDNResponseOp, UnsupportedOperation)
}

func (*BaseHandler) Search(conn *Conn, msg *Message, req *SearchRequest) {
	conn.SendResult(msg.MessageID, nil, TypeSearchResultDoneOp, UnsupportedOperation)
}

// Implementers should provide their own Extended method that defaults to calling this
// if they want to handle other Extended requests.
func (h *BaseHandler) Extended(conn *Conn, msg *Message, req *ExtendedRequest) {
	switch req.Name {
	case OIDStartTLS:
		h.StartTLS(conn, msg)
	default:
		log.Println("Unknown extended request:", req.Name)
		res := &ExtendedResult{
			Result: Result{
				ResultCode:        LDAPResultProtocolError,
				DiagnosticMessage: "the requsted Extended operation is not supported",
			},
		}
		conn.SendResult(msg.MessageID, nil, TypeExtendedResponseOp, res)
	}
}

// Handles a StartTLS extended request
func (*BaseHandler) StartTLS(conn *Conn, msg *Message) {
	res := ExtendedResult{
		Result:       Result{ResultCode: ResultSuccess},
		ResponseName: OIDStartTLS,
	}
	err := conn.StartTLS()
	switch {
	case err == nil:
		// pass
	case errors.Is(err, ErrTLSNotAvailable):
		log.Println("TLS not available for StartTLS")
		res.ResultCode = LDAPResultUnwillingToPerform
		res.DiagnosticMessage = "TLS is not available for StartTLS"
	case errors.Is(err, ErrTLSAlreadySetUp):
		log.Println("TLS is already set up on this connection")
		res.ResultCode = LDAPResultOperationsError
		res.DiagnosticMessage = "TLS is already set up on this connection"
	default:
		log.Println("StartTLS failed, closing connection:", err)
		conn.Close()
		return
	}
	conn.SendResult(msg.MessageID, nil, TypeExtendedResponseOp, &res)
}

func (*BaseHandler) Other(conn *Conn, msg *Message) {
	conn.SendResult(msg.MessageID, nil, BerTypeSequence, UnsupportedOperation)
}
