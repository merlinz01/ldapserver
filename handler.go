package ldapserver

import (
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
	conn.SendResult(msg.MessageID, nil, TypeAddResponseOp,
		ResultUnwillingToPerform.AsResult("the Add operation not supported by this server"))
}

func (*BaseHandler) Bind(conn *Conn, msg *Message, req *BindRequest) {
	conn.SendResult(msg.MessageID, nil, TypeBindResponseOp,
		ResultUnwillingToPerform.AsResult("the Bind operation not supported by this server"))
}

func (*BaseHandler) Compare(conn *Conn, msg *Message, req *CompareRequest) {
	conn.SendResult(msg.MessageID, nil, TypeCompareResponseOp,
		ResultUnwillingToPerform.AsResult("the Compare operation not supported by this server"))
}

func (*BaseHandler) Delete(conn *Conn, msg *Message, dn string) {
	conn.SendResult(msg.MessageID, nil, TypeDeleteResponseOp,
		ResultUnwillingToPerform.AsResult("the Delete operation not supported by this server"))
}

func (*BaseHandler) Modify(conn *Conn, msg *Message, req *ModifyRequest) {
	conn.SendResult(msg.MessageID, nil, TypeModifyResponseOp,
		ResultUnwillingToPerform.AsResult("the Modify operation not supported by this server"))
}

func (*BaseHandler) ModifyDN(conn *Conn, msg *Message, req *ModifyDNRequest) {
	conn.SendResult(msg.MessageID, nil, TypeModifyDNResponseOp,
		ResultUnwillingToPerform.AsResult("the ModifyDN operation not supported by this server"))
}

func (*BaseHandler) Search(conn *Conn, msg *Message, req *SearchRequest) {
	conn.SendResult(msg.MessageID, nil, TypeSearchResultDoneOp,
		ResultUnwillingToPerform.AsResult("the Search operation not supported by this server"))
}

// Implementers should provide their own Extended method that defaults to calling this
// if they want to handle other Extended requests.
func (h *BaseHandler) Extended(conn *Conn, msg *Message, req *ExtendedRequest) {
	switch req.Name {
	case OIDStartTLS:
		res := ExtendedResult{}
		res.ResponseName = OIDStartTLS
		if conn.TLSConfig == nil {
			log.Println("StartTLS requested but TLS is not available")
			res.Result.ResultCode = ResultProtocolError
			res.DiagnosticMessage = "TLS is not available on this connection"
			conn.SendResult(msg.MessageID, nil, TypeExtendedResponseOp, &res)
			return
		} else if conn.IsTLS() {
			log.Println("StartTLS requested but TLS is already set up")
			res.Result.ResultCode = ResultOperationsError
			res.DiagnosticMessage = "TLS is already set up on this connection"
			conn.SendResult(msg.MessageID, nil, TypeExtendedResponseOp, &res)
			return
		} else {
			res.Result.ResultCode = ResultSuccess
			res.DiagnosticMessage = "TLS is supported, go ahead"
			conn.SendResult(msg.MessageID, nil, TypeExtendedResponseOp, &res)
			err := conn.StartTLS()
			if err != nil {
				log.Println("Error starting TLS:", err)
				conn.Close()
			}
		}
	default:
		log.Println("Unknown extended request:", req.Name)
		res := &ExtendedResult{
			Result: Result{
				ResultCode:        ResultProtocolError,
				DiagnosticMessage: "the requsted Extended operation is not supported",
			},
		}
		conn.SendResult(msg.MessageID, nil, TypeExtendedResponseOp, res)
	}
}

func (*BaseHandler) Other(conn *Conn, msg *Message) {
	conn.NotifyDisconnect(ResultProtocolError, "operation type not recognized")
	conn.Close()
}
