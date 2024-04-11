package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/merlinz01/ldapserver"
)

func main() {
	handler := &TestHandler{
		abandonment: make(map[ldapserver.MessageID]bool),
	}
	server := ldapserver.NewLDAPServer(handler)
	err := server.SetupTLS("cert.pem", "privkey.pem")
	if err != nil {
		log.Println("Error setting up TLS:", err)
		return
	}
	println("Serving.")
	server.ListenAndServe("localhost:389")
}

type TestHandler struct {
	ldapserver.BaseHandler
	abandonment     map[ldapserver.MessageID]bool
	abandonmentLock sync.Mutex
}

func (t *TestHandler) Abandon(conn *ldapserver.Conn, msg *ldapserver.Message, messageID ldapserver.MessageID) {
	t.abandonmentLock.Lock()
	if _, exists := t.abandonment[messageID]; exists {
		t.abandonment[messageID] = true
	}
	t.abandonmentLock.Unlock()
}

func (t *TestHandler) Bind(conn *ldapserver.Conn, msg *ldapserver.Message, req *ldapserver.BindRequest) {
	res := &ldapserver.BindResponse{}
	if req.Version != 3 {
		res.ResultCode = ldapserver.LDAPResultProtocolError
		res.DiagnosticMessage = "the protocol version received is not supported"
		conn.SendResult(msg.MessageID, nil, ldapserver.TypeBindResponseOp, res)
	}
	switch req.AuthType {
	case ldapserver.AuthenticationTypeSimple:
		log.Println("Simple authentication:", req.Name, req.Credentials.(string))
		if req.Credentials.(string) != "weakpassword" {
			conn.Authentication = nil
			res.ResultCode = ldapserver.LDAPResultInvalidCredentials
		} else {
			conn.Authentication = req.Name
			res.ResultCode = ldapserver.ResultSuccess
		}
	case ldapserver.AuthenticationTypeSASL:
		creds := req.Credentials.(*ldapserver.SASLCredentials)
		log.Println("SASL authentication:", req.Name, creds.Mechanism, creds.Credentials)
		switch creds.Mechanism {
		case "CRAM-MD5":
			// Put verification code in here
			conn.Authentication = nil
			res.ResultCode = ldapserver.ResultAuthMethodNotSupported
			res.DiagnosticMessage = "the CRAM-MD5 authentication method is not supported"
		default:
			conn.Authentication = nil
			res.ResultCode = ldapserver.ResultAuthMethodNotSupported
			res.DiagnosticMessage = "the SASL authentication method requested is not supported"
		}
	default:
		log.Println("Unsupported authentication")
		res.ResultCode = ldapserver.ResultAuthMethodNotSupported
		res.DiagnosticMessage = "the authentication method requested is not supported by this server"
	}
	conn.SendResult(msg.MessageID, nil, ldapserver.TypeBindResponseOp, res)
}

func (t *TestHandler) Search(conn *ldapserver.Conn, msg *ldapserver.Message, req *ldapserver.SearchRequest) {
	// Allow cancellation
	t.abandonment[msg.MessageID] = false
	defer delete(t.abandonment, msg.MessageID)

	auth := ""
	if conn.Authentication != nil {
		if authstr, ok := conn.Authentication.(string); ok {
			auth = authstr
		}
	}
	if auth != "uid=authorizeduser,ou=users,dc=example,dc=com" {
		log.Println("Not an authorized connection!", auth)
		conn.SendResult(msg.MessageID, nil, ldapserver.TypeSearchResultDoneOp, ldapserver.PermissionDenied)
		return
	}
	log.Println("Base object:", req.BaseObject)
	switch req.Scope {
	case ldapserver.SearchScopeBaseObject:
		log.Println("Scope: base object")
	case ldapserver.SearchScopeSingleLevel:
		log.Println("Scope: single level")
	case ldapserver.SearchScopeWholeSubtree:
		log.Println("Scope: whole subtree")
	}
	switch req.DerefAliases {
	case ldapserver.AliasDerefNever:
		log.Println("Never deref aliases")
	case ldapserver.AliasDerefFindingBaseObj:
		log.Println("Deref aliases finding base object")
	case ldapserver.AliasDerefInSearching:
		log.Println("Deref aliases in searching")
	case ldapserver.AliasDerefAlways:
		log.Println("Always deref aliases")
	}
	log.Println("Size limit:", req.SizeLimit)
	log.Println("Time limit:", req.TimeLimit)
	log.Println("Types only:", req.TypesOnly)
	log.Println("Filter:", req.Filter)
	log.Println("Attributes:", req.Attributes)

	// Return some entries
	for i := range make([]any, 5) {
		if t.abandonment[msg.MessageID] {
			log.Println("Abandoning search request after", i, "requests")
			return
		}
		// Pretend to take a while
		time.Sleep(time.Second * 3)
		entry := &ldapserver.SearchResultEntry{
			ObjectName: req.BaseObject,
			Attributes: []ldapserver.Attribute{
				{Description: "givenname", Values: []string{fmt.Sprintf("John Doe %d", i)}},
			},
		}
		conn.SendResult(msg.MessageID, nil, ldapserver.TypeSearchResultEntryOp, entry)
	}

	res := &ldapserver.Result{
		ResultCode: ldapserver.ResultSuccess,
	}
	conn.SendResult(msg.MessageID, nil, ldapserver.TypeSearchResultDoneOp, res)
}
