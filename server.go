package ldapserver

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"syscall"
)

// The LDAP server object
type LDAPServer struct {
	// Listener for new connections
	listener net.Listener
	// Signal for shutdown complete
	done chan struct{}
	// Handler for LDAP requests
	Handler Handler
	// TLS config for StartTLS and LDAPS connections
	TLSConfig *tls.Config
}

// Create a new LDAP server with the specified handler.
func NewLDAPServer(handler Handler) *LDAPServer {
	s := &LDAPServer{
		Handler: handler,
		done:    make(chan struct{}),
	}
	return s
}

// Load the certificate and key to enable TLS connections.
func (s *LDAPServer) SetupTLS(certFile string, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	return nil
}

// Listen for (initially) non-TLS connections on the specified address.
// Clients may still send StartTLS requests which are accepted if s.TLSConfig is not nil
func (s *LDAPServer) ListenAndServe(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	s.Serve(listener)
	return nil
}

// Listen for TLS connections on the specified address.
func (s *LDAPServer) ListenAndServeTLS(address string) error {
	if s.TLSConfig == nil {
		panic("ListenAndServeTLS called with nil TLSConfig")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	listener = tls.NewListener(listener, s.TLSConfig)
	s.Serve(listener)
	return nil
}

// Run a LDAP server using the specified listener.
// Should not be called more than once on the same server object.
func (s *LDAPServer) Serve(listener net.Listener) {
	if listener == nil {
		panic("nil listener")
	}
	if s.Handler == nil {
		s.Handler = &BaseHandler{}
	}
	if s.done == nil {
		// Shutdown() was called
		listener.Close()
		return
	}
	s.listener = listener
	defer func() {
		s.done <- struct{}{}
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				break
			}
			log.Println("Accept error:", err.Error())
			continue
		}
		go s.handleConnection(conn)
	}
}

// Signal the server to shut down and wait for it to stop.
func (s *LDAPServer) Shutdown() {
	if s.listener == nil {
		return
	}
	s.listener.Close()
	<-s.done
	close(s.done)
	s.done = nil
}

// Handle a connection received from the listener.
func (s *LDAPServer) handleConnection(c net.Conn) {
	log.Println("Handle connection")
	defer c.Close()
	ldapConn := Conn{
		Conn:         c,
		tlsConfig:    s.TLSConfig,
		MessageCache: make(map[MessageID]any),
	}
	for {
		if ldapConn.closed {
			// Close() called
			return
		}
		msg, err := ldapConn.ReadMessage()
		if err != nil {
			if errors.Is(err, syscall.Errno(0x2746)) { // Windows: An existing connection was forcibly closed by the client
				log.Println("Connection was reset by the client.")
				ldapConn.Close()
				return
			} else {
				log.Println("Error reading LDAPMessage, closing connection:", err)
				ldapConn.Close()
				return
			}
		}
		s.handleMessage(&ldapConn, msg)
	}
}

// Process a LDAP Message received from the connection.
func (s *LDAPServer) handleMessage(conn *Conn, msg *Message) {
	if msg.ProtocolOp.Type != TypeBindRequestOp {
		conn.asyncOperations.Add(1)
		defer conn.asyncOperations.Done()
	}
	switch msg.ProtocolOp.Type {
	case TypeAbandonRequestOp:
		messageID, err := BerGetInteger(msg.ProtocolOp.Data)
		if err != nil || messageID < 0 || messageID > 2147483647 {
			log.Println("Invalid Abandon request:", err, messageID)
			return
		}
		s.Handler.Abandon(conn, msg, MessageID(messageID))
	case TypeAddRequestOp:
		req, err := GetAddRequest(msg.ProtocolOp.Data)
		if err != nil {
			log.Println("Error parsing Add request:", err)
			conn.SendResult(msg.MessageID, nil, TypeAddResponseOp, ProtocolError)
			return
		}
		conn.asyncOperations.Add(1)
		go func() {
			defer conn.asyncOperations.Done()
			s.Handler.Add(conn, msg, req)
		}()
	case TypeBindRequestOp:
		req, err := GetBindRequest(msg.ProtocolOp.Data)
		if err != nil {
			log.Println("Error parsing Bind request:", err)
			conn.SendResult(msg.MessageID, nil, TypeBindResponseOp, ProtocolError)
			return
		}
		conn.asyncOperations.Wait()
		s.Handler.Bind(conn, msg, req)
	case TypeCompareRequestOp:
		req, err := GetCompareRequest(msg.ProtocolOp.Data)
		if err != nil {
			log.Println("Error parsing Compare request:", err)
			conn.SendResult(msg.MessageID, nil, TypeCompareResponseOp, ProtocolError)
			return
		}
		conn.asyncOperations.Add(1)
		go func() {
			defer conn.asyncOperations.Done()
			s.Handler.Compare(conn, msg, req)
		}()
	case TypeDeleteRequestOp:
		dn := BerGetOctetString(msg.ProtocolOp.Data)
		conn.asyncOperations.Add(1)
		go func() {
			defer conn.asyncOperations.Done()
			s.Handler.Delete(conn, msg, dn)
		}()
	case TypeExtendedRequestOp:
		req, err := GetExtendedRequest(msg.ProtocolOp.Data)
		if err != nil {
			log.Println("Error parsing Extended request:", err)
			conn.SendResult(msg.MessageID, nil, TypeExtendedResponseOp, &ExtendedResult{Result: *ProtocolError})
			return
		}
		// This is not concurrent in case it is a StartTLS request
		s.Handler.Extended(conn, msg, req)
	case TypeModifyRequestOp:
		req, err := GetModifyRequest(msg.ProtocolOp.Data)
		if err != nil {
			log.Println("Error parsing Modify request:", err)
			conn.SendResult(msg.MessageID, nil, TypeModifyResponseOp, ProtocolError)
			return
		}
		conn.asyncOperations.Add(1)
		defer func() {
			defer conn.asyncOperations.Done()
			s.Handler.Modify(conn, msg, req)
		}()
	case TypeModifyDNRequestOp:
		req, err := GetModifyDNRequest(msg.ProtocolOp.Data)
		if err != nil {
			log.Println("Error parsing ModifyDN request:", err)
			conn.SendResult(msg.MessageID, nil, TypeModifyDNResponseOp, ProtocolError)
			return
		}
		conn.asyncOperations.Add(1)
		defer func() {
			defer conn.asyncOperations.Done()
			s.Handler.ModifyDN(conn, msg, req)
		}()
	case TypeSearchRequestOp:
		req, err := GetSearchRequest(msg.ProtocolOp.Data)
		if err != nil {
			log.Println("Error parsing Search request:", err)
			conn.SendResult(msg.MessageID, nil, TypeSearchResultDoneOp, &ExtendedResult{Result: *ProtocolError})
			return
		}
		conn.asyncOperations.Add(1)
		go func() {
			defer conn.asyncOperations.Done()
			s.Handler.Search(conn, msg, req)
		}()
	case TypeUnbindRequestOp:
		// Unbind has no result
		// Simply close the connection
		conn.Close()
	default:
		// Let the handler deal with it if it knows how
		s.Handler.Other(conn, msg)
	}
}
