package ldapserver

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"sync"
)

type Encodable interface {
	Encode() []byte
}

type Conn struct {
	// Underlying network connection
	Conn net.Conn
	// Flag to signal server to stop reading messages
	closed bool
	// Whether the underlying connection has TLS set up
	isTLS bool
	// TLS config for StartTLS connections
	tlsConfig *tls.Config
	// Mutex to prevent reading/writing while setting up TLS
	tlsStarting sync.Mutex
	// Mutex to synchronize message sending
	sending sync.Mutex
	// Wait group to enable atomic Bind request processing
	asyncOperations sync.WaitGroup
	// User-defined authentication storage
	Authentication any
	// User-defined message storage to enable Abandon functionality.
	// The Conn does not touch the cache.
	MessageCache map[MessageID]any
}

// Closes the underlying connection and stops reading messages.
func (c *Conn) Close() {
	c.Conn.Close()
	c.closed = true
}

// Sends a notice of disconnection to the client
func (c *Conn) NotifyDisconnect(resultCode LDAPResultCode) error {
	return c.SendUnsolicitedNotification(resultCode, OIDNoticeOfDisconnection, "")
}

// Reads a LDAPMessage from the connection
func (c *Conn) ReadMessage() (*Message, error) {
	return ReadLDAPMessage(c.Conn)
}

// Sends an Extended Result with a message ID of 0
func (c *Conn) SendUnsolicitedNotification(resultCode LDAPResultCode, oid OID, respValue string) error {
	res := ExtendedResult{
		Result: Result{
			ResultCode: resultCode,
		},
		ResponseName:  oid,
		ResponseValue: respValue,
	}
	return c.SendResult(0, nil, TypeExtendedResponseOp, &res)
}

// Sends a LDAPMessage to the client and removes the corresponding message from the abandonment cache
func (c *Conn) SendMessage(msg *Message) error {
	c.tlsStarting.Lock()
	defer c.tlsStarting.Unlock()
	c.sending.Lock()
	defer c.sending.Unlock()
	_, err := io.Copy(c.Conn, bytes.NewReader(msg.EncodeWithHeader()))
	return err
}

// Starts TLS on the underlying connection if not already started
func (c *Conn) StartTLS() error {
	c.tlsStarting.Lock()
	defer c.tlsStarting.Unlock()
	if c.isTLS {
		return ErrTLSAlreadySetUp
	}
	if c.tlsConfig == nil {
		return ErrTLSNotAvailable
	}
	tlsConn := tls.Server(c.Conn, c.tlsConfig)
	err := tlsConn.Handshake()
	if err != nil {
		return err
	}
	c.Conn = tlsConn
	c.isTLS = true
	return nil
}

// Sends a LDAPResult to the client with specified parameters.
// Pass an object with an Encode() function returning []byte to res.
func (c *Conn) SendResult(messageID MessageID, controls []Control, rtype BerType, res Encodable) error {
	msg := Message{
		MessageID: messageID,
		Controls:  controls,
	}
	msg.ProtocolOp.Type = rtype
	msg.ProtocolOp.Data = res.Encode()
	return c.SendMessage(&msg)
}
