# ldapserver

A LDAPv3 server framework.

## Why another LDAP library?

I needed to integrate an LDAP-compatible web app with my website database's stored login information.
I didn't want to try to manipulate a full-stack LDAP server
from my website's code, so a custom LDAP server 
was what I was looking for.
The LDAP server frameworks I found gave obscure errors/panics
when I tested them. Being suspicious of the security implications
of such errors, I decided to write a new framework,
specifically focused on enabling the building of custom integrations.

## Usage

See `test/main.go` for an example implementation.

### Create a handler

Create an object implementing the `Handler` interface.
The recommended way to do this is to define a struct that inherits
the `BaseHandler` type, which provides default handling
for all methods, and also handles StartTLS extended requests.

```go
type MyHandler struct {
    ldapserver.BaseHandler
}
handler := &MyHandler{}
```

### Create a LDAP server

Create a `LDAPServer` object using `NewLDAPServer()`.

```go
server := ldapserver.NewLDAPServer(handler)
```

### Set up TLS

Provide a key pair to the server using `SetupTLS()`.

```go
err := server.SetupTLS("cert.pem", "key.pem")
if err != nil {
    log.Println("Error setting up TLS:", err)
    return
}
```

### Start the server

Use `ListenAndServe()` for a `ldap://` server,
or `ListenAndServeTLS()` for a `ldaps://` server.

```go
server.ListenAndServe(":389")
```
```go
server.ListenAndServeTLS(":636")
```

### Shut down the server

If you need to shut down the server gracefully,
call its `Shutdown()` method.

```go
server.Shutdown()
```

## Adding LDAP operations

To enable more functionality,
define your own methods on the handler.

```go
func (h *MyHandler) Bind(conn *ldapserver.Conn, msg *ldapserver.Message, req *ldapserver.BindRequest) {
    // Put your authentication logic here
    result := &ldapserver.BindResponse{}
    result.ResultCode = ldapserver.LDAPResultSuccess
    conn.SendResult(result)
}
```

### Extended operations

The `BaseHandler` struct handles the StartTLS extended operation.
If you want to handle other extended operations,
define your own `Extended()` method.
Use a `switch` statement to determine which extended operation 
to use. For requests you do not handle, simply pass the function
arguments on to the `BaseHandler`'s method, which handles
StartTLS and unsupported requests.

```go
func (h *MyHandler) Extended(conn *ldapserver.Conn, msg *ldapserver.Message, req *.dapserver.ExtendedRequest) {
	switch req.Name {
	case ldapserver.OIDPasswordModify:
		log.Println("Modify password")
		// Put your password modify code here
	default:
		h.BaseHandler.Extended(conn, msg, req)
	}
}
```

## Operation cancellation

To support cancellation of an operation, 
the following method is recommended.
See `test/main.go` for an example.

Add a map and mutex to your handler's struct.

```go
type MyHandler struct {
    ldapserver.BaseHandler
    abandonment map[ldapserver.MessageID]bool
    abandonmentMutex sync.Mutex
}
```

At the beginning of an cancelable method, 
put a flag in the `abandonment` map to indicate that
the operation can be canceled.

```go
h.abandonment[msg.MessageID] = false // i.e. not cancelled but may be
// Make sure not to leave dangling ends
defer delete(h.abandonment, msg.MessageID)
```

Wherever in the method you want to be able to cancel
(e.g. at the beginning/end of a loop), put in the following logic:

```go
...
if t.abandonment[msg.MessageID] {
    log.Println("Abandoning operation")
    return
}
...
```

## Authentication

The `Conn` object passed to each request method
has an `Authentication` field with type `any`, 
for storing implementation-defined authentication info.
See `test/main.go` for an example.

## Goals

- Full conformance to the relevant specifications,
  especially RFC 4511.
- Support for all builtin operations and common extended operations
- Comprehensive encoding/decoding tests
- Strict client data validity checking
  - Currently the only string values
    validated internally are OIDs.
