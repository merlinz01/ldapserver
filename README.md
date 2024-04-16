# ldapserver

A LDAPv3 server framework for custom integrations or full-blown LDAP servers, with no external dependencies.
Focus on the logic of your integration and forget the low-level details.

```
go get github.com/merlinz01/ldapserver
```

## Why another LDAP library?

I needed to integrate an LDAP-compatible web app with my website database's stored login information.
I didn't want to try to remotely manipulate an off-the-shelf LDAP server
from my website's code, so a custom LDAP server 
was what I was looking for.
The existing LDAP server frameworks I found threw obscure errors
when I tested them. Being suspicious of the security implications
of such errors, I decided to write a new framework,
specifically focused on enabling the building of custom integrations.

## Usage

This package provides an interface similar to that of `net/http`.
See `test/main.go` for a working demo implementation.

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

Or you can set/modify the server's `TLSConfig` field
for more specific configuration.
The server's `TLSConfig` must not be `nil` if you want
to support StartTLS or initial TLS.

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

## Implementing LDAP operations

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
func (h *MyHandler) Extended(conn *ldapserver.Conn, msg *ldapserver.Message, req *ldapserver.ExtendedRequest) {
	switch req.Name {
	case ldapserver.OIDPasswordModify:
		log.Println("Modify password")
		// Put your password modify code here
	default:
		h.BaseHandler.Extended(conn, msg, req)
	}
}
```

## Returning results

To return a result, create a `Result` struct with the desired `ResultCode`.
For error results, you should also set the `DiagnosticMessage` field 
so that the user knows what sort of error occurred.
Pass the result along with the appropriate response type code
to the connection's `SendResult` method.

The Bind and Extended requests have their own response types,
`BindResponse` and `ExtendedResponse`, that include a `Result` struct.
These, as well as the `SearchResultEntry` and `SearchResultReference` structs,
can also be passed to `Conn.SendResult()`.

The library defines the result codes in RFC4511 with a `Result` prefix,
e.g. `ResultNoSuchObject`. 
These constants have an `AsResult()` method that returns a pointer to a `Result` struct with the given `DiagnosticMessage` field
that can be passed directly to `Conn.SendResult()`.

## Operation cancellation

To support cancellation of an operation, 
the following method is recommended.
See `test/main.go` for an example.

Add a map and an accompanying mutex to your handler's struct.

```go
type MyHandler struct {
    ...
    abandonment      map[ldapserver.MessageID]bool // Don't forget to initialize the map!
    abandonmentMutex sync.Mutex
}
```

At the beginning of an cancelable method, 
put a flag in the `abandonment` map to indicate that
the operation can be canceled.

```go
h.abandonment[msg.MessageID] = false // i.e. not cancelled but may be
// Remove the flag when done
defer func() {
    t.abandonmentLock.Lock()
    delete(t.abandonment, msg.MessageID)
    t.abandonmentLock.Unlock()
}()
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

Then define your Abandon method like this:

```go
func (t *TestHandler) Abandon(conn *ldapserver.Conn, msg *ldapserver.Message, messageID ldapserver.MessageID) {
    t.abandonmentLock.Lock()
    // Set the flag only if the messageID is in the map
    if _, exists := t.abandonment[messageID]; exists {
        t.abandonment[messageID] = true
    }
    t.abandonmentLock.Unlock()
}
```

## Authentication

The `Conn` object passed to each request method
has an `Authentication` field with type `any`, 
for storing implementation-defined authentication info.
See `test/main.go` for an example.

## Feature support

- [x] TLS support
- [x] Strict protocol validation
- [x] OID validation
- [x] DN parsing support
- [x] Full concurrency ability
- [x] Comprehensive message parsing tests
- [x] Abandon request
- [x] Add request (concurrent)
- [x] Bind request
- [x] Compare request (concurrent)
- [x] Delete request (concurrent)
- [x] Extended requests
- [x] Modify request (concurrent)
- [x] ModifyDN request (concurrent)
- [x] Search request (concurrent)
- [x] StartTLS request
- [x] Unbind request
- [x] Intermediate response
- [x] Unsolicited notifications
- [x] Notice of disconnection

## Goals

- Full conformance to the relevant specifications,
  e.g. RFC 4511.
- Support for all builtin operations and common extended operations
- Comprehensive encoding/decoding tests
- Strict client data validity checking
- Ease of use

Contributions and bug reports are welcome!