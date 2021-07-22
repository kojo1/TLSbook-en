TLS Client/Server Resume Example
================

## Build && Install wolfSSL
```
$ ./configure --enable-opensslextra --enable-session-ticket
$ make
$ make check
$ sudo make install
```
## Make example using wolfSSL
1. Edit Makefile
```
#SSL = OPENSSL   comment out
SSL = WOLFSSL    enabled
````

2. Make
```
$ make
```

## Run example using wolfSSL

1. Launch Server
```
$ ./Server-resume-tls-WOLFSSL
Waiting for a connection...
````
2. Open another terminal to launch Client

```
$ ./Client-resume-ls-WOLFSSL
use localhost(127.0.0.1) as server ip address
Message for server:
```

Enter message following ":"

"shutdonw" to exit Server

"break" to close session, and write session inforamtion into a file

"shutdown" command terminal message example
```
[Server]
$ ./Server-resume-tls-WOLFSSL 
Waiting for a connection...
Client connected successfully
Client: hello

Client: shutdown

Shutdown command issued!

[Client]
$ ./Client-resume-tls-WOLFSSL 
use localhost(127.0.0.1) as server ip address
Message for server: hello
Server: I hear ya fa shizzle!
Message for server: shutdown
sending server shutdown command: shutdown!

````

"break" command terminal message example
```
[Server]
$ ./Server-resume-tls-WOLFSSL 
Waiting for a connection...
Client connected successfully
Client: hello

Client: break

close this session
Waiting for a connection...

[Client]
$ ./Client-resume-tls-WOLFSSL 
use localhost(127.0.0.1) as server ip address
Message for server: hello
Server: I hear ya fa shizzle!
Message for server: break
```