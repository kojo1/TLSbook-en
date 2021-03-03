## Introduction
In the first part, we will look at the technology on which TLS programming is based. Chapter 2 describes the TLS protocol, Chapter 3 describes the cryptographic algorithms and technologies used in it, and Chapter 4 describes the various related standards. In addition, Chapter 5 summarizes security considerations in TLS programming.

## 2.1 Simple client-server communication
Figure 2-1 outlines the client and server programs that communicate for the first time with TLS and the network protocol (full handshake) between them. TLS as a protocol is implemented on top of TCP. All TLS records will be transferred on top of the TCP records between TCP-connected clients and servers.

To achieve this, first establish a TCP connection between the client and server. For example, in a program using a BSD socket, it is realized by entering the connection request wait (accept) from the client on the server side and requesting the connection (connect) from the client to the target server.

All subsequent TLS messages will be carried on the TCP record from this connection.

The server-side program then calls SSL_accept to wait for a TLS layer connection request, and the client-side program calls SSL_connect for a connection request. This call performs a series of TLS handshakes to establish a TLS connection.

## 2.2 Full hand shake
### 2.2.1 Purpose of full handshake
When a client makes TLS communication with the server for the first time as in 2.1, the server must establish a secure TLS session with the other client without prior information. Full hand shake does this.

The main purposes of full hand shake are the following three.

1) Agree on the cipher suite to be used for both communications <br>
2) Agreeing a series of keys to be used in the session (key agreement) <br>
3) Confirm that the communication partner is the correct partner and that there is no spoofing (peer authentication) <br>

Peer authentication consists of server authentication in which the client authenticates the validity of the server and client authentication in which the server authenticates the validity of the client. For TLS, server authentication is mandatory and client authentication is optional.

Once the TLS connection is established, send and receive the desired application data. This is done programmatically via the SSL_send / SSL_recv API. The plaintext message that the application wants to send is encrypted by SSL_send, decrypted by SSL_recv and passed in cleartext to the other application. At this time, it also checks that the received message has not been tampered with from the sender message and that it is authentic.

### 2.2.2 Key agreement with cipher suite
Cipher suite and key agreement, which is the main purpose of the handshake, is made by the ClientHello record first sent from the client to the server and the response ServerHello from the server. Figure 2-2 shows this situation.
<br>
Each TLS extension in the ClientHello record stores information such as:

1) List of supported TLS versions <br>
2) List of supported cipher suites <br>
3) Curve list of supported elliptic curve cryptography <br>


The Key Share extension also stores DH parameters for Diffie Hermann (including elliptic curve DH) key agreements and the client-side DH public key. Key Shere can contain multiple candidates.

On the other hand, if there is something that can be agreed on in the presented list, the server side will return the agreed contents of each item in Server Hello. At this time, the DH public key on the server side is also stored in the Key Share of ServerHello. Both who receive them calculate the premaster secret by the DH algorithm. Based on this value, the key and IV for subsequent encryption and decryption by common key cryptography are derived by the HKDF key derivation algorithm. In TLS1.3, different values ​​are derived depending on the key, IV is the source (server side, client side), handshake, application data transfer, 0-RTT, etc., and the session key is used to further enhance security.

If the server cannot agree on the list of KeyShares presented by the client, you can request another candidate only once from the client (Hello Retry Request). On the other hand, the client side shows the next candidate in the second Client Hello. If the server side agrees on this, the handshake will proceed. If you do not agree, the handshake will be interrupted.

In TLS1.3, the session key can be derived by exchanging one round trip between ClientHello and ServerHello records, but in TLS1.2 or earlier, the server key and client key for agreement are the next ServerKeyExchange and ClientKeyExchange. It took two round trips to complete the agreement to be exchanged. In addition, since the session key can be derived at the beginning of the handshake in TLS1.3, it is possible to conceal the handshake after that and improve the security.

#### 1) TLS version agreement
Client Hello allows you to suggest multiple versions to support so that you can mix multiple TLS versions of the protocol on your network. On the other hand, the server side returns Server Hello in the format corresponding to the agreed version. This allows subsequent handshakes to proceed in the form of the agreed version. With TLS1.3, Secure Renegotiation has been deprecated, so if you agree on TLS1.3 here, then everything must be 1.3 compliant.

Also, downgrades are not allowed with TLS 1.3, so even if the client presents multiple versions, including 1.3, the server must agree on 1.3 if it supports TLS 1.3 and Server Hello with TLS 1.3. Must be returned. At this time, if the TLS1.3 suite is not in the cipher suite list shown in ClientHello, it is considered as a kind of downgrade and the handshake ends. In addition, clients who expect to agree on TLS 1.3 will ensure that this value is not the specified value to prevent downgrade attacks. <br>

On the other hand, when the server supports multiple versions including TLS1.3, if the client side supports only TLS1.2 or less, it is allowed to operate equivalent to the case where the server side also supports only TLS1.2 or less. Has been done. However, in that case, a specific byte string indicating that is displayed at the end of the server random. <br>

Table 2-1 summarizes the combinations of TLS versions supported by the client and server and the required behavior.

| Client <br> TLS1.2 or less | <br> TLS1.3 | Server <br> TLS1.2 or less | <br> TLS1.3 | Operation |
| --- | --- | --- | --- | --- |
| | ✓ | | ✓ | TLS 1.3 session |
| | ✓ | ✓ | ✓ | TLS 1.3 session |
| | ✓ | ✓ | | Handshake Error |
| ✓ | ✓ | | ✓ | TLS 1.3 session |
| ✓ | ✓ | ✓ | ✓ | TLS 1.3 session |
| ✓ | ✓ | ✓ | | TLS 1.2 or lower session |
| ✓ | | | ✓ | Handshake Error |
| ✓ | | ✓ | ✓ | TLS 1.2 or lower session <br> Note |
| ✓ | | ✓ | | TLS 1.2 or lower session |

                Table 2-1 TLS version agreement

Note: In the last 8 bytes of server random <br>
    For TLS 1.2 Hexadecimal "44 4F 57 4E 47 52 44 01" <br>
    For TLS 1.1 or less Hexadecimal "44 4F 57 4E 47 52 44 00" <br> <br>

#### 2) Cipher suite
Compared to previous versions, TLS 1.3 has significantly reduced the types of cipher suites that can be used as follows.

1) As a key agreement algorithm, static RSA has been abolished and only temporary key DH (including elliptic curve DH) is available. <br>
2) With the abolition of static RSA, certificates are now used only for peer authentication. This allows key agreement and authentication to be completely separated and treated independently. <br>
3) The compromised common key cryptographic algorithms have been significantly organized. <br>
4) Authenticity verification by MAC has been abolished, and only the Authenticated Encryption with Associated Data (AEAD) algorithm has been organized. <br>
5) Hash specifies only the hash algorithm for HKDF key derivation <br>

Due to the arrangement of 1), the notation of the key agreement algorithm has become meaningless in the cipher suite notation, and it has been deleted from the notation for TLS 1.3. Also, according to 2), the information about the certificate is also separated from the cipher suite, and the necessary information is stored in the TLS extension.

As a result, the hundreds of cipher suites up to TLS1.2 have been narrowed down to the following as currently available as TLS1.3.
<br>

| Name | ID |
|:---:|:---:|
| TLS_AES_128_GCM_SHA256 | 0x1301 |
| TLS_AES_256_GCM_SHA384 | 0x1302 |
| TLS_CHACHA20_POLY1305_SHA256 | 0x1303 |
| TLS_AES_128_CCM_SHA256 | 0x1304 |
| TLS_AES_128_CCM_8_SHA256 | 0x1305 |

        Table 2-2 TLS 1.3 cipher suites
<br>
Information about key agreements is separated from the cipher suite, and the types of elliptic curves that can be used for ECDH are listed separately in the TLS Extended (Supported Group). A standard elliptic curve type ID is defined as the group type, and an ID indicating the key length is defined for DH.

Table 2-3 lists the main groups and IDs used by Supported Groups.


#### 3) Cipher suite agreement
For the round trip between ClientHell and ServerHell, we agree on the type of elliptic curve indicated by the Supported Group together with these cipher suites. At this time, if you have agreed on TLS 1.3 as the TLS version, you must agree on the TLS 1.3 cipher suite and the DH parameters shown in Key Share.

If there is nothing that the client can agree on, the server can issue another Client Hello request (HelloRetryRequest) only once.

### 2.2.3 Key agreement
After agreeing on the TLS version and cipher suite, the server receives the DH parameters shown in Key Share and the client's DH public key. In response, ServerHello returns the server's DH public key. As a result, the session key is derived by Pre-Master Secret and HKDF for each.

### 2.2.4 Peer authentication
Another major purpose of the handshake is peer authentication (server authentication by client, client authentication by server). Server authentication is mandatory for TLS and client authentication is optional. However, whenever the server side requests client authentication, the client side must respond to it.

Figure 2-3 shows the relationship between the client, the server program, and the certificates, keys, and protocols used for server authentication. On the TLS program, the client side loads the trusted CA certificate in advance for server authentication. On the server side, load the server certificate and private key signed by the CA.

In the handshake, the server side sends the loaded server certificate to the client in a Certificate record. In addition, the signature created with the private key will be sent in the Verify Certificate record. On the receiving client side, after verifying the authenticity of the certificate sent by the loaded CA certificate, the signature is verified by the stored public key.

Client authentication does much the same thing with the client and server symmetrical. However, client authentication is optional, so the server side sends a Certificate Request to the client as needed.

Regarding the peer authentication protocol, up to TLS1.2, the signature sent from the server side was stored in ServerKeyExchange, and there were some parts that were not symmetrical in the protocol, but in TLS1.3, the authentication side and non-authentication side as described above. Arranged to be symmetrical on the side.

Algorithmic information about peer authentication is stored in each TLS extension.

The list of supported certificate signing algorithms is stored in the Signature Algorithms. The signature algorithm is defined by a combination of signature and hash algorithms. In TLS1.3, RSA and ECDSA are defined as standard as the signature part. For RSA, it also defines the padding method. For ECDSA, the type of elliptic curve is also specified here. SHA1 or SHA2 is used as the hash.

Table 2-4 lists the signature algorithms that can be used with TLS 1.3.
