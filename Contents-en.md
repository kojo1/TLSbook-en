# Part 1 TLS Overview
## Introduction From SSL to TLS (10P)

## 1. Simple TLS program
### 1.1 TCP client, server
### 1.2 Add TLS layer
### 1.3 Overview of TLS Protocol

## Chapter 2 Protocol (15P)
## 2.1 Full hand shake
### 2.1.1 Purpose of full handshake
### 2.1.2 Cipher Suite Agreement
### 2.1.3 HelloRetry
### 2.1.4 Key agreement
### 2.1.5 Key derivation
### 2.1.6 Peer authentication
### 2.1.7 Certificate Status Information: OCSP Stapling
## 2.1.8 Other TLS extensions

## 2.2 Pre-shared key and session restart
### 2.2.1 Pre-shared key (PSK)
### 2.2.2 Early Data
### 2.2.3 Session resume

## 2.3 Message after handshake
## 2.4 Record Protocol
## 2.5 Alert Protocol


## Chapter 3 Cryptography (30P)
## 3.1 Overview
## 3.2 Random numbers
## 3.3 hash
## 3.4 Common key cryptography
## 3.5 Key derivation

## 3.6 Public-key cryptography and key sharing
### 3.6.1 Background
### 3.6.2 RSA practical technology
### 3.6.3 Initial key exchange with RSA
### 3.6.4 Diffie-Hellman Key Exchange
### 3.6.5 Digital signature
### 3.6.6 Standards for public key cryptography

## 3.7 Elliptic curve cryptography
### 3.7.1 Principle
### 3.7.2 ECDH (Elliptic Curve Diffie Hermann)
### 3.7.3 ECDSA (Elliptic Curve Digital Signature)
### 3.7.4 Curve types and standardization

## 3.8 Public Key Certificate
### 3.8.1 Principle
### 3.8.2 Standard

## 3.9 Public Key Infrastructure (PKI)
### 3.9.1 PKCS
### 3.9.2 Public key trust model
### 3.9.3 Certificate life cycle


## Chapter 4 Standard (20P)
#### Standard format
#### PKCS, ASN1, X.509, PEM, DER, etc.

## Chapter 5 Security Issues (15P)
#### Complete forward secrecy
#### Side channel attack
#### Quantum-resistant computing
<br>

#Part 2 Programming using API
#### Explanation based on C language sample source code and WireShark packet capture, focusing on OpenSSL compatible API.
<br>

# Part2. Progressing
## Introduction
## 6.1 Client / Server Communication
### 6.1.1 Functional overview:
### 6.1.2 Program
### 6.1.3 Program description:
See ### 6.1.4

## 6.2 Pre-shared key (PSK)
### 6.2.1 Feature overview:
### 6.2.2 Program
### 6.2.3 Program description:

## 6.3 Session resume
### 6.3.1 Feature overview:
### 6.3.2 Program
### 6.3.3 Program description:

## Chapter 7 Cryptographic Programming (30P)
### 7.1 Random
### 7.2 Hash
### 7.3 MAC
### 7.4 Common key cryptography
### 7.5 Public Key Cryptography / Decryption

### 7.6 Public key signature
#### 7.6.1 RSA signature
#### 7.6.2 ECDSA signature

### 7.7 Key Agreement

## Chapter 8 PKI, Certificate and Key (20P)
#### Certificate and key management
#### Format conversion
#### Key generation and signature
#### Certificate, key management
#### PKCS # 7
#### PKCS # 11
#### PKCS # 12

## Chapter 9 Framework
#### Server task
#### Bare metal, non-block
#### Debug log
####

<br>

## Part 3 How the TLS Library Works
#### Explanation based on wolfSSL source code
## Chapter 10 Overall configuration (5P)
## Chapter 11 Protocol Layer (10P)
#### Protocol state management
#### TLS record layer
## Chapter 12 Cryptographic Algorithm Layer (15P)
#### Basic algorithm
#### Large integer arithmetic
#### Hardware architecture and optimization
## Chapter 13 Porting (25P)
#### Platform Dependencies
#### exclusion control
#### File system
#### Heap management
#### Random numbers
#### clock
#### C standard function
#### others

<br>

## Appendix 1 (20 pages)
#### Explains the order of reproduction by the reader, such as the programming environment used in Part 2.
#### Programming environment
#### Sample program repository
#### Library, application build
#### tool
## Appendix 2 (15 pages)
#### APIs covered in this document 
More about this source textSource text required for additional translation information
Send feedback
Side panels