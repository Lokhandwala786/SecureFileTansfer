

A Java-based client-server application that enables secure file transfers with end-to-end encryption and authentication using RSA and AES cryptography.

## 📋 Overview

This system implements a secure protocol for transferring files between clients and a server. It uses RSA public/private key cryptography for authentication and initial key exchange, followed by AES symmetric encryption for efficient and secure file transfers. The implementation follows secure cryptographic practices to ensure confidentiality, integrity, and authentication.

## 🔐 Security Features

- **Authentication**: RSA-based mutual authentication between client and server
- **Key Agreement**: Secure exchange of session keys
- **Encryption**: AES/CBC/PKCS5Padding for all file transfers
- **Digital Signatures**: SHA1withRSA signatures to verify identity
- **Secure File Listing**: Server filters out sensitive private key files
- **Session Management**: Unique encryption keys for each session


## 🛠️ Requirements

- Java Development Kit (JDK) 8 or higher
- RSA key pairs for each user and the server


## 🔧 Setup

1. **Generate RSA Keys**:
Use the provided `RSAKeyGen.java` program to generate key pairs for each user and the server.

```plaintext
java RSAKeyGen <userid>
```

This will create `<userid>.pub` and `<userid>.prv` files.


2. **Key Distribution**:

1. Place the server's public key (`server.pub`) and the client's private key (`<userid>.prv`) in the client's directory.
2. Place all clients' public keys (`<userid>.pub`) and the server's private key (`server.prv`) in the server's directory.



3. **Compile the Programs**:

```plaintext
javac Server.java
javac Client.java
```




## 🚀 Usage

1. **Start the Server**:

```plaintext
java Server <port>
```

Example: `java Server 8888`


2. **Start the Client**:

```plaintext
java Client <host> <port> <userid>
```

Example: `java Client localhost 8888 alice`


3. **Client Commands**:

1. `ls`: List all available files on the server (excluding private key files)
2. `get <filename>`: Download a file from the server
3. `bye`: Terminate the connection





## 🔍 Implementation Details

### Authentication and Key Agreement Protocol

1. Client connects to server and sends encrypted userid and 16 random bytes
2. Server verifies client's identity using signature verification
3. Server sends back 32 encrypted bytes (client's 16 bytes + server's 16 bytes)
4. Client verifies server's identity and confirms its original 16 bytes
5. Both sides independently generate a 256-bit AES key from the 32 bytes


### File Transmission Protocol

- All subsequent messages are encrypted with AES/CBC/PKCS5Padding
- CBC initialization vector (IV) is derived from the 32 bytes using MD5
- Each subsequent message uses the MD5 hash of the previous IV as the new IV


## ⚠️ Security Considerations

- Key files must be protected and distributed securely
- The system assumes a trusted environment for key storage
- Private key files (.prv) are never transmitted or listed
- The system implements proper error handling for cryptographic failures


## 🔎 Troubleshooting

- **Connection Issues**: Ensure the server is running and the port is accessible
- **Authentication Failures**: Verify that the correct key files are in place
- **Encryption Errors**: Check that the key files are not corrupted
