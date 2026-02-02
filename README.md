# CO3099_Assignment1
CyberSec 

CO3099 Assignment 1 PRD

Purpose
This project produces a small, controlled, educational prototype that demonstrates core secure programming concepts from the module, specifically symmetric encryption, public key encryption, digital signatures, and simple network communication in Java. The deliverable is three Java programs that work together end to end on the departmental Linux platform and follow the exact input output and file naming rules required for automated and manual marking.

Success criteria
The project is successful if all three programs compile and run on departmental Linux, follow the required command line interfaces exactly, read and write only the specified files in the current working directory, and complete the full flow: encrypt a file, store an encrypted key, verify identity via signatures, and recover the original file via a server mediated key release.

Deliverables
You must submit only these three files, with these exact names and exact casing.
1. WannaCry.java
2. Decryptor.java
3. Server.java

No additional source files are submitted. Any helper classes must be inside these files if you choose to structure it that way.

Operating assumptions
All required files already exist when each program runs, and only the required files exist. All file reads and writes must happen in the same folder you run the program from. You must not hardcode absolute paths and you must not read or write outside the working directory.

The marking process is sensitive to filename casing on Linux. alice.prv is not the 
same as Alice.prv.

Programs must not prompt the user for input. The only inputs are command line arguments.

Files and artifacts
This project uses these file types in the working directory.
1. test.txt is the plaintext input file to be encrypted by the ransomware component.
2. test.txt.cry is the encrypted output file produced by the ransomware component.
3. aes.key is the encrypted AES key file produced by the ransomware component.
4. <userid>.pub is a user public key file, raw encoded bytes written by the provided key generator.
5. <userid>.prv is a user private key file, raw encoded bytes written by the provided key generator.
6. A server master private key file exists separately for the server, provided in Base64 form and referenced by the spec.

Component overview
The system has three programs.
1. Ransomware prototype: WannaCry.java
2. Decryption client: Decryptor.java
3. Server: Server.java

The first program encrypts test.txt and creates test.txt.cry plus aes.key. The second program proves identity using a signature, sends a request to the server, and if verified, decrypts test.txt.cry back into test.txt. The server verifies signatures and releases the decrypted AES key only after verification.

Detailed functional requirements
1. Ransomware prototype, WannaCry.java

Invocation: java WannaCry

Required behavior.

The program generates a fresh random 256 bit AES key.

The program encrypts exactly one file named test.txt using AES in CBC mode with PKCS5Padding. The IV must be 16 empty bytes, meaning all bits are zero. The encrypted content is written to test.txt.cry. The original test.txt is deleted after writing test.txt.cry.

The AES key bytes, specifically the bytes returned by the Java key getEncoded() method, are encrypted using the provided master RSA public key. The result is stored 
in a file named aes.key.

The master RSA public key is provided as a Base64 string representing the encoded public key bytes from Java. Your program must reconstruct a Java PublicKey from that Base64 string. The Base64 string must be embedded directly in your source code.

After completing the encryption steps, the program prints a simple payment demand style message and then exits.

Non goals for this component.

It does not encrypt multiple files. It does not attempt persistence, stealth, privilege escalation, or anything outside the explicit educational spec.

2. Decryption client, Decryptor.java

Invocation: java Decryptor host port userid

Inputs.

1. host is the server hostname.
2. port is the server port number.
3. userid is the client identity string such as alice or bob.

Required behavior.

The client must prove identity by generating a digital signature. The signature is computed using algorithm SHA256withRSA.

The signature content must incorporate the userid and the encrypted AES key value. The encrypted AES key value refers to the data in aes.key, as created by the ransomware component. The intent is that a captured request cannot be trivially replayed under a different identity.

The client uses the appropriate key that identifies the user. Practically, this means the client must use the user private key file <userid>.prv to sign, and it must not require keys that it should not own.

The client connects to the server using the supplied host and port, then sends to the server the userid, the encrypted AES key, and the signature.

If the server verifies the signature, the client receives the decrypted AES key from the server. The client then uses that decrypted AES key to decrypt test.txt.cry back into test.txt using the same cipher settings required by the encryption step, 
including the IV choice.

The client prints a success style message when recovery completes.

If verification fails, the client prints a failure style message indicating identity could not be verified and exits without crashing.

3. Server, Server.java

Invocation: java Server port

Required behavior.

The server runs continuously once started and listens for incoming connections on the given port. It handles one client at a time, then returns to listening. It does not terminate after a single request.

Upon connection, the server receives the fields from the client. The spec includes userid and encrypted AES key and signature, and it also mentions a payment id value. Your design must match what the assignment expects, so the network protocol must include whatever fields the marking tests send. The safest approach is to implement receiving userid, a payment id string, the encrypted AES key bytes, and the signature bytes, in that order, and to tolerate a simple payment id such as an empty string if needed.

The server verifies the signature using the correct public key for the given userid, meaning it should load <userid>.pub and use that to verify a SHA256withRSA signature over the same content definition used by the client.

If signature verification fails, the server prints a simple message on the server console that includes the userid and indicates verification failed. The server then disconnects that client and continues running, ready for the next client.

If signature verification succeeds, the server decrypts the encrypted AES key that it received. The server can do this because it holds the master RSA private key that matches the master public key used by the ransomware component.

The master RSA private key is provided as Base64 encoded encoded bytes in a specific file, and the spec says the server should read it from that file and that the filename must match exactly. The server must reconstruct a Java PrivateKey from that Base64 data.

After decrypting the AES key, the server sends the decrypted AES key back to the client. The server prints a simple success message on its console, disconnects the client, and returns to listening.

Cryptography requirements summary

AES requirements.

1. Key size is 256 bit.
2. Mode is CBC.
3. Padding is PKCS5Padding.
4. IV is 16 zero bytes.
5. Encryption transforms test.txt into test.txt.cry.
6. Decryption transforms test.txt.cry back into test.txt.

RSA requirements.

1. User RSA keys are generated externally by the provided key generator and stored as raw encoded bytes in <userid>.pub and <userid>.prv.
2. The master RSA public key is embedded in the ransomware source as Base64 and used to encrypt the AES key bytes.
3. The master RSA private key is held by the server as Base64 and used to decrypt the 
AES key.

Signature requirements.

1. Algorithm is SHA256withRSA.
2. Client signs using <userid>.prv.
3. Server verifies using <userid>.pub.
4. Signed content includes userid and the encrypted AES key data.

Network protocol requirements

The protocol must be simple, deterministic, and tolerant to marking scripts. The design must not require interactive prompts or manual inputs.

A robust minimum protocol is a single request and single response.

Request fields.

1. userid as a UTF string
2. payment id as a UTF string
3. encrypted AES key length as an int, then encrypted AES key bytes
4. signature length as an int, then signature bytes

Response fields.

1. success flag as a boolean
2. if success is true, AES key length as an int then AES key bytes
3. if success is false, an optional message string

This structure keeps parsing unambiguous and avoids delimiter problems.

Error handling requirements

Every program must fail gracefully, meaning it prints a clear message and exits cleanly rather than throwing an uncaught exception.

Cases to handle.
1. Missing required file in working directory.
2. Invalid command line argument count.
3. Invalid port number.
4. Connection refused or server unreachable.
5. Signature verification failure.
6. Decryption failure due to wrong key or wrong input file.

The server must never crash just because a single client request is malformed or fails verification. It must continue to accept new clients.

Constraints that affect marks

The departmental Linux platform is the execution environment. Your programs must run there.

Do not hardcode local machine paths, usernames, or folders.

Do not hardcode host and port. The client must use the command line host and port.

Keep file naming exact and case correct.

Follow the specified command line argument ordering exactly.

A critical marking point is correct key ownership. Each program must only require the keys it should logically have. If a program crashes because it tries to load a key it should not need, you can lose most or all execution marks.

Marking alignment checklist
Execution testing is 25 marks and is banded. You maximize this score by ensuring the full flow works reliably with both success and failure cases, and by ensuring the 
programs behave correctly when wrong keys are provided.

Code inspection is 70 marks with approximate distribution.
1. RSA key decoding and RSA encryption or decryption: 20
2. AES key generation and AES encryption or decryption: 20
3. Signature generation and signature verification: 20
4. Other aspects including client server interaction: 10

Readability is 5 marks and is mostly about indentation and naming. Comments should be useful and not translate code into English line by line.

Out of scope
This project is not a real ransomware implementation. It must never be extended beyond the assignment requirements. It does not attempt to evade detection, spread, persist, or handle multiple targets.

Acceptance tests

You should treat these as your done definition for the coursework.

1. javac WannaCry.java Decryptor.java Server.java succeeds on Linux.
2. Running java WannaCry creates test.txt.cry, creates aes.key, and removes test.txt.
3. Running java Server <port> keeps the server running and listening.
4. Running java Decryptor <host> <port> <userid> with matching keys recovers test.txt and prints a success message.
5. Running the client with a mismatched userid and key results in a verification failure message without crashing, and the server remains running afterward.
6. No program reads or writes outside the working directory.
7. No program asks for interactive input.

Build and run workflow

A typical manual workflow in the working directory is.
1. Compile all: javac WannaCry.java Decryptor.java Server.java
2. Start server in one terminal: java Server 5000
3. Run ransomware: java WannaCry
4. Run client: java Decryptor localhost 5000 alice

You can repeat the client step with wrong combinations to confirm verification failures are handled cleanly.

Implementation plan

Start with correctness over structure.

Phase 1: File based AES encryption and decryption round trip locally without RSA and without networking.

Phase 2: RSA master key reconstruction from Base64 for public key in the ransomware and private key in the server, then encrypt and decrypt the AES key bytes, still without networking.

Phase 3: User key loading for <userid>.prv and <userid>.pub, then signature generation and verification on the same machine, still without networking.

Phase 4: Add network transport for the request and response and validate end to end.

Phase 5: Harden error handling, ensure Linux compatibility, check filenames and argument handling, and confirm server robustness after failures.
