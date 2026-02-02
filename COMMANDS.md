# CO3099 Assignment 1 - Command Reference

Quick reference for all commands used in this project.

---

## Compilation

Compile all three Java files:

```bash
javac WannaCry.java Decryptor.java Server.java
```

Compile individually:

```bash
javac WannaCry.java
javac Decryptor.java
javac Server.java
```

---

## Program Invocations

### 1. WannaCry (Ransomware Prototype)

```bash
java WannaCry
```

**What it does:**
- Reads `test.txt`
- Encrypts it to `test.txt.cry`
- Creates `aes.key` (RSA-encrypted AES key)
- Deletes original `test.txt`
- Prints ransom message

**Required files in working directory:**
- `test.txt` (plaintext to encrypt)

**Files created:**
- `test.txt.cry` (encrypted file)
- `aes.key` (encrypted AES key)

---

### 2. Server

```bash
java Server <port>
```

**Example:**

```bash
java Server 5000
```

**What it does:**
- Listens on specified port
- Receives client requests (userid, payment_id, encrypted AES key, signature)
- Verifies signature using `<userid>.pub`
- If valid, decrypts AES key and sends it back
- Runs continuously until manually stopped

**Required files in working directory:**
- `<userid>.pub` (public key for each user who connects)
- Master private key file (for decrypting AES key)

---

### 3. Decryptor (Client)

```bash
java Decryptor <host> <port> <userid>
```

**Example:**

```bash
java Decryptor localhost 5000 alice
```

**What it does:**
- Loads `<userid>.prv` to sign request
- Reads `aes.key` (encrypted AES key)
- Generates signature over userid + encrypted AES key
- Connects to server and sends request
- If verified, receives decrypted AES key
- Decrypts `test.txt.cry` back to `test.txt`

**Required files in working directory:**
- `<userid>.prv` (user's private key for signing)
- `aes.key` (encrypted AES key from WannaCry)
- `test.txt.cry` (encrypted file to decrypt)

**Files created:**
- `test.txt` (recovered plaintext)

---

## Full End-to-End Workflow

Run these in order (use two terminals for server):

**Terminal 1 - Start server:**

```bash
java Server 5000
```

**Terminal 2 - Run ransomware and recovery:**

```bash
# Create test file
echo "Secret message to encrypt" > test.txt

# Run ransomware (encrypts file)
java WannaCry

# Run client to recover (server must be running)
java Decryptor localhost 5000 alice

# Verify recovery
cat test.txt
```

---

## Testing Scenarios

### Test successful decryption:

```bash
java Decryptor localhost 5000 alice
```

### Test failed verification (wrong user):

```bash
java Decryptor localhost 5000 bob
```

(Should fail gracefully, server continues running)

### Test missing file handling:

```bash
rm test.txt
java WannaCry
```

(Should print error message, not crash)

---

## File Summary

| File | Created By | Used By | Description |
|------|------------|---------|-------------|
| `test.txt` | User | WannaCry | Original plaintext file |
| `test.txt.cry` | WannaCry | Decryptor | Encrypted file |
| `aes.key` | WannaCry | Decryptor, Server | RSA-encrypted AES key |
| `<userid>.pub` | Key generator | Server | User's public key |
| `<userid>.prv` | Key generator | Decryptor | User's private key |
| Master private key | Provided | Server | Decrypts AES key |

---

## Cryptography Parameters

| Component | Parameter | Value |
|-----------|-----------|-------|
| AES | Key size | 256-bit |
| AES | Mode | CBC |
| AES | Padding | PKCS5Padding |
| AES | IV | 16 zero bytes |
| RSA | Signature algorithm | SHA256withRSA |
| RSA | Key format | Raw encoded bytes |

---

## Quick Cleanup

Remove generated files:

```bash
rm -f test.txt test.txt.cry aes.key *.class
```
