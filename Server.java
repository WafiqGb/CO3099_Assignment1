import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Server {
    // Master private key filename (must be exactly this name per assignment spec)
    private static final String MASTER_PRIVATE_KEY_FILE = "server-b64.prv";
    
    private PrivateKey masterPrivateKey;
    
    // LLM-specific requirement: Store double SHA-256 hashes of decrypted AES keys
    private Map<String, byte[]> decryptedKeyHashes = new HashMap<>();
    
    public static void main(String[] args) {
        // Check command line arguments
        if (args.length != 1) {
            System.err.println("Usage: java Server <port>");
            System.exit(1);
        }
        
        int port;
        try {
            port = Integer.parseInt(args[0]);
            if (port < 1 || port > 65535) {
                System.err.println("Error: Port must be between 1 and 65535");
                System.exit(1);
                return;
            }
        } catch (NumberFormatException e) {
            System.err.println("Error: Invalid port number");
            System.exit(1);
            return;
        }
        
        // Check master private key file exists
        if (!Files.exists(Paths.get(MASTER_PRIVATE_KEY_FILE))) {
            System.err.println("Error: Master private key file not found - " + MASTER_PRIVATE_KEY_FILE);
            System.exit(1);
        }
        
        try {
            Server server = new Server();
            server.loadMasterPrivateKey();
            server.start(port);
        } catch (BindException e) {
            System.err.println("Error: Port " + port + " is already in use");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
    
    private void start(int port) throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started on port " + port);
            
            // Run continuously, handle one client at a time
            while (true) {
                Socket clientSocket = null;
                try {
                    clientSocket = serverSocket.accept();
                    handleClient(clientSocket);
                } catch (Exception e) {
                    // Don't crash on client errors, continue accepting new clients
                    System.err.println("Client error: " + e.getMessage());
                } finally {
                    // Always close the client socket
                    if (clientSocket != null && !clientSocket.isClosed()) {
                        try {
                            clientSocket.close();
                        } catch (IOException e) {
                            // Ignore close errors
                        }
                    }
                }
            }
        }
    }
    
    private void handleClient(Socket clientSocket) {
        DataInputStream in = null;
        DataOutputStream out = null;
        String userid = "unknown";
        
        try {
            clientSocket.setSoTimeout(30000); // 30 second timeout
            in = new DataInputStream(clientSocket.getInputStream());
            out = new DataOutputStream(clientSocket.getOutputStream());
            
            // Read request fields (per protocol spec)
            // 1. userid as UTF string
            userid = in.readUTF();
            
            // 2. payment id as UTF string
            String paymentId = in.readUTF();
            
            // 3. encrypted AES key length + bytes
            int encKeyLen = in.readInt();
            if (encKeyLen <= 0 || encKeyLen > 1024) {
                throw new IOException("Invalid encrypted key length: " + encKeyLen);
            }
            byte[] encryptedAesKey = new byte[encKeyLen];
            in.readFully(encryptedAesKey);
            
            // 4. signature length + bytes
            int sigLen = in.readInt();
            if (sigLen <= 0 || sigLen > 1024) {
                throw new IOException("Invalid signature length: " + sigLen);
            }
            byte[] signature = new byte[sigLen];
            in.readFully(signature);
            
            System.out.println("User " + userid + " connected.");
            
            // Verify signature
            boolean valid = false;
            
            try {
                valid = verifySignature(userid, encryptedAesKey, signature);
            } catch (java.nio.file.NoSuchFileException e) {
                // Public key file not found for this user
            } catch (Exception e) {
                // Signature verification failed
            }
            
            if (valid) {
                System.out.println("Signature verified. Key decrypted and sent.");
                
                // Decrypt AES key
                byte[] decryptedAesKey = decryptAesKey(encryptedAesKey);
                
                // LLM-specific: Compute and store double SHA-256 hash (not displayed)
                try {
                    byte[] doubleHash = computeDoubleHash(decryptedAesKey);
                    decryptedKeyHashes.put(userid, doubleHash);
                } catch (Exception e) {
                    // Hash computation error - continue anyway
                }
                
                // Send success response
                out.writeBoolean(true);
                out.writeInt(decryptedAesKey.length);
                out.write(decryptedAesKey);
                out.flush();
            } else {
                // Include userid in failure message as required by spec
                System.out.println("User " + userid + ": Signature not verified.");
                
                // Send failure response
                out.writeBoolean(false);
                out.writeUTF("Signature verification failed");
                out.flush();
            }
            
        } catch (SocketTimeoutException e) {
            System.err.println("Client timed out");
        } catch (EOFException e) {
            System.err.println("Client disconnected unexpectedly");
        } catch (IOException e) {
            System.err.println("IO error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error handling client: " + e.getMessage());
        }
    }
    
    private void loadMasterPrivateKey() throws Exception {
        String keyB64 = Files.readString(Paths.get(MASTER_PRIVATE_KEY_FILE)).trim();
        byte[] keyBytes = Base64.getDecoder().decode(keyB64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        masterPrivateKey = keyFactory.generatePrivate(keySpec);
    }
    
    // Load user's public key from <userid>.pub (raw encoded bytes)
    private PublicKey loadUserPublicKey(String userid) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(userid + ".pub"));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
    
    // Verify SHA256withRSA signature over (userid + encrypted AES key)
    private boolean verifySignature(String userid, byte[] encryptedAesKey, 
                                    byte[] signature) throws Exception {
        PublicKey userPublicKey = loadUserPublicKey(userid);
        
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(userPublicKey);
        
        // Verify: userid bytes + encrypted AES key bytes (same order as signing)
        sig.update(userid.getBytes("UTF-8"));
        sig.update(encryptedAesKey);
        
        return sig.verify(signature);
    }
    
    private byte[] decryptAesKey(byte[] encryptedAesKey) throws Exception {
        // Use explicit padding for cross-platform consistency
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, masterPrivateKey);
        return rsaCipher.doFinal(encryptedAesKey);
    }
    
    // LLM-specific requirement: Compute two rounds of SHA-256 hash
    private byte[] computeDoubleHash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] firstHash = digest.digest(data);
        byte[] secondHash = digest.digest(firstHash);
        return secondHash;
    }
}
