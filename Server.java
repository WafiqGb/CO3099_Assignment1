import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class Server {
    // Master private key filename (must be exactly this name per assignment spec)
    private static final String MASTER_PRIVATE_KEY_FILE = "server-b64.prv";
    
    private PrivateKey masterPrivateKey;
    
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java Server <port>");
            System.exit(1);
        }
        
        int port;
        try {
            port = Integer.parseInt(args[0]);
        } catch (NumberFormatException e) {
            System.err.println("Error: Invalid port number");
            System.exit(1);
            return;
        }
        
        try {
            Server server = new Server();
            server.loadMasterPrivateKey();
            server.start(port);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
    
    private void start(int port) throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started on port " + port);
            System.out.println("Waiting for connections...");
            
            // Run continuously, handle one client at a time
            while (true) {
                try (Socket clientSocket = serverSocket.accept()) {
                    System.out.println("\nClient connected: " + clientSocket.getInetAddress());
                    handleClient(clientSocket);
                } catch (Exception e) {
                    // Don't crash on client errors, continue accepting new clients
                    System.err.println("Client error: " + e.getMessage());
                }
            }
        }
    }
    
    private void handleClient(Socket clientSocket) throws Exception {
        DataInputStream in = new DataInputStream(clientSocket.getInputStream());
        DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());
        
        // Read request fields (per protocol spec)
        // 1. userid as UTF string
        String userid = in.readUTF();
        
        // 2. payment id as UTF string
        String paymentId = in.readUTF();
        
        // 3. encrypted AES key length + bytes
        int encKeyLen = in.readInt();
        byte[] encryptedAesKey = new byte[encKeyLen];
        in.readFully(encryptedAesKey);
        
        // 4. signature length + bytes
        int sigLen = in.readInt();
        byte[] signature = new byte[sigLen];
        in.readFully(signature);
        
        System.out.println("Received request from: " + userid);
        System.out.println("Payment ID: " + paymentId);
        
        // Verify signature
        boolean valid = false;
        try {
            valid = verifySignature(userid, encryptedAesKey, signature);
        } catch (Exception e) {
            System.err.println("Signature verification error: " + e.getMessage());
        }
        
        if (valid) {
            System.out.println("Signature VALID for " + userid);
            
            // Decrypt AES key
            byte[] decryptedAesKey = decryptAesKey(encryptedAesKey);
            
            // Send success response
            out.writeBoolean(true);
            out.writeInt(decryptedAesKey.length);
            out.write(decryptedAesKey);
            out.flush();
            
            System.out.println("Decrypted AES key sent to " + userid);
        } else {
            System.out.println("Signature INVALID for " + userid);
            System.out.println("Verification failed. Access denied.");
            
            // Send failure response
            out.writeBoolean(false);
            out.writeUTF("Signature verification failed");
            out.flush();
        }
    }
    
    private void loadMasterPrivateKey() throws Exception {
        String keyB64 = Files.readString(Paths.get(MASTER_PRIVATE_KEY_FILE)).trim();
        byte[] keyBytes = Base64.getDecoder().decode(keyB64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        masterPrivateKey = keyFactory.generatePrivate(keySpec);
        System.out.println("Master private key loaded.");
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
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, masterPrivateKey);
        return rsaCipher.doFinal(encryptedAesKey);
    }
}
