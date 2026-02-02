import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;

public class Decryptor {
    
    public static void main(String[] args) {
        if (args.length != 3) {
            System.err.println("Usage: java Decryptor <host> <port> <userid>");
            System.exit(1);
        }
        
        String host = args[0];
        int port;
        try {
            port = Integer.parseInt(args[1]);
        } catch (NumberFormatException e) {
            System.err.println("Error: Invalid port number");
            System.exit(1);
            return;
        }
        String userid = args[2];
        
        try {
            // 1. Load user's private key for signing
            PrivateKey userPrivateKey = loadUserPrivateKey(userid);
            
            // 2. Read encrypted AES key
            byte[] encryptedAesKey = Files.readAllBytes(Paths.get("aes.key"));
            
            // 3. Generate signature over (userid + encrypted AES key)
            byte[] signature = generateSignature(userid, encryptedAesKey, userPrivateKey);
            
            // 4. Connect to server and send request
            System.out.println("Connecting to " + host + ":" + port + "...");
            
            try (Socket socket = new Socket(host, port)) {
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream());
                
                // Send request fields (per protocol spec)
                // 1. userid as UTF string
                out.writeUTF(userid);
                
                // 2. payment id as UTF string (can be empty)
                out.writeUTF("");
                
                // 3. encrypted AES key length + bytes
                out.writeInt(encryptedAesKey.length);
                out.write(encryptedAesKey);
                
                // 4. signature length + bytes
                out.writeInt(signature.length);
                out.write(signature);
                out.flush();
                
                System.out.println("Request sent. Waiting for response...");
                
                // Read response
                boolean success = in.readBoolean();
                
                if (success) {
                    // Read decrypted AES key
                    int keyLen = in.readInt();
                    byte[] decryptedAesKey = new byte[keyLen];
                    in.readFully(decryptedAesKey);
                    
                    System.out.println("Received decrypted AES key from server.");
                    
                    // Decrypt the file
                    decryptFile(decryptedAesKey);
                    System.out.println("File recovery successful!");
                } else {
                    // Read error message
                    String errorMsg = in.readUTF();
                    System.err.println("Server denied request: " + errorMsg);
                    System.err.println("Identity could not be verified.");
                }
            }
            
        } catch (ConnectException e) {
            System.err.println("Error: Could not connect to server at " + host + ":" + port);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
    
    // Load user's private key from <userid>.prv (raw encoded bytes)
    private static PrivateKey loadUserPrivateKey(String userid) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(userid + ".prv"));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
    
    // Generate SHA256withRSA signature over (userid + encrypted AES key)
    private static byte[] generateSignature(String userid, byte[] encryptedAesKey, 
                                            PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        
        // Sign: userid bytes + encrypted AES key bytes
        sig.update(userid.getBytes("UTF-8"));
        sig.update(encryptedAesKey);
        
        return sig.sign();
    }
    
    // Decrypt test.txt.cry to test.txt using AES key
    private static void decryptFile(byte[] aesKeyBytes) throws Exception {
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        
        byte[] iv = new byte[16]; // all zeros
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        
        byte[] ciphertext = Files.readAllBytes(Paths.get("test.txt.cry"));
        byte[] plaintext = cipher.doFinal(ciphertext);
        
        Files.write(Paths.get("test.txt"), plaintext);
    }
}
