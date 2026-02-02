import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;

public class Decryptor {
    
    public static void main(String[] args) {
        // Phase 3: Signature generation (no networking yet)
        // Phase 4 will add: network connection to server
        
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
            System.out.println("Loaded private key for " + userid);
            
            // 2. Read encrypted AES key
            byte[] encryptedAesKey = Files.readAllBytes(Paths.get("aes.key"));
            System.out.println("Loaded encrypted AES key (" + encryptedAesKey.length + " bytes)");
            
            // 3. Generate signature over (userid + encrypted AES key)
            byte[] signature = generateSignature(userid, encryptedAesKey, userPrivateKey);
            System.out.println("Generated signature (" + signature.length + " bytes)");
            
            // Phase 3 test: Write signature to file for Server to verify
            Files.write(Paths.get("test.sig"), signature);
            Files.writeString(Paths.get("test.userid"), userid);
            System.out.println("Saved signature to test.sig for Server verification test");
            
            // Phase 4 will add:
            // - Connect to server at host:port
            // - Send userid, payment_id, encrypted AES key, signature
            // - Receive decrypted AES key
            // - Decrypt test.txt.cry to test.txt
            
            System.out.println("\nPhase 3 complete. Run Server to verify signature.");
            
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
    
    // Will be used in Phase 4 after receiving decrypted AES key from server
    public static void decryptFile(byte[] aesKeyBytes) throws Exception {
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        
        byte[] iv = new byte[16]; // all zeros
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        
        byte[] ciphertext = Files.readAllBytes(Paths.get("test.txt.cry"));
        byte[] plaintext = cipher.doFinal(ciphertext);
        
        Files.write(Paths.get("test.txt"), plaintext);
        System.out.println("File decrypted successfully! test.txt recovered.");
    }
}
