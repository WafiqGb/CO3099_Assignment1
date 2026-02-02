import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class Server {
    // Master private key filename (must be exactly this name per assignment spec)
    private static final String MASTER_PRIVATE_KEY_FILE = "server-b64.prv";
    
    private PrivateKey masterPrivateKey;
    
    public static void main(String[] args) {
        // Phase 3: Test signature verification (no networking yet)
        // Phase 4 will add: if (args.length != 1) { ... } and socket handling
        
        try {
            Server server = new Server();
            server.loadMasterPrivateKey();
            System.out.println("Server initialized. Master private key loaded.");
            
            // Phase 3 test: verify signature from test files
            if (Files.exists(Paths.get("test.sig")) && Files.exists(Paths.get("test.userid"))) {
                String userid = Files.readString(Paths.get("test.userid")).trim();
                byte[] signature = Files.readAllBytes(Paths.get("test.sig"));
                byte[] encryptedAesKey = Files.readAllBytes(Paths.get("aes.key"));
                
                System.out.println("\n=== Signature Verification Test ===");
                System.out.println("User: " + userid);
                
                // Verify signature
                boolean valid = server.verifySignature(userid, encryptedAesKey, signature);
                
                if (valid) {
                    System.out.println("Signature VALID for " + userid);
                    
                    // Decrypt AES key and recover file
                    byte[] decryptedAesKey = server.decryptAesKey(encryptedAesKey);
                    System.out.println("AES key decrypted (" + decryptedAesKey.length + " bytes)");
                    
                    // Decrypt file to prove it works
                    decryptFile(decryptedAesKey);
                } else {
                    System.out.println("Signature INVALID for " + userid);
                    System.out.println("Verification failed. Access denied.");
                }
            } else {
                System.out.println("No test signature files found. Run Decryptor first.");
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
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
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, masterPrivateKey);
        return rsaCipher.doFinal(encryptedAesKey);
    }
    
    // Decrypt test.txt.cry to test.txt
    private static void decryptFile(byte[] aesKeyBytes) throws Exception {
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        
        byte[] iv = new byte[16]; // all zeros
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        
        byte[] ciphertext = Files.readAllBytes(Paths.get("test.txt.cry"));
        byte[] plaintext = cipher.doFinal(ciphertext);
        
        Files.write(Paths.get("test.txt"), plaintext);
        System.out.println("File decrypted! test.txt recovered.");
        System.out.println("Content: " + new String(plaintext));
    }
}
