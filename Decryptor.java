import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;

public class Decryptor {
    
    public static void main(String[] args) {
        // Check command line arguments
        if (args.length != 3) {
            System.err.println("Usage: java Decryptor <host> <port> <userid>");
            System.exit(1);
        }
        
        String host = args[0];
        int port;
        try {
            port = Integer.parseInt(args[1]);
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
        String userid = args[2];
        
        // Display welcome message
        System.out.println();
        System.out.println("Dear customer, thank you for purchasing this software.");
        System.out.println("We are here to help you recover your files from this horrible attack.");
        System.out.println("Trying to decrypt files...");
        
        try {
            // Check required files exist
            Path privateKeyFile = Paths.get(userid + ".prv");
            if (!Files.exists(privateKeyFile)) {
                System.err.println("Error: Private key file not found - " + userid + ".prv");
                System.exit(1);
            }
            
            Path aesKeyFile = Paths.get("aes.key");
            if (!Files.exists(aesKeyFile)) {
                System.err.println("Error: Encrypted key file not found - aes.key");
                System.exit(1);
            }
            
            Path encryptedFile = Paths.get("test.txt.cry");
            if (!Files.exists(encryptedFile)) {
                System.err.println("Error: Encrypted file not found - test.txt.cry");
                System.exit(1);
            }
            
            // 1. Load user's private key for signing
            PrivateKey userPrivateKey = loadUserPrivateKey(userid);
            
            // 2. Read encrypted AES key
            byte[] encryptedAesKey = Files.readAllBytes(aesKeyFile);
            
            // 3. Generate signature over (userid + encrypted AES key)
            byte[] signature = generateSignature(userid, encryptedAesKey, userPrivateKey);
            
            // 4. Connect to server and send request
            try (Socket socket = new Socket()) {
                // Set connection timeout
                socket.connect(new InetSocketAddress(host, port), 10000);
                socket.setSoTimeout(30000); // Read timeout
                
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
                
                // Read response
                boolean success = in.readBoolean();
                
                if (success) {
                    // Read decrypted AES key
                    int keyLen = in.readInt();
                    byte[] decryptedAesKey = new byte[keyLen];
                    in.readFully(decryptedAesKey);
                    
                    // Decrypt the file
                    decryptFile(decryptedAesKey);
                    System.out.println("Success! Your files have now been recovered!");
                    System.out.println();
                } else {
                    // Read error message
                    String errorMsg = in.readUTF();
                    System.out.println("Unfortunately we cannot verify your identity.");
                    System.out.println("Please try again, making sure that you have the correct signature");
                    System.out.println("key in place and have entered the correct userid.");
                    System.out.println();
                }
            }
            
        } catch (ConnectException e) {
            System.err.println("Error: Could not connect to server at " + host + ":" + port);
            System.err.println("Make sure the server is running.");
        } catch (SocketTimeoutException e) {
            System.err.println("Error: Connection timed out");
        } catch (UnknownHostException e) {
            System.err.println("Error: Unknown host - " + host);
        } catch (java.nio.file.NoSuchFileException e) {
            System.err.println("Error: File not found - " + e.getFile());
        } catch (BadPaddingException e) {
            System.err.println("Error: Decryption failed - wrong key or corrupted file");
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
