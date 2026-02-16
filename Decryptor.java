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
        int port = Integer.parseInt(args[1]);
        String userid = args[2];

        System.out.println("Dear customer, thank you for purchasing this software.");
        System.out.println("We are here to help you recover your files from this horrible attack.");
        System.out.println("Trying to decrypt files...");

        try {
            byte[] encryptedAesKey = Files.readAllBytes(Paths.get("aes.key"));

            // Sign (userid + encrypted AES key) with user's private key
            byte[] privKeyBytes = Files.readAllBytes(Paths.get(userid + ".prv"));
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
            PrivateKey userPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(privKeySpec);

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(userPrivateKey);
            sig.update(userid.getBytes("UTF-8"));
            sig.update(encryptedAesKey);
            byte[] signature = sig.sign();

            // Connect to server and exchange data
            Socket socket = new Socket(host, port);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            out.writeUTF(userid);
            out.writeInt(encryptedAesKey.length);
            out.write(encryptedAesKey);
            out.writeInt(signature.length);
            out.write(signature);
            out.flush();

            boolean success = in.readBoolean();

            if (success) {
                int keyLen = in.readInt();
                byte[] decryptedAesKey = new byte[keyLen];
                in.readFully(decryptedAesKey);

                SecretKey aesKey = new SecretKeySpec(decryptedAesKey, "AES");
                byte[] iv = new byte[16];
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

                byte[] ciphertext = Files.readAllBytes(Paths.get("test.txt.cry"));
                byte[] plaintext = cipher.doFinal(ciphertext);
                Files.write(Paths.get("test.txt"), plaintext);

                System.out.println("Success! Your files have now been recovered!");
            } else {
                System.out.println("Unfortunately we cannot verify your identity.");
                System.out.println("Please try again, making sure that you have the correct signature");
                System.out.println("key in place and have entered the correct userid.");
            }

            socket.close();

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
}
