import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Server {
    private PrivateKey masterPrivateKey;
    private Map<String, byte[]> keyHashes = new HashMap<>();

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java Server <port>");
            System.exit(1);
        }

        int port = Integer.parseInt(args[0]);

        try {
            Server server = new Server();
            server.loadMasterPrivateKey();
            server.start(port);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }

    private void loadMasterPrivateKey() throws Exception {
        String keyB64 = Files.readString(Paths.get("server-b64.prv")).trim();
        byte[] keyBytes = Base64.getDecoder().decode(keyB64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        masterPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    private void start(int port) throws Exception {
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server started on port " + port);

        while (true) {
            Socket clientSocket = null;
            try {
                clientSocket = serverSocket.accept();
                handleClient(clientSocket);
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
            } finally {
                if (clientSocket != null && !clientSocket.isClosed()) {
                    try { clientSocket.close(); } catch (IOException ignored) {}
                }
            }
        }
    }

    private void handleClient(Socket clientSocket) throws Exception {
        DataInputStream in = new DataInputStream(clientSocket.getInputStream());
        DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());

        String userid = in.readUTF();

        int encKeyLen = in.readInt();
        byte[] encryptedAesKey = new byte[encKeyLen];
        in.readFully(encryptedAesKey);

        int sigLen = in.readInt();
        byte[] signature = new byte[sigLen];
        in.readFully(signature);

        System.out.println("User " + userid + " connected.");

        // Verify signature using the user's public key
        boolean verified = false;
        try {
            byte[] pubKeyBytes = Files.readAllBytes(Paths.get(userid + ".pub"));
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
            PublicKey userPublicKey = KeyFactory.getInstance("RSA").generatePublic(pubKeySpec);

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(userPublicKey);
            sig.update(userid.getBytes("UTF-8"));
            sig.update(encryptedAesKey);
            verified = sig.verify(signature);
        } catch (Exception e) {
            verified = false;
        }

        if (verified) {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, masterPrivateKey);
            byte[] decryptedAesKey = rsaCipher.doFinal(encryptedAesKey);

            // Store double SHA-256 hash for later comparison
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(decryptedAesKey);
            hash = digest.digest(hash);
            keyHashes.put(userid, hash);

            out.writeBoolean(true);
            out.writeInt(decryptedAesKey.length);
            out.write(decryptedAesKey);
            out.flush();

            System.out.println("Signature verified. Key decrypted and sent.");
        } else {
            out.writeBoolean(false);
            out.writeUTF("Signature verification failed");
            out.flush();

            System.out.println("Signature not verified.");
        }
    }
}
