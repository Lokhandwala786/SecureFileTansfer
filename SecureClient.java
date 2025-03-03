import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class SecureClient {
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
    private static final String SIGNATURE_MODE = "SHA1withRSA";
    private static final String AES_MODE = "AES/CBC/PKCS5Padding";

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Usage: java SecureClient <host> <port> <userid>");
            return;
        }
        String hostAddress = args[0];
        int portNumber = Integer.parseInt(args[1]);
        String userId = args[2];

        // Load client's private key and server's public key
        PrivateKey clientPrivateKey = loadPrivateKey(userId + ".prv");
        PublicKey serverPublicKey = loadPublicKey("server.pub");

        try (Socket socket = new Socket(hostAddress, portNumber);
             ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
             Scanner scanner = new Scanner(System.in)) {

            System.out.println("Connected to server at " + hostAddress + ":" + portNumber);

            // Sending encrypted user ID and random bytes to server
            byte[] randomBytes = generateRandomBytes(16);
            String clientData = userId + " " + Base64.getEncoder().encodeToString(randomBytes);

            Cipher rsaCipher = Cipher.getInstance(RSA_MODE);
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedClientData = rsaCipher.doFinal(clientData.getBytes());

            Signature signature = Signature.getInstance(SIGNATURE_MODE);
            signature.initSign(clientPrivateKey);
            signature.update(encryptedClientData);
            byte[] clientSignature = signature.sign();

            outputStream.writeObject(encryptedClientData);
            outputStream.writeObject(clientSignature);

            System.out.println("Sent encrypted data and signature to server.");

            // Receive server's encrypted response
            byte[] encryptedResponse = (byte[]) inputStream.readObject();
            byte[] serverSignature = (byte[]) inputStream.readObject();

            // Verifying server signature
            signature.initVerify(serverPublicKey);
            signature.update(encryptedResponse);
            if (!signature.verify(serverSignature)) {
                System.out.println("Server signature verification failed. Closing connection.");
                return;
            }

            // Decrypting server response
            rsaCipher.init(Cipher.DECRYPT_MODE, clientPrivateKey);
            byte[] decryptedResponse = rsaCipher.doFinal(encryptedResponse);

            // Generate AES key
            SecretKeySpec aesKey = createAESKey(decryptedResponse);

            // Handle user commands
            while (true) {
                System.out.print("Enter command: ");
                String command = scanner.nextLine();

                if (command.equalsIgnoreCase("bye")) {
                    outputStream.writeObject(encryptAES(command.getBytes(), aesKey));
                    System.out.println("Disconnected from server.");
                    break;
                }

                outputStream.writeObject(encryptAES(command.getBytes(), aesKey));
                byte[] encryptedServerResponse = (byte[]) inputStream.readObject();
                String response = new String(decryptAES(encryptedServerResponse, aesKey));

                System.out.println("Server: " + response);
            }
        }
    }

    // methods for key loading, encryption, decryption, etc.
    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    private static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename));
        java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    private static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static SecretKeySpec createAESKey(byte[] combinedBytes) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(combinedBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] encryptAES(byte[] data, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(generateIV(key)));
        return cipher.doFinal(data);
    }

    private static byte[] decryptAES(byte[] encryptedData, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(generateIV(key)));
        return cipher.doFinal(encryptedData);
    }

    private static byte[] generateIV(SecretKeySpec key) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(key.getEncoded());
    }
}