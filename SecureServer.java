import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.nio.charset.StandardCharsets;

public class SecureServer {
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
    private static final String SIGNATURE_MODE = "SHA1withRSA";
    private static final String AES_MODE = "AES/CBC/PKCS5Padding";

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Usage: java SecureServer <port>");
            return;
        }
        int portNumber = Integer.parseInt(args[0]);

        // Load server's private key
        PrivateKey privateKey = loadPrivateKey("server.prv");

        try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
            System.out.println("Server is running on port " + portNumber);

            while (true) {
                try (Socket clientSocket = serverSocket.accept();
                     ObjectInputStream inputStream = new ObjectInputStream(clientSocket.getInputStream());
                     ObjectOutputStream outputStream = new ObjectOutputStream(clientSocket.getOutputStream())) {

                    System.out.println("Client connected!");

                    // Step 1: Receive encrypted user ID and random bytes
                    byte[] encryptedData = (byte[]) inputStream.readObject();
                    byte[] signatureFromClient = (byte[]) inputStream.readObject();

                    System.out.println("Received encrypted data and signature.");

                    // Decrypt client data
                    Cipher rsaCipher = Cipher.getInstance(RSA_MODE);
                    rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
                    byte[] decryptedData = rsaCipher.doFinal(encryptedData);

                    // Verify client signature
                    String userId = new String(decryptedData, StandardCharsets.UTF_8).split(" ")[0];
                    PublicKey clientPublicKey = loadPublicKey(userId + ".pub");
                    Signature signature = Signature.getInstance(SIGNATURE_MODE);
                    signature.initVerify(clientPublicKey);
                    signature.update(encryptedData);
                    if (!signature.verify(signatureFromClient)) {
                        System.out.println("Signature verification failed. Closing connection.");
                        continue;
                    }

                    byte[] clientRandomBytes = Base64.getDecoder()
                            .decode(new String(decryptedData, StandardCharsets.UTF_8).split(" ")[1]);

                    // Generate server's random bytes and send encrypted response
                    byte[] serverRandomBytes = generateRandomBytes(16);
                    byte[] combinedBytes = new byte[32];
                    System.arraycopy(clientRandomBytes, 0, combinedBytes, 0, 16);
                    System.arraycopy(serverRandomBytes, 0, combinedBytes, 16, 16);

                    rsaCipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
                    byte[] encryptedResponse = rsaCipher.doFinal(combinedBytes);

                    signature.initSign(privateKey);
                    signature.update(encryptedResponse);
                    byte[] serverSignature = signature.sign();

                    outputStream.writeObject(encryptedResponse);
                    outputStream.writeObject(serverSignature);

                    System.out.println("Sent encrypted response and signature to client.");

                    // Generate AES key
                    SecretKeySpec aesKey = createAESKey(combinedBytes);

                    // Handle client commands
                    while (true) {
                        byte[] encryptedCommand = (byte[]) inputStream.readObject();
                        System.out.println("Received command from client.");

                        String command = new String(decryptAES(encryptedCommand, aesKey), StandardCharsets.UTF_8);
                        System.out.println("Command: " + command);

                        if (command.equals("bye")) {
                            System.out.println("Client " + userId + " disconnected.");
                            break;
                        } else if (command.startsWith("get ")) {
                            String filename = command.substring(4);
                            File file = new File(filename);
                            if (!file.exists() || file.getName().endsWith(".prv")) {
                                outputStream.writeObject(encryptAES("File not found.".getBytes(StandardCharsets.UTF_8), aesKey));
                            } else {
                                byte[] fileContent = readFile(file);
                                outputStream.writeObject(encryptAES(fileContent, aesKey));
                            }
                        } else if (command.equals("ls")) {
                            File currentDirectory = new File(".");
                            StringBuilder fileList = new StringBuilder();
                            for (File f : currentDirectory.listFiles()) {
                                if (!f.getName().endsWith(".prv")) {
                                    fileList.append(f.getName()).append("\n");
                                }
                            }
                            outputStream.writeObject(encryptAES(fileList.toString().getBytes(StandardCharsets.UTF_8), aesKey));
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
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

    private static byte[] readFile(File file) throws IOException {
        return java.nio.file.Files.readAllBytes(file.toPath());
    }
}