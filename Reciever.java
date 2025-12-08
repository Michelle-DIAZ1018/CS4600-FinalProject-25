import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.time.Instant;

public class Receiver {

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java Receiver <TransmittedFile> <PrivateKey>");
            return;
        }

        String transmittedFile = args[0];
        String privateKeyFile = args[1];

        try {
            HashMap<String, String> map = parseKeyValueFile(transmittedFile);

            PrivateKey privateKey = loadPrivateKey(privateKeyFile);

            String encryptedKeyB64 = map.getOrDefault("encryptedAESKey", map.get("aesKey"));
            if (encryptedKeyB64 == null) throw new Exception("No AES key found in transmitted file");

            SecretKey aesKey = decryptAESKey(encryptedKeyB64, privateKey);

            byte[] iv = Base64.getDecoder().decode(
                    map.getOrDefault("iv", map.get("aesIV"))
            );
            byte[] ciphertext = Base64.getDecoder().decode(
                    map.getOrDefault("ciphertext", map.get("data"))
            );
            byte[] receivedHmac = Base64.getDecoder().decode(
                    map.getOrDefault("hmac", map.get("mac"))
            );

            if (!verifyHMAC(aesKey, iv, ciphertext, receivedHmac)) {
                System.err.println("[" + Instant.now() + "] HMAC verification failed! Message may be tampered.");
                return;
            }

            byte[] plaintext = decryptAES(ciphertext, aesKey, iv);

            String outputFile = "DecryptedMessage.txt";
            writeBytesToFile(outputFile, plaintext);

            System.out.println("Decryption successful -- Message saved to: " + outputFile);
            if (map.containsKey("sender")) System.out.println("Sender: " + map.get("sender"));
            if (map.containsKey("timestamp")) System.out.println("Sent at: " + map.get("timestamp"));
            if (map.containsKey("messageType")) System.out.println("Message type: " + map.get("messageType"));

        } catch (Exception e) {
            System.err.println("Error during decryption: " + e.getMessage());
            e.printStackTrace();
        }
    }


    private static HashMap<String, String> parseKeyValueFile(String path) throws Exception {
        List<String> lines = readAllLines(path);
        HashMap<String, String> map = new HashMap<>();
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || !line.contains(":")) continue; // skip empty or invalid lines
            String[] parts = line.split(":", 2);
            map.put(parts[0].trim(), parts[1].trim());
        }
        return map;
    }

    private static List<String> readAllLines(String path) throws IOException {
        List<String> lines = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) {
                lines.add(line);
            }
        }
        return lines;
    }

    private static PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] privBytes = readAllBytes(path);
        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(privBytes));
    }

    private static byte[] readAllBytes(String path) throws IOException {
        File file = new File(path);
        byte[] data = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            if (fis.read(data) != data.length) {
                throw new IOException("Failed to read entire file: " + path);
            }
        }
        return data;
    }

    private static void writeBytesToFile(String path, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(data);
        }
    }

    private static SecretKey decryptAESKey(String encryptedKeyB64, PrivateKey rsaKey) throws Exception {
        byte[] encryptedAESKey = Base64.getDecoder().decode(encryptedKeyB64);
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAESKey);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

   
    private static boolean verifyHMAC(SecretKey aesKey, byte[] iv, byte[] ciphertext, byte[] receivedHmac) throws Exception {
        // Use the AES key directly for HMAC
        SecretKeySpec macKey = new SecretKeySpec(aesKey.getEncoded(), "HmacSHA256");

        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(macKey);
        hmac.update(iv);
        hmac.update(ciphertext);

        byte[] computedHmac = hmac.doFinal();
        return MessageDigest.isEqual(computedHmac, receivedHmac);
    }

    private static byte[] decryptAES(byte[] ciphertext, SecretKey aesKey, byte[] iv) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return aesCipher.doFinal(ciphertext);
    }
}
