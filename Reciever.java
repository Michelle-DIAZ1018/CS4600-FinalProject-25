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
        // needs two items to function 1. the transmitted file 2. the private key -- brings up an error if it is not found
        if (args.length != 2) { 
            System.out.println("Usage: java Receiver <TransmittedFile> <PrivateKey>");
            return;
        }

        String transmittedFile = args[0]; // transmitted file
        String privateKeyFile = args[1]; // private key 

        try {
            // reads file, breaks it down, extracts it to keys and values
            HashMap<String, String> map = parseKeyValueFile(transmittedFile);

            // loads and reads private key 
            PrivateKey privateKey = loadPrivateKey(privateKeyFile);

            // AES key from sender
            String encryptedKeyB64 = map.getOrDefault("encryptedAESKey", map.get("aesKey"));
            if (encryptedKeyB64 == null) throw new Exception("No AES key found in transmitted file"); // in case there is no key to be found

            // decrypting the file with the key 
            SecretKey aesKey = decryptAESKey(encryptedKeyB64, privateKey);

            // coverts text from the file to to bytes // 
            byte[] iv = Base64.getDecoder().decode(
                    map.getOrDefault("iv", map.get("aesIV")) // start value to start shuffle
            );
            byte[] ciphertext = Base64.getDecoder().decode(
                    map.getOrDefault("ciphertext", map.get("data")) // encrypted message
            );
            byte[] receivedHmac = Base64.getDecoder().decode(
                    map.getOrDefault("hmac", map.get("mac")) 
            );

            // authenticity check for tampering
            if (!verifyHMAC(aesKey, iv, ciphertext, receivedHmac)) {
                System.err.println("[" + Instant.now() + "] HMAC verification failed! Message may be tampered.");
                return;
            }

            // cipher chain blocking with AES (advanced excryption standard)
            byte[] plaintext = decryptAES(ciphertext, aesKey, iv);

            // writes message into a file 
            String outputFile = "DecryptedMessage.txt";
            writeBytesToFile(outputFile, plaintext);

            // displays all the decrypted data // 
            System.out.println("Decryption successful -- Message saved to: " + outputFile);
            if (map.containsKey("sender")) System.out.println("Sender: " + map.get("sender"));
            if (map.containsKey("timestamp")) System.out.println("Sent at: " + map.get("timestamp"));
            if (map.containsKey("messageType")) System.out.println("Message type: " + map.get("messageType"));
        
            // exception handling for formatting 
        } catch (Exception e) {
            System.err.println("Error during decryption: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ALL METHODS USED // 

    // reads all lines, one by one in a for loop 
    private static HashMap<String, String> parseKeyValueFile(String path) throws Exception {
        List<String> lines = readAllLines(path);
        HashMap<String, String> map = new HashMap<>();
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || !line.contains(":")) continue; // skip empty or invalid lines
            String[] parts = line.split(":", 2);
            map.put(parts[0].trim(), parts[1].trim()); // puts into key : values 
        }
        return map;
    }

    // reads the file into the order of lines 
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

    // loads the private RSA key 
    private static PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] privBytes = readAllBytes(path); // reads raw bytes 
        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(privBytes)); // converts bytes into PKCS format 
    }

    // reads the file in the byte format 
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

    // writes the bytes to the file 
    private static void writeBytesToFile(String path, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(data);
        }
    }

    // decodes Base64 --> decrypts --> turns into the AES key 
    private static SecretKey decryptAESKey(String encryptedKeyB64, PrivateKey rsaKey) throws Exception {
        byte[] encryptedAESKey = Base64.getDecoder().decode(encryptedKeyB64);
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAESKey);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

   // AES key --> HMAC key 
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

    // AES decryption 
    private static byte[] decryptAES(byte[] ciphertext, SecretKey aesKey, byte[] iv) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return aesCipher.doFinal(ciphertext);
    }
}

/*
ALGORITHMS USED: 
RSA
AES
HMAC
Base64
Secure Hash 
*/ 
