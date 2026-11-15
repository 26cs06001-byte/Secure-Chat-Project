import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_BITS = 128;

    public static byte[] generateSalt() {
        byte[] salt = new byte[32];
        RANDOM.nextBytes(salt);
        return salt;
    }

    // HKDF-SHA256: extract, then one expand block for a 32-byte key.
    public static SecretKey deriveKey(
            byte[] sharedSecret,
            byte[] salt,
            String context) throws Exception {

        if (salt == null || salt.length != 32) {
            throw new IllegalArgumentException("Salt must be 32 bytes.");
        }

        Mac hmac = Mac.getInstance("HmacSHA256");

        hmac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = hmac.doFinal(sharedSecret);

        hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
        hmac.update(context.getBytes(StandardCharsets.UTF_8));
        byte[] keyBytes = hmac.doFinal(new byte[] { 1 });

        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        Arrays.fill(prk, (byte) 0);
        Arrays.fill(keyBytes, (byte) 0);

        return key;
    }

    // Packet format: Base64(nonce || ciphertext || authentication tag).
    public static String encrypt(
            String message, SecretKey key) throws Exception {

        byte[] nonce = new byte[NONCE_LENGTH];
        RANDOM.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.ENCRYPT_MODE,
                key,
                new GCMParameterSpec(TAG_BITS, nonce));

        byte[] encrypted = cipher.doFinal(
                message.getBytes(StandardCharsets.UTF_8));

        byte[] packet = ByteBuffer
                .allocate(nonce.length + encrypted.length)
                .put(nonce)
                .put(encrypted)
                .array();

        return Base64.getEncoder().encodeToString(packet);
    }

    public static String decrypt(
            String encodedPacket, SecretKey key) throws Exception {

        byte[] packet = Base64.getDecoder().decode(encodedPacket);

        if (packet.length < NONCE_LENGTH + TAG_BITS / 8) {
            throw new IllegalArgumentException("Encrypted packet is too short.");
        }

        byte[] nonce = Arrays.copyOfRange(packet, 0, NONCE_LENGTH);

        byte[] encrypted = Arrays.copyOfRange(
                packet, NONCE_LENGTH, packet.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                new GCMParameterSpec(TAG_BITS, nonce));

        byte[] plaintext = cipher.doFinal(encrypted);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {

        System.out.println("=== Encryption Module Test ===");

        KeyPair alice = DHKeyExchange.generateInitialKeyPair();
        KeyPair bob = DHKeyExchange.generateCompatibleKeyPair(
                alice.getPublic());

        byte[] aliceSecret = DHKeyExchange.calculateSharedSecret(
                alice.getPrivate(), bob.getPublic());

        byte[] bobSecret = DHKeyExchange.calculateSharedSecret(
                bob.getPrivate(), alice.getPublic());

        // Both parties use the same public salt and direction label.
        byte[] salt = generateSalt();
        String context = "SecureChat-v1|Alice-to-Bob";

        SecretKey aliceSendKey = deriveKey(
                aliceSecret, salt, context);

        SecretKey bobReceiveKey = deriveKey(
                bobSecret, salt, context);

        Arrays.fill(aliceSecret, (byte) 0);
        Arrays.fill(bobSecret, (byte) 0);

        String original = "Hello Bob! Yeh hamara encrypted message hai.";
        String encrypted = encrypt(original, aliceSendKey);
        String decrypted = decrypt(encrypted, bobReceiveKey);

        System.out.println();
        System.out.println("Original:  " + original);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);

        if (!original.equals(decrypted)) {
            throw new IllegalStateException("Message round-trip failed.");
        }

        System.out.println();
        System.out.println("SUCCESS: Message encryption/decryption passed.");

        byte[] tampered = Base64.getDecoder().decode(encrypted);
        tampered[tampered.length - 1] ^= 1;

        System.out.println();
        System.out.println("Testing a modified encrypted packet...");

        try {
            decrypt(
                    Base64.getEncoder().encodeToString(tampered),
                    bobReceiveKey);

            throw new IllegalStateException(
                    "FAILURE: Modified packet was accepted.");

        } catch (AEADBadTagException expected) {
            System.out.println(
                    "SUCCESS: Modified packet rejected.");
        }

        System.out.println();
        System.out.println("Local test only. Peer identity is not verified yet.");
    }
}