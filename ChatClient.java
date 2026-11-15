import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.SecretKey;

public class ChatClient {

    private static void send(BufferedWriter out, String line)
            throws IOException {

        out.write(line);
        out.newLine();
        out.flush();
    }

    private static String receive(BufferedReader in)
            throws IOException {

        String line = in.readLine();

        if (line == null) {
            throw new EOFException("Peer or server disconnected.");
        }

        return line;
    }

    private static String receiveField(
            BufferedReader in, String prefix) throws IOException {

        String line = receive(in);

        if (!line.startsWith(prefix)) {
            throw new IOException("Unexpected protocol message.");
        }

        return line.substring(prefix.length());
    }

    private static PublicKey decodePublicKey(String encoded)
            throws Exception {

        byte[] bytes = Base64.getDecoder().decode(encoded);

        return KeyFactory.getInstance("DH").generatePublic(
                new X509EncodedKeySpec(bytes));
    }

    public static void main(String[] args) {

        try (Socket socket = new Socket("127.0.0.1", 5000);
             BufferedReader in = new BufferedReader(
                     new InputStreamReader(
                             socket.getInputStream(),
                             StandardCharsets.UTF_8));
             BufferedWriter out = new BufferedWriter(
                     new OutputStreamWriter(
                             socket.getOutputStream(),
                             StandardCharsets.UTF_8))) {

            BufferedReader keyboard = new BufferedReader(
                    new InputStreamReader(System.in));

            String role = receiveField(in, "ROLE:");

            if (!role.equals("ALICE") && !role.equals("BOB")) {
                throw new IOException("Unknown role.");
            }

            boolean isAlice = role.equals("ALICE");
            String peerName = isAlice ? "Bob" : "Alice";

            System.out.println("=== Secure Chat: " + role + " ===");
            System.out.println("Waiting for the other client...");

            if (!receive(in).equals("READY")) {
                throw new IOException("Expected READY.");
            }

            KeyPair ownKeys;
            PublicKey peerKey;
            byte[] salt;
            String alicePublic;
            String bobPublic;

            if (isAlice) {
                ownKeys = DHKeyExchange.generateInitialKeyPair();

                alicePublic = Base64.getEncoder().encodeToString(
                        ownKeys.getPublic().getEncoded());

                salt = CryptoUtils.generateSalt();

                send(out, "PUB:" + alicePublic);
                send(out, "SALT:" + Base64.getEncoder()
                        .encodeToString(salt));

                bobPublic = receiveField(in, "PUB:");
                peerKey = decodePublicKey(bobPublic);

            } else {
                alicePublic = receiveField(in, "PUB:");
                peerKey = decodePublicKey(alicePublic);

                salt = Base64.getDecoder().decode(
                        receiveField(in, "SALT:"));

                ownKeys = DHKeyExchange.generateCompatibleKeyPair(
                        peerKey);

                bobPublic = Base64.getEncoder().encodeToString(
                        ownKeys.getPublic().getEncoded());

                send(out, "PUB:" + bobPublic);
            }

            String transcript = "SecureChat-v1\n"
                    + alicePublic + "\n"
                    + bobPublic + "\n"
                    + Base64.getEncoder().encodeToString(salt);

            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(transcript.getBytes(StandardCharsets.UTF_8));

            String sessionId = HexFormat.of().formatHex(digest);

            System.out.println();
            System.out.println("Session fingerprint:");
            System.out.println(sessionId);
            System.out.println();
            System.out.println(
                    "Compare the FULL fingerprint with the other window.");
            System.out.println(
                    "Type MATCH only if both fingerprints are identical:");

            if (!"MATCH".equals(keyboard.readLine())) {
                System.out.println("Verification cancelled. Closing.");
                return;
            }

            byte[] sharedSecret = DHKeyExchange.calculateSharedSecret(
                    ownKeys.getPrivate(), peerKey);

            SecretKey aliceToBob = CryptoUtils.deriveKey(
                    sharedSecret, salt,
                    "SecureChat-v1|Alice-to-Bob|" + sessionId);

            SecretKey bobToAlice = CryptoUtils.deriveKey(
                    sharedSecret, salt,
                    "SecureChat-v1|Bob-to-Alice|" + sessionId);

            Arrays.fill(sharedSecret, (byte) 0);

            SecretKey sendKey = isAlice ? aliceToBob : bobToAlice;
            SecretKey receiveKey = isAlice ? bobToAlice : aliceToBob;

            send(out, "CHECK:" + CryptoUtils.encrypt(
                    "VERIFIED|" + role, sendKey));

            String peerCheck = CryptoUtils.decrypt(
                    receiveField(in, "CHECK:"), receiveKey);

            String expectedRole = isAlice ? "BOB" : "ALICE";

            if (!peerCheck.equals("VERIFIED|" + expectedRole)) {
                throw new IOException("Peer key confirmation failed.");
            }

            System.out.println();
            System.out.println("Verification and key confirmation passed.");
            System.out.println("Chat ready. Type a message and press Enter.");
            System.out.println("Type /quit to exit.");

            Thread receiver = new Thread(() -> {
                long expectedSequence = 0;

                try {
                    while (true) {
                        String encrypted = receiveField(in, "MSG:");
                        String plaintext = CryptoUtils.decrypt(
                                encrypted, receiveKey);

                        String prefix = expectedSequence + "|";

                        if (!plaintext.startsWith(prefix)) {
                            throw new IOException(
                                    "Unexpected message sequence.");
                        }

                        expectedSequence++;

                        System.out.println(
                                "\n" + peerName + ": "
                                + plaintext.substring(prefix.length()));
                    }

                } catch (Exception e) {
                    System.out.println(
                            "\nChat closed: " + e.getMessage());
                    System.out.println(
                            "Press Enter if the prompt has not returned.");

                } finally {
                    try {
                        socket.close();
                    } catch (IOException ignored) {
                    }
                }
            });

            receiver.setDaemon(true);
            receiver.start();

            long sequence = 0;
            String message;

            while (!socket.isClosed()
                    && (message = keyboard.readLine()) != null) {

                if (socket.isClosed() || message.equals("/quit")) {
                    break;
                }

                if (message.isBlank()) {
                    continue;
                }

                String encrypted = CryptoUtils.encrypt(
                        sequence + "|" + message, sendKey);

                send(out, "MSG:" + encrypted);
                sequence++;
            }

        } catch (Exception e) {
            System.out.println("Client stopped: " + e.getMessage());
        }
    }
}