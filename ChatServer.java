import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class ChatServer {

    private static final int PORT = 5000;

    private static class Peer implements AutoCloseable {
        final Socket socket;
        final BufferedReader input;
        final BufferedWriter output;

        Peer(Socket socket) throws IOException {
            this.socket = socket;

            input = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.UTF_8));

            output = new BufferedWriter(new OutputStreamWriter(
                    socket.getOutputStream(), StandardCharsets.UTF_8));
        }

        synchronized void send(String line) throws IOException {
            output.write(line);
            output.newLine();
            output.flush();
        }

        @Override
        public void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static void relay(
            Peer source, Peer destination, String direction) {

        try {
            String packet;

            while ((packet = source.input.readLine()) != null) {
                destination.send(packet);
                System.out.println("Forwarded a packet: " + direction);
            }

        } catch (IOException e) {
            System.out.println("Connection ended: " + direction);

        } finally {
            source.close();
            destination.close();
        }
    }

    public static void main(String[] args) {

        System.out.println("=== Secure Chat Relay Server ===");

        try (ServerSocket server = new ServerSocket(
                PORT, 2, InetAddress.getByName("127.0.0.1"))) {

            System.out.println("Listening on 127.0.0.1:" + PORT);
            System.out.println("Waiting for Alice...");

            try (Peer alice = new Peer(server.accept())) {

                alice.send("ROLE:ALICE");

                System.out.println("Alice connected.");
                System.out.println("Waiting for Bob...");

                try (Peer bob = new Peer(server.accept())) {

                    bob.send("ROLE:BOB");

                    System.out.println("Bob connected.");

                    alice.send("READY");
                    bob.send("READY");

                    System.out.println("Both clients connected.");
                    System.out.println("Relaying packets...");

                    Thread aliceToBob = new Thread(
                            () -> relay(alice, bob, "Alice -> Bob"));

                    Thread bobToAlice = new Thread(
                            () -> relay(bob, alice, "Bob -> Alice"));

                    aliceToBob.start();
                    bobToAlice.start();

                    aliceToBob.join();
                    bobToAlice.join();

                    System.out.println("Session ended.");
                }
            }

        } catch (IOException e) {
            System.out.println("Server error: " + e.getMessage());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.out.println("Server interrupted.");
        }
    }
}