import java.math.BigInteger;

public class MathDemo {

    public static void main(String[] args) {

        // Small values are for learning only, not real chat security.
        BigInteger p = BigInteger.valueOf(23);
        BigInteger g = BigInteger.valueOf(5);

        BigInteger alicePrivate = BigInteger.valueOf(6);
        BigInteger bobPrivate = BigInteger.valueOf(15);

        BigInteger alicePublic = g.modPow(alicePrivate, p);
        BigInteger bobPublic = g.modPow(bobPrivate, p);

        BigInteger aliceSecret = bobPublic.modPow(alicePrivate, p);
        BigInteger bobSecret = alicePublic.modPow(bobPrivate, p);

        System.out.println("=== Diffie-Hellman Mathematical Demo ===");
        System.out.println();

        System.out.println("Public prime p = " + p);
        System.out.println("Public generator g = " + g);

        System.out.println();
        System.out.println("--- Private values: demo display only ---");
        System.out.println("Alice private value a = " + alicePrivate);
        System.out.println("Bob private value b = " + bobPrivate);

        System.out.println();
        System.out.println("--- Public values exchanged ---");
        System.out.println("Alice: A = g^a mod p = " + alicePublic);
        System.out.println("Bob:   B = g^b mod p = " + bobPublic);

        System.out.println();
        System.out.println("--- Shared secret calculation ---");
        System.out.println("Alice: B^a mod p = " + aliceSecret);
        System.out.println("Bob:   A^b mod p = " + bobSecret);

        System.out.println();

        if (aliceSecret.equals(bobSecret)) {
            System.out.println("SUCCESS: Both shared secrets match.");
        } else {
            System.out.println("ERROR: Shared secrets do not match.");
        }

        System.out.println();
        System.out.println("Educational demo only. Not a secure chat app yet.");
    }
}