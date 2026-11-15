import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class DHKeyExchange {

    public static KeyPair generateInitialKeyPair() throws Exception {
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("DH");

        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static KeyPair generateCompatibleKeyPair(
            PublicKey peerPublicKey) throws Exception {

        if (!(peerPublicKey instanceof DHPublicKey)) {
            throw new IllegalArgumentException("Expected a DH public key.");
        }

        DHPublicKey dhPublicKey = (DHPublicKey) peerPublicKey;
        DHParameterSpec parameters = dhPublicKey.getParams();

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("DH");

        generator.initialize(parameters);
        return generator.generateKeyPair();
    }

    public static byte[] calculateSharedSecret(
            PrivateKey ownPrivateKey,
            PublicKey peerPublicKey) throws Exception {

        KeyAgreement agreement = KeyAgreement.getInstance("DH");
        agreement.init(ownPrivateKey);
        agreement.doPhase(peerPublicKey, true);

        return agreement.generateSecret();
    }

    public static void main(String[] args) throws Exception {

        System.out.println("=== Java DH Key Exchange Test ===");
        System.out.println();

        KeyPair alice = generateInitialKeyPair();
        System.out.println("Alice key pair generated.");

        KeyPair bob = generateCompatibleKeyPair(alice.getPublic());
        System.out.println("Bob key pair generated using the same DH parameters.");

        byte[] aliceSecret = calculateSharedSecret(
                alice.getPrivate(), bob.getPublic());

        byte[] bobSecret = calculateSharedSecret(
                bob.getPrivate(), alice.getPublic());

        boolean matching =
                MessageDigest.isEqual(aliceSecret, bobSecret);

        System.out.println();
        System.out.println("DH parameter size: "
                + ((DHPublicKey) alice.getPublic())
                        .getParams().getP().bitLength()
                + " bits");

        System.out.println("Shared secrets match: " + matching);

        Arrays.fill(aliceSecret, (byte) 0);
        Arrays.fill(bobSecret, (byte) 0);

        if (!matching) {
            throw new IllegalStateException("Shared secrets do not match.");
        }

        System.out.println();
        System.out.println("SUCCESS: DH key exchange completed.");
        System.out.println("Private keys and shared secrets are not displayed.");
        System.out.println("Local test only: networking and authentication");
        System.out.println("have not been added yet.");
    }
}