// Generates the JWT signing key set INDIGO IAM needs, with NO external deps.
// Run via:  java iam/GenKeystore.java iam/keys/keystore.jwks
//
// INDIGO expects a JWK *set* (JSON) whose key id matches IAM_JWK_DEFAULT_KEY_ID
// (default "rsa1"). We emit a single RS256 RSA key in that format. Pure JDK:
// RSAPrivateCrtKey exposes every CRT parameter a JWK needs.

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class GenKeystore {

    // base64url, no padding, minimal unsigned big-endian (strip the sign byte
    // that BigInteger.toByteArray() prepends when the high bit is set).
    static String b64(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length > 1 && b[0] == 0) {
            byte[] t = new byte[b.length - 1];
            System.arraycopy(b, 1, t, 0, t.length);
            b = t;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    public static void main(String[] args) throws Exception {
        String out = args.length > 0 ? args[0] : "keystore.jwks";
        String kid = args.length > 1 ? args[1] : "rsa1";

        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        RSAPrivateCrtKey pri = (RSAPrivateCrtKey) kp.getPrivate();

        String jwk = "{\n  \"keys\": [\n    {\n"
                + "      \"kty\": \"RSA\",\n"
                + "      \"kid\": \"" + kid + "\",\n"
                + "      \"use\": \"sig\",\n"
                + "      \"alg\": \"RS256\",\n"
                + "      \"n\": \"" + b64(pub.getModulus()) + "\",\n"
                + "      \"e\": \"" + b64(pub.getPublicExponent()) + "\",\n"
                + "      \"d\": \"" + b64(pri.getPrivateExponent()) + "\",\n"
                + "      \"p\": \"" + b64(pri.getPrimeP()) + "\",\n"
                + "      \"q\": \"" + b64(pri.getPrimeQ()) + "\",\n"
                + "      \"dp\": \"" + b64(pri.getPrimeExponentP()) + "\",\n"
                + "      \"dq\": \"" + b64(pri.getPrimeExponentQ()) + "\",\n"
                + "      \"qi\": \"" + b64(pri.getCrtCoefficient()) + "\"\n"
                + "    }\n  ]\n}\n";

        Files.write(Paths.get(out), jwk.getBytes());
        System.out.println("wrote " + out + " (kid=" + kid + ", RSA 2048)");
    }
}
