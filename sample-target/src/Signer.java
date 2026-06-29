import java.security.*;

public class Signer {
    public KeyPair rsaKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");  // RSA
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public byte[] sign(byte[] data, PrivateKey key) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");      // ECDSA
        s.initSign(key);
        s.update(data);
        return s.sign();
    }

    public byte[] legacyDigest(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);        // MD5
    }
}
