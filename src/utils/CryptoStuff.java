package utils;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.KeyAgreement;

public abstract class CryptoStuff {

    private static final int DH_KEY_SIZE = 512;

    // ===== HASH =====
    public static byte[] hash(String content) {
        return hash(content.getBytes());
    }

    public static byte[] hash(byte[] content) {
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA256");
            hash.reset();
            hash.update(content);
            return hash.digest();
        } catch (Exception e) {
            System.out.println("Could not hash contents.");
            e.printStackTrace();
        }
        return new byte[0];
    }

    public static String hashB64(String content) {
        return hashB64(content.getBytes());
    }

    public static String hashB64(byte[] content) {
        byte[] hashed = hash(content);
        return Base64.getEncoder().encodeToString(hashed);
    }

    // ===== Diffie-Hellman Key Exchange =====
    public static KeyPair dhGenerateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(DH_KEY_SIZE);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            System.out.println("Could not generate key pair for dh.");
            e.printStackTrace();
        }
        return null;
    }

    public static KeyAgreement dhCreateKeyAgreement(KeyPair keyPair) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(keyPair.getPrivate());
            return ka;
        } catch (Exception e) {
            System.out.println("Could not create a key agreement for dh.");
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] dhGenerateSecret(KeyAgreement keyAgreement, Key publicKey) {
        try {
            keyAgreement.doPhase(publicKey, true);
            return keyAgreement.generateSecret();
        } catch (Exception e) {
            System.out.println("Could not generate a secret for dh.");
            e.printStackTrace();
        }
        return new byte[0];
    }
}
