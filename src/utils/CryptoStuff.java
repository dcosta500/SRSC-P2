package utils;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public abstract class CryptoStuff {

    // ===== Current settings =====
    private static final String SYMMETRIC_ENCRYPTION_CIPHERSUITE = "AES/CCM/PKCS5Padding";
    private static final String SYMMETRIC_ALG = "AES";
    private static final String HASHING_ALG = "SHA256";
    private static final String SECRET_EXCHANGE_ALG = "DH";
    private static final String PBE_ALG = "PBKDF2WithHmacSHA256";
    private static final String SIG_CIPHERSUITE = "SHA256withRSA";
    private static final String SIG_ALG = "RSA";

    private static final int DH_KEY_SIZE = 512;
    private static final int SYM_KEY_SIZE = 256;
    private static final int ITERATION_COUNT = 10; //This value in a real situation should be in ten of thousands for simplicity reasons and lower computacional times we only use 10

    private static final byte[] IV = { (byte) 14, (byte) 7, (byte) 212, (byte) 157, (byte) 18, (byte) 147, (byte) 221,
            (byte) 49, (byte) 152, (byte) 198, (byte) 74, (byte) 52, (byte) 130, (byte) 156, (byte) 225, (byte) 102 };

    // ===== Secure Random =====
    /**
     * Secure random
     * @return a random number in long format
     */
    public static long getRandom() {
        return new SecureRandom().nextLong();
    }

    /**
     * Generates a random filled byte array
     * @param Size of byte array
     * @return the byte array randomly filled
     */
    public static byte[] generateRandomByteArray(int nrOfBytes) {
        byte[] array = new byte[nrOfBytes];
        new SecureRandom().nextBytes(array);
        return array;
    }

    // ===== Hash =====
    /**
     * Hash a byte array
     * @param content the content to be hashed
     * @return hashed byte array of content
     */
    public static byte[] hash(String content) {
        return hash(content.getBytes());
    }

    /**
     * Hash a byte array
     * @param content the content to be hashed
     * @return hashed byte array of content
     */
    public static byte[] hash(byte[] content) {
        try {
            MessageDigest hash = MessageDigest.getInstance(HASHING_ALG);
            hash.reset();
            hash.update(content);
            return hash.digest();
        } catch (Exception e) {
            System.out.println("Could not hash contents.");
            e.printStackTrace();
        }
        return new byte[0];
    }

    /**
     * Hash a byte array
     * @param content the content to be hashed
     * @return Base64 of content hash
     */
    public static String hashB64(String content) {
        return hashB64(content.getBytes());
    }

    /**
     * Hash a byte array
     * @param content the content to be hashed
     * @return Base64 of content hash
     */
    public static String hashB64(byte[] content) {
        byte[] hashed = hash(content);
        return Base64.getEncoder().encodeToString(hashed);
    }

    // ===== Diffie-Hellman Key Exchange =====
    /**
     * Generate Diffie-Hellman keypair
     * @return the Key pair
     */
    public static KeyPair dhGenerateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(SECRET_EXCHANGE_ALG);
            keyGen.initialize(DH_KEY_SIZE);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            System.out.println("Could not generate key pair for dh.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Created Key agreement object.
     * @return The key agreement
     */
    public static KeyAgreement dhCreateKeyAgreement(KeyPair keyPair) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance(SECRET_EXCHANGE_ALG);
            ka.init(keyPair.getPrivate());
            return ka;
        } catch (Exception e) {
            System.out.println("Could not create a key agreement for dh.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Generates a secret
     * @return the secret
     */
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

    /**
     * Gets the public key
     * @param publicKeyBytes the public key byte array
     * @return the Public key object
     */
    public static Key dhRecreatePublicKeyFromBytes(byte[] publicKeyBytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(SECRET_EXCHANGE_ALG);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            System.out.println("Could not recreate public key from bytes.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Gets the public key
     * @param sharedSecret the secret
     * @return the key generated from the secret
     */
    public static Key dhCreateKeyFromSharedSecret(byte[] sharedSecret) {
        return new SecretKeySpec(sharedSecret, 0, sharedSecret.length, SYMMETRIC_ALG);
    }

    // ===== Symmetric Encryption =====

    public static Key parseSymKeyFromBase64(String b64Key) {
        try {
            byte[] keyAsBytes = Base64.getDecoder().decode(b64Key);
            return new SecretKeySpec(keyAsBytes, SYMMETRIC_ALG);
        } catch (Exception e) {
            System.out.println("Could not parse symmetric key from base 64.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Creates a symetric Key
     * @return random symetric key
     */
    public static Key createSymKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(SYMMETRIC_ALG);
            kg.init(SYM_KEY_SIZE);
            return kg.generateKey();
        } catch (Exception e) {
            System.out.println("Could not generate a key");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Encripts content with a simetric key
     * @param key the simetric key
     * @param the content to be encripted
     * @return the encrypted content
     */
    public static byte[] symEncrypt(Key key, byte[] content) {
        try {
            Cipher cipher = Cipher.getInstance(SYMMETRIC_ENCRYPTION_CIPHERSUITE);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Could not encrypt content.");
            e.printStackTrace();
        }
        return new byte[0];
    }

    /**
     * decripts content with a simetric key
     * @param key the simetric key
     * @param the content to be decripted
     * @return the decrypted content
     */
    public static byte[] symDecrypt(Key key, byte[] content) {
        try {
            Cipher cipher = Cipher.getInstance(SYMMETRIC_ENCRYPTION_CIPHERSUITE);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Could not decrypt content.");
            e.printStackTrace();
        }
        return new byte[0];
    }

    // ===== Password Based Encryption =====

    /**
     * @param the password
     * @return the key generated from password
     */
    public static Key pbeCreateKeyFromPassword(String password) {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBE_ALG);
            byte[] salt = IV;
            PBEKeySpec pks = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, SYM_KEY_SIZE);
            return skf.generateSecret(pks);
        } catch (Exception e) {
            System.out.println("Could not create pbe key.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @param key the key generated from password
     * @param content the content to be encrypted
     * @return the encrypted content
     */
    public static byte[] pbeEncrypt(Key key, byte[] content) {
        try {
            Cipher cipher = Cipher.getInstance(PBE_ALG);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Could not encrypt content (pbe).");
            e.printStackTrace();
        }
        return new byte[0];
    }

    /**
     * @param key the key generated from password
     * @param content the content to be decrypted
     * @return the decrypted content
     */
    public static byte[] pbeDecrypt(Key key, byte[] content) {
        try {
            Cipher cipher = Cipher.getInstance(PBE_ALG);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Could not decrypt content (pbe).");
            e.printStackTrace();
        }
        return new byte[0];
    }

    // ===== Digital Signature =====
    /**
     * Digitally signs a message to prove authenticity.
     * @param privKey the private key of the signature owner
     * @param content the content to be signed
     * @return the content digitally signed
     */
    public static byte[] sign(PrivateKey privKey, byte[] content) {
        try {
            Signature signature = Signature.getInstance(SIG_CIPHERSUITE);
            signature.initSign(privKey);
            signature.update(content);
            return signature.sign();
        } catch (Exception e) {
            System.out.println("Could not sign contents.");
            e.printStackTrace();
        }
        return new byte[0];
    }

    // ===== File Parsing Methods =====
    /**
     * @param path the name of the file where the private key is stored
     * @return the private key extracted from the file
     */
    public static PrivateKey parsePrivateKeyFromPemFormat(String path) {
        try {
            // Read the content of the .key file
            String keyFileContent = new String(Files.readAllBytes(Paths.get(path)));

            // Remove the first and last lines if it's in PEM format
            keyFileContent = keyFileContent.replaceAll("-----BEGIN PRIVATE KEY-----", "");
            keyFileContent = keyFileContent.replaceAll("-----END PRIVATE KEY-----", "");

            // Decode the Base64-encoded key content
            byte[] keyBytes = Base64.getDecoder().decode(keyFileContent);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(SIG_ALG);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            System.out.println("Could not parse private key from pem.");
            e.printStackTrace();
        }
        return null;
    }
}
