package srsc.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;


public abstract class CryptoStuff {
    // ===== Current settings =====
    private static final String SYMMETRIC_ENCRYPTION_CIPHERSUITE = "AES/CTR/NoPadding";
    private static final String SYMMETRIC_ALG = "AES";
    private static final String HASHING_ALG = "SHA256";
    private static final String SECRET_EXCHANGE_ALG = "DH";
    private static final String PBE_ALG = "PBEWithMD5AndTripleDES";
    private static final int PBE_ITERATIONS = 10_000;
    private static final int PBE_KEYSIZE = 256;
    private static final String SIG_CIPHERSUITE = "SHA256withRSA";
    private static final String SIG_ALG = "RSA";
    private static final String TRUSTSTORE_TYPE = "JKS";

    private static final int DH_KEY_SIZE = 512;
    private static final int SYM_KEY_SIZE = 256;

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
     * @param nrOfBytes to be generated
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

    public static byte[] b64ToBytes(String b64) {
        return Base64.getDecoder().decode(b64);
    }

    public static String bytesToB64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
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
     * Generate Diffie-Hellman shared secret
     * @param privateKey the private key
     * @param publicKeyBytes public key in bytes
     * @return the shared secret
     */
    public static byte[] dhGenerateSharedSecret(PrivateKey privateKey, byte[] publicKeyBytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);

            return keyAgreement.generateSecret();
        } catch (Exception e) {
            System.out.println("Could not compute shared dh secret.");
            e.printStackTrace();
        }
        return new byte[0];
    }

    /**
     * Gets the public key
     * @param sharedSecret the secret
     * @return the key generated from the secret
     */
    public static Key dhCreateKeyFromSharedSecret(byte[] sharedSecret) {
        byte[] keyBytes = new byte[SYM_KEY_SIZE / 8];
        new Random(Base64.getEncoder().encodeToString(sharedSecret).hashCode()).nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, SYMMETRIC_ALG);
    }

    // ===== Symmetric Encryption =====
    /**
     * Parse byte array to key
     * @param symKey the symmetric key as a byte array
     * @return the symetric key
     */
    public static Key parseSymKeyFromBytes(byte[] symKey) {
        try {
            return new SecretKeySpec(symKey, SYMMETRIC_ALG);
        } catch (Exception e) {
            System.out.println("Could not parse symmetric key from.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Parse String base 64 encryption to key
     * @param b64Key The key in base64 format
     * @return the key
     */
    public static Key parseSymKeyFromBase64(String b64Key) {
        return parseSymKeyFromBytes(Base64.getDecoder().decode(b64Key));
    }

    /**
     * Creates a symmetric Key
     * @return random symmetric key
     */
    public static Key generateSymKey() {
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
     * @param content the content to be encripted
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
     * @param content the content to be decripted
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
    public static String pbeHashing(byte[] salt, String password){
        try{
            KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, PBE_ITERATIONS, PBE_KEYSIZE);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hashedBytes = keyFactory.generateSecret(keySpec).getEncoded();
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (Exception e){
            System.out.println("Could not produce password hash.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @param password the password
     * @return the key generated from password
     */
    public static Key pbeCreateKeyFromPassword(byte[] salt, String password) {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBE_ALG);
            PBEKeySpec pks = new PBEKeySpec(password.toCharArray(), salt, PBE_ITERATIONS, PBE_KEYSIZE);
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
    public static byte[] pbeEncrypt(Key key, byte[] salt, byte[] content) {
        try {
            Cipher cipher = Cipher.getInstance(PBE_ALG);
            PBEParameterSpec pbeSpec = new PBEParameterSpec(salt, PBE_ITERATIONS);
            cipher.init(Cipher.ENCRYPT_MODE, key, pbeSpec);
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
    public static byte[] pbeDecrypt(Key key, byte[] salt, byte[] content) {
        try {
            Cipher cipher = Cipher.getInstance(PBE_ALG);
            PBEParameterSpec pbeSpec = new PBEParameterSpec(salt, PBE_ITERATIONS);
            cipher.init(Cipher.DECRYPT_MODE, key, pbeSpec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Could not decrypt content (pbe).");
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

    /**
     * Checks if signature is valid
     * @param pubKey the public key of the signature owner
     * @param content the content signed
     * @param sig the signature
     * @return if the signature is valid
     */
    public static boolean verifySignature(PublicKey pubKey, byte[] content, byte[] sig) {
        try {
            Signature signature = Signature.getInstance(SIG_CIPHERSUITE);
            signature.initVerify(pubKey);
            signature.update(content);
            return signature.verify(sig);
        } catch (Exception e) {
            System.out.println("Could not verify signature.");
            e.printStackTrace();
        }
        return false;
    }

    // ===== File Parsing Methods =====
    /**
     *
     * @param alias name of the alias
     * @param trstPassword the truststore password
     * @return the public key for that alias
     */
    public static PublicKey getPublicKeyFromTruststore(String alias, String trstPassword) {
        try {
            KeyStore truststore = KeyStore.getInstance(TRUSTSTORE_TYPE);
            String truststorePath = System.getProperty("javax.net.ssl.trustStore");
            truststore.load(new FileInputStream(truststorePath), trstPassword.toCharArray());
            Certificate cer = truststore.getCertificate(alias);
            return cer.getPublicKey();
        } catch (Exception e) {
            System.out.println("Could not retrieve public key from truststore.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     *
     * @param alias name of the alias
     * @param kstrPassword the keystore password
     * @return the private key for that alias
     */
    public static PrivateKey getPrivateKeyFromKeystore(String alias, String kstrPassword) {
        try {
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(new FileInputStream(System.getProperty("KEYSTORE_PATH")), kstrPassword.toCharArray());

            // Get the private key and certificate chain from the keystore
            Key key = keystore.getKey(alias, kstrPassword.toCharArray());
            if (key instanceof PrivateKey)
                return (PrivateKey) key;
        } catch (Exception e) {
            System.out.println("Could not retrieve private key from truststore.");
            e.printStackTrace();
        }
        return null;
    }

    public static PublicKey getPublicKeyFromCertificate(String alias, String certificatePath,
                                                        String keystorePassword){
        try {
            // Load the certificate file
            FileInputStream fis = new FileInputStream(certificatePath);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Certificate certificate = certificateFactory.generateCertificate(fis);
            fis.close();

            return certificate.getPublicKey();
        } catch (Exception e) {
            System.out.println("Could not retrieve public key from keystore.");
            e.printStackTrace();
        }
        return null;
    }
}
