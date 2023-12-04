package utils;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;

public class ServiceFilePackage {

    private final boolean isCorrupted;
    private String path;
    private String owner;
    private Instant creationTime;
    private String lastWriteUser;
    private Instant lastWriteTime;
    private String lastReadUser;
    private Instant lastReadTime;
    private byte[] content;

    public ServiceFilePackage(byte[] data) {
        this.isCorrupted = unpack(data);
    }

    private boolean unpack(byte[] data) {
        /* *
         * File -> { len + fileContent || len + SIGs(fileContent) }Kspriv
         * fileContent = { len + metadata || len + content }
         * metadata = { len + path || len + owner || len + TSCreation || len + lastChangedUser || len + TSLastChanged || len + lastReadUser || len + TSLastRead }
         * */
        Key key = CryptoStuff.parseSymKeyFromBase64(System.getProperty("PRIVATE_SYM_KEY"));
        byte[] contentDecrypted = CryptoStuff.symDecrypt(key, data);
        ByteBuffer bb = ByteBuffer.wrap(contentDecrypted);

        byte[] fileContent = MySSLUtils.getNextBytes(bb);
        byte[] signature = MySSLUtils.getNextBytes(bb);

        // Verify signature
        PublicKey pubKey = CryptoStuff.getPublicKeyFromCertificate("ss", System.getProperty("user.dir")+"/certs/ssCrypto/ss.cer","ss123456");
        if (!CryptoStuff.verifySignature(pubKey, fileContent, signature)) {
            System.out.println("Signature does not match in the file.");
            System.out.println("File is corrupted.");
            return true;
        }

        // Unpack
        bb = ByteBuffer.wrap(fileContent);
        byte[] metadata = MySSLUtils.getNextBytes(bb);
        byte[] content = MySSLUtils.getNextBytes(bb);

        bb= ByteBuffer.wrap(metadata);
        byte[] pathBytes = MySSLUtils.getNextBytes(bb);
        System.out.println("Path bytes: " + new String(pathBytes, StandardCharsets.UTF_8));
        byte[] ownerBytes = MySSLUtils.getNextBytes(bb);
        System.out.println("Owner Bytes: " + new String(ownerBytes, StandardCharsets.UTF_8));
        byte[] creationTimeBytes = MySSLUtils.getNextBytes(bb);
        byte[] lastWriteUserBytes = MySSLUtils.getNextBytes(bb);
        byte[] lastWriteTimeBytes = MySSLUtils.getNextBytes(bb);
        byte[] lastReadUserBytes = MySSLUtils.getNextBytes(bb);
        byte[] lastReadTimeBytes = MySSLUtils.getNextBytes(bb);

        // Write values
        this.path = new String(pathBytes, StandardCharsets.UTF_8);
        this.owner = new String(ownerBytes, StandardCharsets.UTF_8);
        this.creationTime = Instant.parse(new String(creationTimeBytes, StandardCharsets.UTF_8));
        this.lastWriteUser = new String(lastWriteUserBytes, StandardCharsets.UTF_8);
        this.lastWriteTime = Instant.parse(new String(lastWriteTimeBytes, StandardCharsets.UTF_8));
        this.lastReadUser = new String(lastReadUserBytes, StandardCharsets.UTF_8);
        this.lastReadTime = Instant.parse(new String(lastReadTimeBytes, StandardCharsets.UTF_8));
        this.content = content;

        // Not corrupted
        return false;
    }

    public byte[] getContent() {
        return content;
    }

    public String getOwner() {
        return owner;
    }

    public Instant getCreationTime() {
        return creationTime;
    }

    public String getLastWriteUser() {
        return lastWriteUser;
    }

    public Instant getLastWriteTime() {
        return lastWriteTime;
    }

    public String getLastReadUser() {
        return lastReadUser;
    }

    public Instant getLastReadTime() {
        return lastReadTime;
    }

    public String getPath() {
        return path;
    }

    public String getMetadata() {
        return String.format("Metadata -> [ name:%s, owner:%s, createTime:%s, lastEditUser:%s, lastEditTime:%s, lastReadUser:%s, lastReadTime:%s ]",
                path, owner, creationTime, lastWriteUser, lastWriteTime, lastReadUser, lastReadTime);
    }
    public static byte[] createFileBytes(byte[] content, String owner, String path) {
        /* *
         * File -> { len + fileContent || len + SIGs(fileContent) }Kspriv
         * fileContent = { len + metadata || len + content }
         * metadata = { len + path || len + owner || len + TSCreation || len + lastChangedUser || len + TSLastChanged || len + lastReadUser || len + TSLastRead }
         * */

        Instant now = Instant.now();
        // Metadata
        byte[] pathBytes = path.getBytes();
        byte[] ownerBytes = owner.getBytes();
        byte[] tsCreation = now.toString().getBytes();
        byte[] writeAuthorBytes = owner.getBytes(); // Changed
        byte[] tsLastChangedBytes = now.toString().getBytes();// Changed
        byte[] lastReadUserBytes = owner.getBytes();
        byte[] tsLastReadBytes = now.toString().getBytes();

        byte[] metadata = constructMetadata(pathBytes, ownerBytes, tsCreation, writeAuthorBytes, tsLastChangedBytes, lastReadUserBytes, tsLastReadBytes);

        // File Content
        byte[] fileContent = createFileContent(content, metadata);

        // Signature
        return signFileContentAndEncrypt(fileContent);
    }

    public static byte[] writeFileBytes(ServiceFilePackage oldFile, byte[] content, String writeAuthor) {
        /* *
         * File -> { len + fileContent || len + SIGs(fileContent) }Kspriv
         * fileContent = { len + metadata || len + content }
         * metadata = { len + path || len + owner || len + TSCreation || len + lastChangedUser || len + TSLastChanged || len + lastReadUser || len + TSLastRead }
         * */

        if (oldFile.isCorrupted) {
            System.out.println("File is corrupted");
            return null;
        }

        // Reconstruct metadata with modifications
        byte[] pathBytes = oldFile.getPath().getBytes();
        byte[] ownerBytes = oldFile.getOwner().getBytes();
        byte[] tsCreation = oldFile.getCreationTime().toString().getBytes();
        byte[] writeAuthorBytes = writeAuthor.getBytes(); // Changed
        byte[] tsLastChangedBytes = Instant.now().toString().getBytes(); // Changed
        byte[] lastReadUserBytes = Instant.now().toString().getBytes();
        byte[] tsLastReadBytes = Instant.now().toString().getBytes();

        byte[] metadata = constructMetadata(pathBytes, ownerBytes, tsCreation, writeAuthorBytes, tsLastChangedBytes, lastReadUserBytes, tsLastReadBytes);

        // Pack metadata with new content
        byte[] fileContent = createFileContent(content, metadata);

        // Signature
        return signFileContentAndEncrypt(fileContent);
    }

    public static byte[] readFileBytes(ServiceFilePackage oldFile, String readUser) {
        /* *
         * File -> { len + fileContent || len + SIGs(fileContent) }Kspriv
         * fileContent = { len + metadata || len + content }
         * metadata = { len + path || len + owner || len + TSCreation || len + lastChangedUser || len + TSLastChanged || len + lastReadUser || len + TSLastRead }
         * */

        if (oldFile.isCorrupted) {
            System.out.println("File is corrupted");
            return null;
        }

        // Reconstruct metadata with modifications
        byte[] pathBytes = oldFile.getPath().getBytes();
        byte[] ownerBytes = oldFile.getOwner().getBytes();
        byte[] tsCreation = oldFile.getCreationTime().toString().getBytes();
        byte[] writeAuthorBytes = oldFile.getLastWriteUser().getBytes();
        byte[] tsLastChangedBytes = oldFile.getLastWriteTime().toString().getBytes();
        byte[] lastReadUserBytes = readUser.getBytes(); // Changed
        byte[] tsLastReadBytes = Instant.now().toString().getBytes(); // Changed

        byte[] metadata = constructMetadata(pathBytes, ownerBytes, tsCreation, writeAuthorBytes, tsLastChangedBytes, lastReadUserBytes, tsLastReadBytes);

        // Pack metadata with old content
        byte[] fileContent = createFileContent(oldFile.getContent(), metadata);

        // Signature
        return signFileContentAndEncrypt(fileContent);
    }

    public static byte[] copyFileBytes(ServiceFilePackage oldFile, String copyAuthor, String newPath) {
        /* *
         * File -> { len + fileContent || len + SIGs(fileContent) }Kspriv
         * fileContent = { len + metadata || len + content }
         * metadata = { len + path || len + owner || len + TSCreation || len + lastChangedUser || len + TSLastChanged || len + lastReadUser || len + TSLastRead }
         * */

        if (oldFile.isCorrupted) {
            System.out.println("File is corrupted");
            return null;
        }

        return ServiceFilePackage.createFileBytes(oldFile.getContent(), copyAuthor, newPath);
    }

    // ===== AUX METHODS =====
    private static byte[] constructMetadata(byte[] pathBytes, byte[] ownerBytes, byte[] tsCreation,
                                            byte[] writeAuthorBytes, byte[] tsLastChangedBytes, byte[] lastReadUserBytes, byte[] tsLastReadBytes) {
        // metadata = { len + path || len + owner || len + TSCreation || len + lastChangedUser || len + TSLastChanged || len + lastReadUser || len + TSLastRead }
        byte[] metadata = new byte[7 * Integer.BYTES + pathBytes.length + ownerBytes.length + tsCreation.length
                + writeAuthorBytes.length + tsLastChangedBytes.length + lastReadUserBytes.length + tsLastReadBytes.length];
        ByteBuffer bb = ByteBuffer.wrap(metadata);
        MySSLUtils.putLengthAndBytes(bb, pathBytes, ownerBytes, tsCreation, writeAuthorBytes, tsLastChangedBytes,
                lastReadUserBytes, tsLastReadBytes);
        return metadata;
    }

    private static byte[] createFileContent(byte[] content, byte[] metadata) {
        byte[] fileContent = new byte[2 * Integer.BYTES + metadata.length + content.length];
        ByteBuffer bb = ByteBuffer.wrap(fileContent);
        MySSLUtils.putLengthAndBytes(bb, metadata, content);
        return fileContent;
    }

    private static byte[] signFileContentAndEncrypt(byte[] fileContent) {
        // File -> { len + fileContent || len + SIGs(fileContent) }Kspriv
        PrivateKey privKey = CryptoStuff.getPrivateKeyFromKeystore("ss", "ss123456");
        byte[] signature = CryptoStuff.sign(privKey, fileContent);

        // Encrypt and Pack
        byte[] fileAndSigBytes = createFileContent(signature, fileContent);

        Key key = CryptoStuff.parseSymKeyFromBase64(System.getProperty("PRIVATE_SYM_KEY"));
        return CryptoStuff.symEncrypt(key, fileAndSigBytes);
    }
}