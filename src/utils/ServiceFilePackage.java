package utils;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.Arrays;

public class ServiceFilePackage {

    private static final byte[] IS_DIR = {0x0};
    private static final byte[] IS_FILE = {0x1};

    private byte[] content;
    private String owner;
    private Instant creation;
    private String lastWriteUser;
    private Instant lastWriteTime;
    private String lastReadUser;
    private Instant lastReadTime;
    private String path;
    private byte[] dir;
    private boolean isCorrupted;


    public ServiceFilePackage(byte[] content) {
        this.isCorrupted = unpack(content);
    }

    // {len+{ len + content || len + owner || len+TSCreation || len + lastChangedUser || len + TSLastChanged } || len+Ass(len + content || len + uidClient)}Kcpriv
    private boolean unpack(byte[] content) {
        Key key = CryptoStuff.parseSymKeyFromBase64(System.getProperty("PRIVATE_SYM_KEY"));
        byte[] contentDecrypted = CryptoStuff.symDecrypt(key, content);
        ByteBuffer bb = ByteBuffer.wrap(contentDecrypted);

        byte[] firstHalf = MySSLUtils.getNextBytes(bb);
        byte[] signature = MySSLUtils.getNextBytes(bb);
        bb = ByteBuffer.wrap(firstHalf);
        this.dir = MySSLUtils.getNextBytes(bb);
        this.path = new String(MySSLUtils.getNextBytes(bb), StandardCharsets.UTF_8);
        if (Arrays.equals(dir, IS_FILE)) this.content = MySSLUtils.getNextBytes(bb);
        this.owner = new String(MySSLUtils.getNextBytes(bb), StandardCharsets.UTF_8);
        this.creation = Instant.parse(new String(MySSLUtils.getNextBytes(bb), StandardCharsets.UTF_8));
        this.lastWriteUser = new String(MySSLUtils.getNextBytes(bb), StandardCharsets.UTF_8);
        this.lastWriteTime = Instant.parse(new String(MySSLUtils.getNextBytes(bb), StandardCharsets.UTF_8));
        this.lastReadUser = new String(MySSLUtils.getNextBytes(bb), StandardCharsets.UTF_8);
        this.lastReadTime = Instant.parse(new String(MySSLUtils.getNextBytes(bb), StandardCharsets.UTF_8));
        if (!CryptoStuff.verifySignature(CryptoStuff.getPublicKeyFromTruststore("ss", "ss123456"), firstHalf, signature)) {
            System.out.println("Signature does not match in the file");
            System.out.println("File is curropted");
            return true;
        }
        return false;
    }

    public byte[] getContent() {
        return content;
    }


    public String getOwner() {
        return owner;
    }


    public Instant getCreation() {
        return creation;
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

    public boolean isDir() {
        return Arrays.equals(this.dir, IS_DIR);
    }



    // { len + {  len + File Format || len+Ass() }Kspriv }
    // File Format -> {}
    // File Format -> { dir || len+ Path || len + content || len + owner || len+TSCreation || len + lastChangedUser || len + TSLastChanged ||
    //    len + LastReadUser || len + LastReadTS }
    // metadata: isDir, path, owner, TSCreation, lastChangedUser, TSLastChanged, lastReadUser, TSLastRead
    public static byte[] createFile(byte[] content, String owner, String path) {
        byte[] tsCreation = Instant.now().toString().getBytes();
        byte[] firstHalfFile = new byte[1 + 8 * Integer.BYTES + path.getBytes().length + content.length + 2 * owner.getBytes().length + 2 + tsCreation.length];
        ByteBuffer bb = ByteBuffer.wrap(firstHalfFile);
        MySSLUtils.putLengthAndBytes(bb, IS_FILE, path.getBytes(), content, owner.getBytes(), tsCreation, owner.getBytes(), tsCreation, new byte[0], new byte[0]);
        PrivateKey privKey = CryptoStuff.getPrivateKeyFromKeystore("ss", "ss123456");
        byte[] signature = CryptoStuff.sign(privKey, firstHalfFile);
        byte[] fullFile = new byte[2 * Integer.BYTES + firstHalfFile.length + signature.length];
        bb = ByteBuffer.wrap(fullFile);
        MySSLUtils.putLengthAndBytes(bb, firstHalfFile, signature);

        Key key = CryptoStuff.parseSymKeyFromBase64(System.getProperty("PRIVATE_SYM_KEY"));
        return CryptoStuff.symEncrypt(key, fullFile);
    }

    // { len + { len + File Format || len+Ass() }Kspriv }
    //File Format -> { len + content || len + owner || len+TSCreation || len + lastChangedUser || len + TSLastChanged ||
    //    len + LastReadUser || len + LastReadTS }
    public static byte[] writeFile(ServiceFilePackage oldfile, byte[] content, String whoWrote) {
        if (oldfile.isCorrupted) {
            System.out.println("File is corrputed");
            return null;
        }
        byte[] tsChange = Instant.now().toString().getBytes();
        byte[] firstHalfFile = new byte[1 + 8 * Integer.BYTES + oldfile.getPath().getBytes().length + oldfile.content.length + oldfile.getOwner().getBytes().length + oldfile.getCreation().toString().getBytes().length +
                whoWrote.getBytes().length + tsChange.length + oldfile.getLastReadUser().getBytes().length + oldfile.getLastReadTime().toString().getBytes().length];

        ByteBuffer bb = ByteBuffer.wrap(firstHalfFile);
        MySSLUtils.putLengthAndBytes(bb, IS_FILE, oldfile.getPath().getBytes(), content, oldfile.owner.getBytes(), oldfile.owner.getBytes(), whoWrote.getBytes(), tsChange, oldfile.getLastReadUser().getBytes(),
                oldfile.getLastReadTime().toString().getBytes());
        byte[] signature = CryptoStuff.sign(CryptoStuff.getPrivateKeyFromKeystore("ss", "ss123456"), firstHalfFile);
        byte[] fullFile = new byte[2 * Integer.BYTES + firstHalfFile.length + signature.length];
        bb = ByteBuffer.wrap(fullFile);

        MySSLUtils.putLengthAndBytes(bb, firstHalfFile, signature);
        Key key = CryptoStuff.parseSymKeyFromBase64(System.getProperty("PRIVATE_SYM_KEY"));
        return CryptoStuff.symEncrypt(key, fullFile);
    }

    // { len + { len + File Format || len+Ass() }Kspriv }
    //File Format -> { len + content || len + owner || len+TSCreation || len + lastChangedUser || len + TSLastChanged ||
    //    len + LastReadUser || len + LastReadTS }
    public static byte[] readFile(ServiceFilePackage oldfile, String whoRead) {
        if (oldfile.isCorrupted) {
            System.out.println("File is corrputed");
            return null;
        }
        byte[] tsRead = Instant.now().toString().getBytes();
        byte[] firstHalfFile = new byte[1 + 8 * Integer.BYTES + oldfile.getContent().length + oldfile.getOwner().getBytes().length + oldfile.getCreation().toString().getBytes().length +
                oldfile.getLastWriteUser().getBytes().length + oldfile.getLastWriteTime().toString().getBytes().length + whoRead.getBytes().length + tsRead.length];
        ByteBuffer bb = ByteBuffer.wrap(firstHalfFile);
        MySSLUtils.putLengthAndBytes(bb, IS_FILE, oldfile.getPath().getBytes(), oldfile.getContent(), oldfile.owner.getBytes(), oldfile.owner.getBytes(), oldfile.getLastWriteUser().getBytes(), oldfile.getLastWriteTime().toString().getBytes(), whoRead.getBytes(),
                tsRead);
        byte[] signature = CryptoStuff.sign(CryptoStuff.getPrivateKeyFromKeystore("ss", "ss123456"), firstHalfFile);
        byte[] fullFile = new byte[2 * Integer.BYTES + firstHalfFile.length + signature.length];
        bb = ByteBuffer.wrap(fullFile);
        byte[] fullFileEncrypted;
        MySSLUtils.putLengthAndBytes(bb, firstHalfFile, signature);
        Key key = CryptoStuff.parseSymKeyFromBase64(System.getProperty("PRIVATE_SYM_KEY"));
        fullFileEncrypted = CryptoStuff.symEncrypt(key, fullFile);
        return fullFileEncrypted;
    }

   /* public static byte[] createDir(String owner,String path) {
        byte[] tsCreation = Instant.now().toString().getBytes();
        byte[] firstHalfFile = new byte[ 1+ 7 * Integer.BYTES +path.getBytes().length+ 2 * owner.getBytes().length + 2 + tsCreation.length];
        ByteBuffer bb = ByteBuffer.wrap(firstHalfFile);
        MySSLUtils.putLengthAndBytes(bb,  IS_DIR,path.getBytes(),owner.getBytes(), tsCreation, owner.getBytes(), tsCreation, new byte[0], new byte[0]);
        PrivateKey privKey = CryptoStuff.getPrivateKeyFromKeystore("ss", "ss123456");
        byte[] signature = CryptoStuff.sign(privKey, firstHalfFile);
        byte[] fullFile = new byte[2 * Integer.BYTES + firstHalfFile.length + signature.length];
        bb = ByteBuffer.wrap(fullFile);
        MySSLUtils.putLengthAndBytes(bb, firstHalfFile, signature);
        Key key = CryptoStuff.parseSymKeyFromBase64(System.getProperty("PRIVATE_SYM_KEY"));
        return CryptoStuff.symEncrypt(key, fullFile);
    }*/

    public static byte[] copyFile(ServiceFilePackage oldfile, String newPath) {
        if (oldfile.isCorrupted) {
            System.out.println("File is corrputed");
            return null;
        }
        byte[] firstHalfFile = new byte[1 + 8 * Integer.BYTES + newPath.getBytes().length + oldfile.content.length + oldfile.getOwner().getBytes().length + oldfile.getCreation().toString().getBytes().length +
                oldfile.getLastWriteUser().getBytes().length + oldfile.getLastWriteTime().toString().getBytes().length + oldfile.getLastReadUser().getBytes().length + oldfile.getLastReadTime().toString().getBytes().length];

        ByteBuffer bb = ByteBuffer.wrap(firstHalfFile);
        MySSLUtils.putLengthAndBytes(bb, IS_FILE, oldfile.getPath().getBytes(), oldfile.content, oldfile.owner.getBytes(), oldfile.owner.getBytes(), oldfile.getLastWriteUser().getBytes(),
                oldfile.getLastWriteTime().toString().getBytes(), oldfile.getLastReadUser().getBytes(),
                oldfile.getLastReadTime().toString().getBytes());
        byte[] signature = CryptoStuff.sign(CryptoStuff.getPrivateKeyFromKeystore("ss", "ss123456"), firstHalfFile);
        byte[] fullFile = new byte[2 * Integer.BYTES + firstHalfFile.length + signature.length];
        bb = ByteBuffer.wrap(fullFile);
        MySSLUtils.putLengthAndBytes(bb, firstHalfFile, signature);
        Key key = CryptoStuff.parseSymKeyFromBase64(System.getProperty("PRIVATE_SYM_KEY"));
        return CryptoStuff.symEncrypt(key, fullFile);
    }
}