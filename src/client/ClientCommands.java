package client;

import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.KeyAgreement;
import javax.net.ssl.SSLSocket;

import client.responseModels.LoginResponseModel;
import utils.Command;
import utils.CommonValues;
import utils.CryptoStuff;
import utils.MySSLUtils;
import utils.ResponsePackage;

public abstract class ClientCommands {
    public static void sum(SSLSocket socket) {
        // Input: { command(int) | length(int) | content(byte[]) }
        // content: {int}

        // Output: { code(int) | length(int) | content(byte[])}

        // ===== Build Content Input =====
        byte[] inputContent = new byte[Integer.BYTES];
        ByteBuffer bb = ByteBuffer.wrap(inputContent);

        bb.putInt(0, 5);

        // ===== Send Content =====
        byte[] dataOut = MySSLUtils.buildPackage(Command.SUM, inputContent);
        MySSLUtils.sendData(socket, dataOut);

        // ===== Receive Response =====
        byte[] dataIn = MySSLUtils.receiveData(socket);
        ResponsePackage rp = ResponsePackage.parse(dataIn);

        // ===== Unpack Response =====
        if (rp.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Error code received. Aborting...");
            return;
        }

        bb = ByteBuffer.wrap(rp.getContent());

        int result = bb.getInt(0);
        System.out.println("Result: " + result);
    }

    public static void mult(SSLSocket socket) {
        // Input: { command(int) | length(int) | content(byte[]) }
        // content: {int}

        // Output: { code(int) | length(int) | content(byte[])}

        // ===== Build Content Input =====
        byte[] inputContent = new byte[Integer.BYTES];
        ByteBuffer bb = ByteBuffer.wrap(inputContent);

        bb.putInt(0, 5);

        // ===== Send Content =====
        byte[] dataOut = MySSLUtils.buildPackage(Command.MULT, inputContent);
        MySSLUtils.sendData(socket, dataOut);

        // ===== Receive Response =====
        byte[] dataIn = MySSLUtils.receiveData(socket);
        ResponsePackage rp = ResponsePackage.parse(dataIn);

        // ===== Unpack Response =====
        if (rp.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Error code received. Aborting...");
            return;
        }

        bb = ByteBuffer.wrap(rp.getContent());

        int result = bb.getInt(0);
        System.out.println("Result: " + result);
    }

    public static LoginResponseModel login(SSLSocket socket, String cmd) {
        /**
        * Data flow:
        * Send-1 -> { len+uid }
        * Receive-1 -> { Secure Random (long) || len+Yauth }
        * Send-2 -> { len+Yclient || len+{ Secure Random }Kpwd }
        * Receive-2 -> { len+{ len+"auth" || len+Ktoken1024 || len+TSf || Secure Random (long) || len+Kclient,ac }Kdh || 
        * len+{ len+"auth" || len+Ktoken1024 || len+TSf || Secure Random (long) || len+Kclient,ac }SIGauth }
        */

        // ===== Send 1 =====
        // Send-1 -> { len+uid }
        String[] cmdArgs = cmd.split(" ");
        String uid = cmdArgs[1];
        String pwd = cmdArgs[2];

        byte[] uidBytes = uid.getBytes();

        byte[] dataToSend1 = new byte[Integer.BYTES + uidBytes.length];
        ByteBuffer bb = ByteBuffer.wrap(dataToSend1);

        int curIdx = 0;
        curIdx = MySSLUtils.putLengthAndBytes(bb, uidBytes, curIdx);

        MySSLUtils.sendData(socket, MySSLUtils.buildPackage(Command.LOGIN, dataToSend1));

        // ===== Receive 1 =====
        // Receive-1 -> { Secure Random (long) || len+Yauth }
        byte[] content = MySSLUtils.receiveData(socket);
        ResponsePackage rp = ResponsePackage.parse(content);
        byte[] dataReceived1 = rp.getContent();

        if (rp.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Could not do login (1)");
            return null;
        }

        bb = ByteBuffer.wrap(dataReceived1);

        // Unpack
        byte[] srBytes_r1 = new byte[Long.BYTES];

        curIdx = 0;

        bb.get(curIdx, srBytes_r1);
        curIdx += srBytes_r1.length;

        long sr_r1 = ByteBuffer.wrap(srBytes_r1).getLong();

        byte[] serverPublicKeyDHBytesR1 = MySSLUtils.getNextBytes(bb, curIdx);
        curIdx += Integer.BYTES + serverPublicKeyDHBytesR1.length;

        // Process
        KeyPair kp = CryptoStuff.dhGenerateKeyPair();
        byte[] dhSecret = CryptoStuff.dhGenerateSharedSecret(kp.getPrivate(), serverPublicKeyDHBytesR1);
        Key dhKey = CryptoStuff.dhCreateKeyFromSharedSecret(dhSecret);

        byte[] pubKeyClientBytes_R1 = kp.getPublic().getEncoded();

        String hash = CryptoStuff.hashB64(pwd);
        Key pbeKey_R1 = CryptoStuff.pbeCreateKeyFromPassword(hash);
        byte[] srEncryptedBytes_R1 = CryptoStuff.pbeEncrypt(pbeKey_R1, srBytes_r1);

        // ===== Send 2 =====
        // Send-2 -> { len+Yclient || len+{ Secure Random }Kpwd }
        byte[] dataToSend_S2 = new byte[2 * Integer.BYTES + pubKeyClientBytes_R1.length + srEncryptedBytes_R1.length];
        bb = ByteBuffer.wrap(dataToSend_S2);

        curIdx = 0;
        curIdx = MySSLUtils.putLengthAndBytes(bb, pubKeyClientBytes_R1, curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, srEncryptedBytes_R1, curIdx);

        MySSLUtils.sendData(socket, dataToSend_S2);

        // ===== Receive 2 =====
        // { len+{ len+"auth" || len+Ktoken1024 || len+TSf || Secure Random (long) || len+Kclient,ac }Kdh || 
        // len+{ len+"auth" || len+Ktoken1024 || len+TSf || Secure Random (long) || len+Kclient,ac }SIGauth }

        byte[] dataToReceive_R2 = MySSLUtils.receiveData(socket);
        rp = ResponsePackage.parse(dataToReceive_R2);

        if (rp.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Could not do login (2)");
            return null;
        }

        content = rp.getContent();
        bb = ByteBuffer.wrap(content);

        curIdx = 0;
        byte[] encryptedBytes_R2 = MySSLUtils.getNextBytes(bb, curIdx);
        curIdx += Integer.BYTES + encryptedBytes_R2.length;

        byte[] bytes_R2 = CryptoStuff.symDecrypt(dhKey, encryptedBytes_R2);

        byte[] signedBytes_R2 = MySSLUtils.getNextBytes(bb, curIdx);
        curIdx += Integer.BYTES + signedBytes_R2.length;

        PublicKey asPublicKey = CryptoStuff.getPublicKeyFromTruststore("as", "cl123456");

        if (!CryptoStuff.verifySignature(asPublicKey, bytes_R2, signedBytes_R2)) {
            System.out.println("Failed signature verification.");
            return null;
        }

        // Unpack
        bb = ByteBuffer.wrap(bytes_R2);

        curIdx = 0;

        byte[] asId_bytes = MySSLUtils.getNextBytes(bb, curIdx);
        curIdx += Integer.BYTES + asId_bytes.length;
        String asId = new String(asId_bytes, StandardCharsets.UTF_8);

        if (!asId.equals("auth")) {
            System.out.println("Auth Server ID not correct.");
            return null;
        }

        byte[] ktoken1024 = MySSLUtils.getNextBytes(bb, curIdx);
        curIdx += Integer.BYTES + ktoken1024.length;

        byte[] tsf = MySSLUtils.getNextBytes(bb, curIdx);
        curIdx += Integer.BYTES + tsf.length;

        long sr_r2 = bb.getLong(curIdx);
        curIdx += Long.BYTES;

        if (sr_r2 != sr_r1) {
            System.out.println("Secure Randoms do not match.");
            return null;
        }

        byte[] key_bytes = MySSLUtils.getNextBytes(bb, curIdx);
        curIdx += Integer.BYTES + key_bytes.length;

        LoginResponseModel lrm = LoginResponseModel.parse(ktoken1024, tsf, key_bytes);
        return lrm;
    }

    public static void stats(SSLSocket socket) {
        byte[] dataToSend = MySSLUtils.buildPackage(Command.STATS, new byte[0]);
        MySSLUtils.sendData(socket, dataToSend);

        byte[] received = MySSLUtils.receiveData(socket);
        ResponsePackage rp = ResponsePackage.parse(received);
        ByteBuffer bb = ByteBuffer.wrap(rp.getContent());

        int length = bb.getInt(0);
        System.out.println("Length: " + length);

        byte[] ipAddBytes = new byte[length];
        bb.get(Integer.BYTES, ipAddBytes);

        System.out.println("Ip: " + new String(ipAddBytes, StandardCharsets.UTF_8));
    }

    // ===== AUX METHODS =====
}