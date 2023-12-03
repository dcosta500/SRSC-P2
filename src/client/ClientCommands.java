package client;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Instant;
import javax.net.ssl.SSLSocket;

import client.responseModels.AccessResponseModel;
import client.responseModels.LoginResponseModel;
import client.responseModels.MakedirResponseModel;
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
        /* *
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

        MySSLUtils.putLengthAndBytes(bb, uidBytes);

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

        bb.get(srBytes_r1);

        long sr_r1 = ByteBuffer.wrap(srBytes_r1).getLong();

        byte[] serverPublicKeyDHBytesR1 = MySSLUtils.getNextBytes(bb);

        // Process
        KeyPair kp = CryptoStuff.dhGenerateKeyPair();
        assert kp != null;
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

        MySSLUtils.putLengthAndBytes(bb, pubKeyClientBytes_R1, srEncryptedBytes_R1);

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

        byte[] encryptedBytes_R2 = MySSLUtils.getNextBytes(bb);

        byte[] bytes_R2 = CryptoStuff.symDecrypt(dhKey, encryptedBytes_R2);

        byte[] signedBytes_R2 = MySSLUtils.getNextBytes(bb);

        PublicKey asPublicKey = CryptoStuff.getPublicKeyFromTruststore("as", "cl123456");

        if (!CryptoStuff.verifySignature(asPublicKey, bytes_R2, signedBytes_R2)) {
            System.out.println("Failed signature verification.");
            return null;
        }

        // Unpack
        bb = ByteBuffer.wrap(bytes_R2);

        byte[] asId_bytes = MySSLUtils.getNextBytes(bb);
        String asId = new String(asId_bytes, StandardCharsets.UTF_8);

        if (!asId.equals("auth")) {
            System.out.println("Auth Server ID not correct.");
            return null;
        }

        byte[] ktoken1024 = MySSLUtils.getNextBytes(bb);

        byte[] tsf = MySSLUtils.getNextBytes(bb);

        long sr_r2 = bb.getLong();

        if (sr_r2 != sr_r1) {
            System.out.println("Secure Randoms do not match.");
            return null;
        }

        byte[] key_bytes = MySSLUtils.getNextBytes(bb);

        return LoginResponseModel.parse(uid, ktoken1024, tsf, key_bytes);
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

    public static MakedirResponseModel mkdir(SSLSocket socket, byte[] auth_ktoken1024, AccessResponseModel arm, Key client_auth_key, String uid, String cmdArgs) {
        String response = executeReadCommand(socket, auth_ktoken1024, arm, client_auth_key, uid, cmdArgs);
        return new MakedirResponseModel(response);
    }

    // ===== AUX METHODS =====
    private static AccessResponseModel access(SSLSocket socket, byte[] auth_ktoken1024, Key client_auth_key, String uid) {
        /* *
         * Data flow:
         * Send-1-> { len+IdService || len+token1024 || len+AuthClient}
         * AuthClient = {len+IdClient || len+ IpClient || len+TS || NOUNCE}Kc,AC
         * Receive-1 -> { len+Kc,service || len+IdService || len+TSf || len+KvToken }Kc,ac
         */

        // ===== Send-1 =====
        // { len+IdServiço || len+token1024 || len+AuthClient}
        // AuthClient = {len+IdClient || len+ IpClient || len+TS || NOUNCE}Kc,AC

        //Creating of Auth Client encrypted with Access control key
        byte[] serviceIDbytes = CommonValues.STORAGE_SERVICE_ID.getBytes();
        byte[] clientAuthenticator = createClientAuthenticator(uid, client_auth_key);

        byte[] dataToSend1 = new byte[Integer.BYTES + serviceIDbytes.length + Integer.BYTES + auth_ktoken1024.length
                + Integer.BYTES + clientAuthenticator.length];

        ByteBuffer bb = ByteBuffer.wrap(dataToSend1);

        MySSLUtils.putLengthAndBytes(bb, serviceIDbytes, auth_ktoken1024, clientAuthenticator);

        MySSLUtils.sendData(socket, MySSLUtils.buildPackage(Command.ACCESS, dataToSend1));

        // ===== Receive-1 =====
        // { len+Kc,service || len+IdService || len+TSf || len+KvToken }Kc,ac

        byte[] dataToReceive_R1 = MySSLUtils.receiveData(socket);
        ResponsePackage rp = ResponsePackage.parse(dataToReceive_R1);

        if (rp.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Could not do access");
            return null;
        }

        byte[] content = CryptoStuff.symDecrypt(client_auth_key, rp.getContent());

        //  Kvtoken = { len + { len + kvtoken_content || len + SIGac( kvtoken_content ) } Kac,s }
        //  kvtoken_content = { len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms }

        bb = ByteBuffer.wrap(content);
        byte[] key_c_service = MySSLUtils.getNextBytes(bb); // erroring
        byte[] serviceId_check = MySSLUtils.getNextBytes(bb);
        byte[] timestamp_final = MySSLUtils.getNextBytes(bb);
        byte[] kvToken = MySSLUtils.getNextBytes(bb);

        return AccessResponseModel.parse(key_c_service, serviceId_check, timestamp_final, kvToken);
    }

    private static String executeReadCommand(SSLSocket socket, byte[] auth_ktoken1024, AccessResponseModel arm, Key client_auth_key, String uid, String cmdArgs){
        /* Data Flow:
         * Send-1 -> { len + IDservice || len + Ktoken1024 || len + AUTHclient1 }
         * Receive-1 -> { len + Kc,s || len + IDservice || len + TSf || len + Kvtoken }Kc,Ac
         *
         * Send-2 -> { len + Kvtoken || len + AUTHclient2 || R (long) }
         * Receive-2 -> { len + { R }Kc,s }
         * Send-3 -> { len + { len + arguments || Nonce }Kc,s }
         * Receive-3 -> { len + { len + response || Nonce }Kc,s }
         *
         * AuthClient1 = { len + { len + IDClient || len + TS || Nonce }Kc,ac }
         * AuthClient2 = { len + { len + IDClient || len + TS || Nonce }Kc,s }
         *
         * Kvtoken = { len + { len + kvtoken_content || len + SIGac( kvtoken_content ) } Kac,s }
         * kvtoken_content = { len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms }
         */

        // ===== ACCESS =====
        if (arm == null)
            arm = access(socket, auth_ktoken1024, client_auth_key, uid);

        if (arm == null) {
            System.out.println("Could not retrieve from Access Control");
            return null;
        }

        // ===== AUTHENTICATE SERVICE =====
        if (!authenticateService(socket, arm, client_auth_key, uid)) {
            System.out.println("Could not authenticate service server.");
            return null;
        }

        // ===== SEND 3 =====
        //{ len + { len + arguments || Nonce }Kc,s }
        long nonce = CryptoStuff.getRandom();
        sendArguments(socket, arm, cmdArgs, nonce);

        // ===== RECEIVE 3 =====
        // Receive-3 -> { len +  { len + response || Nonce }Kc,s }
        return receiveResponse(socket, arm, nonce);
    }

    private static void sendArguments(SSLSocket socket, AccessResponseModel arm, String cmdArgs, long nonce) {
        // mkdir username path
        // ["mkdir", "username path"]
        String[] cmdArgsNoCommand = cmdArgs.split(" ", 1);
        String[] arguments = cmdArgsNoCommand[1].split(" ");

        int argNonceSize = 0;
        for (String arg : arguments) {
            argNonceSize += Integer.BYTES + arg.getBytes().length;
        }
        argNonceSize += Long.BYTES;

        byte[] argNonce = new byte[argNonceSize];
        ByteBuffer bb = ByteBuffer.wrap(argNonce);

        for (String arg : arguments) {
            MySSLUtils.putLengthAndBytes(bb, arg.getBytes());
        }
        bb.putLong(nonce);

        byte[] argNonceEncrypted = CryptoStuff.symEncrypt(arm.clientService_key, argNonce);

        byte[] dataToSend3 = new byte[Integer.BYTES + argNonceEncrypted.length];
        bb = ByteBuffer.wrap(dataToSend3);

        MySSLUtils.putLengthAndBytes(bb, argNonceEncrypted);
        MySSLUtils.sendData(socket, dataToSend3);
    }

    private static String receiveResponse(SSLSocket socket, AccessResponseModel arm, long nonce) {
        byte[] receivedPayload3 = MySSLUtils.receiveData(socket);
        ResponsePackage rp3 = ResponsePackage.parse(receivedPayload3);

        if (rp3.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Error 3");
            return null;
        }

        byte[] content3 = rp3.getContent();
        ByteBuffer bb = ByteBuffer.wrap(content3);

        byte[] encryptedResponseNonce = MySSLUtils.getNextBytes(bb);
        byte[] responseNonceDecrypted = CryptoStuff.symDecrypt(arm.clientService_key, encryptedResponseNonce);

        bb = ByteBuffer.wrap(responseNonceDecrypted);
        byte[] responseBytes2 = MySSLUtils.getNextBytes(bb);
        long nonce2 = bb.getLong();

        if (nonce != nonce2) {
            System.out.println("Nonce don't match");
            return null;
        }

        return new String(responseBytes2, StandardCharsets.UTF_8);
    }

    private static boolean authenticateService(SSLSocket socket, AccessResponseModel arm, Key client_auth_key, String uid) {
        // ===== SEND 2 =====
        // { len + Kvtoken || len + AUTHclient2 || R (long) }
        byte[] clientAuth2 = createClientAuthenticator(uid, client_auth_key);
        long rChallenge = CryptoStuff.getRandom();
        byte[] dataToSend2 = new byte[2 * Integer.BYTES + arm.kvtoken.length + clientAuth2.length + Long.BYTES];

        ByteBuffer bb = ByteBuffer.wrap(dataToSend2);

        MySSLUtils.putLengthAndBytes(bb, arm.kvtoken, clientAuth2);
        bb.putLong(rChallenge);

        byte[] payload2 = MySSLUtils.buildPackage(Command.MKDIR, dataToSend2);
        MySSLUtils.sendData(socket, payload2);

        // ===== RECEIVE 2 =====
        // { len + { R }Kc,s }
        byte[] receivedPayload2 = MySSLUtils.receiveData(socket);
        ResponsePackage rp = ResponsePackage.parse(receivedPayload2);

        if (rp.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Error 1");
            return false;
        }

        byte[] content = rp.getContent();
        bb = ByteBuffer.wrap(content);

        byte[] rChallengeResponse = MySSLUtils.getNextBytes(bb);
        byte[] rChallengeResponseDecrypted = CryptoStuff.symDecrypt(arm.clientService_key, rChallengeResponse);

        bb = ByteBuffer.wrap(rChallengeResponseDecrypted);
        long rChallengeResponseLong = bb.getLong();

        if (rChallengeResponseLong != rChallenge) {
            System.out.println("Service could not respond to challenge");
            return false;
        }

        return true;
    }

    private static byte[] createClientAuthenticator(String uid, Key client_auth_key) {
        try {
            long nonce = CryptoStuff.getRandom();
            byte[] uid_bytes = uid.getBytes();
            byte[] instant_bytes = Instant.now().toString().getBytes();

            byte[] auth_Client = new byte[2 * Integer.BYTES + uid_bytes.length + instant_bytes.length
                    + Long.BYTES];

            ByteBuffer bb = ByteBuffer.wrap(auth_Client);

            MySSLUtils.putLengthAndBytes(bb, uid_bytes, instant_bytes);
            bb.putLong(nonce);

            return CryptoStuff.symEncrypt(client_auth_key, auth_Client);
        } catch (Exception e) {
            System.out.println("Could not create client's authenticator.");
            e.printStackTrace();
        }
        return new byte[0];
    }
}