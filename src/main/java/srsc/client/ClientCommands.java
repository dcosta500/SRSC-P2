package srsc.client;

import srsc.client.responseModels.*;
import srsc.utils.*;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Instant;

public abstract class ClientCommands {
    private static final String DEFAULT_PUT_DIR = System.getProperty("user.dir") + "/clientFiles/putRoot/";
    private static final String DEFAULT_GET_DIR = System.getProperty("user.dir") + "/clientFiles/getRoot/";

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
        byte[] dataReceived1 = rp.content();

        if (rp.code() == CommonValues.ERROR_CODE) {
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

        if (rp.code() == CommonValues.ERROR_CODE) {
            System.out.println("Could not do login (2)");
            return null;
        }

        content = rp.content();
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

    public static CommandResponseModel mkdir(SSLSocket socket, byte[] auth_ktoken1024, Key client_auth_key, String uid, String cmdArgs) {
        byte[] response = executeCommand(Command.MKDIR, socket, auth_ktoken1024, client_auth_key, uid, cmdArgs, false);
        return response == null ? null: new CommandResponseModel(new String(response, StandardCharsets.UTF_8));
    }

    public static CommandResponseModel put(SSLSocket socket, byte[] auth_ktoken1024, Key client_auth_key, String uid, String cmdArgs) {
        byte[] response = executeCommand(Command.PUT, socket, auth_ktoken1024, client_auth_key, uid, cmdArgs, true);
        return response == null ? null: new CommandResponseModel(new String(response, StandardCharsets.UTF_8));
    }

    public static CommandResponseModel get(SSLSocket socket, byte[] auth_ktoken1024, Key client_auth_key, String uid, String cmdArgs) {
        byte[] response = executeCommand(Command.GET, socket, auth_ktoken1024, client_auth_key, uid, cmdArgs, false);

        if(response == null || !writeFromGet(response, cmdArgs))
            return null;

        return new CommandResponseModel("Successfully download file.");
    }

    public static CommandResponseModel list(SSLSocket socket, byte[] auth_ktoken1024, Key client_auth_key, String uid, String cmdArgs) {
        byte[] response = executeCommand(Command.LIST, socket, auth_ktoken1024, client_auth_key, uid, cmdArgs, false);
        return response == null ? null: new CommandResponseModel(new String(response, StandardCharsets.UTF_8));
    }

    public static CommandResponseModel remove(SSLSocket socket, byte[] auth_ktoken1024, Key client_auth_key, String uid, String cmdArgs) {
        byte[] response = executeCommand(Command.REMOVE, socket, auth_ktoken1024, client_auth_key, uid, cmdArgs, false);
        return response == null ? null: new CommandResponseModel(new String(response, StandardCharsets.UTF_8));
    }

    public static CommandResponseModel file(SSLSocket socket, byte[] auth_ktoken1024, Key client_auth_key, String uid, String cmdArgs) {
        byte[] response = executeCommand(Command.FILE, socket, auth_ktoken1024, client_auth_key, uid, cmdArgs, false);
        return response == null ? null: new CommandResponseModel(new String(response, StandardCharsets.UTF_8));
    }

    public static CommandResponseModel copy(SSLSocket socket, byte[] auth_ktoken1024, Key client_auth_key, String uid, String cmdArgs) {
        byte[] response = executeCommand(Command.COPY, socket, auth_ktoken1024, client_auth_key, uid, cmdArgs, false);
        return response == null ? null: new CommandResponseModel(new String(response, StandardCharsets.UTF_8));
    }

    // ===== AUX METHODS =====
    private static AccessResponseModel access(SSLSocket socket, byte[] auth_ktoken1024, Key client_auth_key, String uid) {
        /* *
         * Data flow:
         * Send-1-> { len+IdService || len+token1024 || len+AuthClient}
         * AuthClient = {len+IdClient || len+ IpClient || len+TS || NOUNCE}Kc,AC
         * Receive-1 -> { len+Kc,service || len+IdService || len+TSf || len+KvToken }Kc,ac
         *
         * Ktoken1024 = { len + Ktoken1024_content || len + { Ktoken1024_content }SIGauth }Kauth,ac
         * Ktoken1024_content = { len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }
         */

        // ===== Send-1 =====
        // { len+IdServiço || len+token1024 || len+AuthClient}
        // AuthClient = {len+IdClient || len+ IpClient || len+TS || NOUNCE}Kc,AC

        // Creating of Auth Client encrypted with Access control key
        byte[] serviceIDbytes = CommonValues.STORAGE_SERVICE_ID.getBytes();
        byte[] clientAuthenticator = createClientAuthenticator(uid, client_auth_key);

        byte[] dataToSend1 = new byte[3 * Integer.BYTES + serviceIDbytes.length + auth_ktoken1024.length + clientAuthenticator.length];

        ByteBuffer bb = ByteBuffer.wrap(dataToSend1);

        MySSLUtils.putLengthAndBytes(bb, serviceIDbytes, auth_ktoken1024, clientAuthenticator);

        byte[] payloadToSend = MySSLUtils.buildPackage(Command.ACCESS, dataToSend1);
        MySSLUtils.sendData(socket, payloadToSend);


        // ===== Receive-1 =====
        // { len+Kc,service || len+IdService || len+TSf || len+KvToken }Kc,ac
        byte[] dataToReceive_R1 = MySSLUtils.receiveData(socket);
        ResponsePackage rp = ResponsePackage.parse(dataToReceive_R1);

        if (rp.code() == CommonValues.ERROR_CODE) {
            System.out.println("Could not do access control.");
            return null;
        }

        byte[] content = CryptoStuff.symDecrypt(client_auth_key, rp.content());

        //  Kvtoken = { len + { len + kvtoken_content || len + SIGac( kvtoken_content ) } Kac,s }
        //  kvtoken_content = { len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms }

        bb = ByteBuffer.wrap(content);
        byte[] key_c_service = MySSLUtils.getNextBytes(bb); // erroring
        byte[] serviceId_check = MySSLUtils.getNextBytes(bb);
        byte[] timestamp_final = MySSLUtils.getNextBytes(bb);
        byte[] kvToken = MySSLUtils.getNextBytes(bb);

        return AccessResponseModel.parse(key_c_service, serviceId_check, timestamp_final, kvToken);
    }

    private static boolean writeFromGet(byte[] content, String cmdArgs) {
        String[] args = cmdArgs.split(" ");
        Path pathToFile = Paths.get(DEFAULT_GET_DIR).resolve(args[1]).resolve(args[2]);
        try {
            Files.createDirectories(pathToFile.getParent());
            Files.write(pathToFile, content, StandardOpenOption.CREATE);
        } catch (Exception e) {
            System.out.println("Error writing file.");
            return false;
        }
        return true;
    }

    private static byte[] executeCommand(Command command, SSLSocket socket, byte[] auth_ktoken1024, Key client_auth_key,
                                         String uid, String cmdArgs, boolean willSendFiles) {
        /* Data Flow:
         * Send-1 -> { len + IDservice || len + Ktoken1024 || len + AUTHclient1 }
         * Receive-1 -> { len + Kc,s || len + IDservice || len + TSf || len + Kvtoken }Kc,Ac
         *
         * Send-2 -> { len + Kvtoken || len + AUTHclient2 || R (long) }
         * Receive-2 -> { { R }Kc,s }
         * Send-3 -> { len + { len + arguments || Nonce }Kc,s }
         * Receive-3 -> { len + { len + response || Nonce }Kc,s }
         *
         * AuthClient1 = { len + { len + IDClient || len + TS || Nonce }Kc,ac }
         * AuthClient2 = { len + { len + IDClient || len + TS || Nonce }Kc,s }
         *
         * Kvtoken = { len + { len + kvtoken_content || len + SIGac( kvtoken_content ) } Kac,s }
         * kvtoken_content = { len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms }
         *
         * Ktoken1024 = { len + Ktoken1024_content || len + { Ktoken1024_content }SIGauth }Kauth,ac
         * Ktoken1024_content = { len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }
         */

        // ===== ACCESS =====
        if (ClientTokens.arm == null) {
            SSLSocket acSocket = startConnectionToMDServer();
            ClientTokens.arm = access(acSocket, auth_ktoken1024, client_auth_key, uid);
            MySSLUtils.closeConnectionToServer(acSocket);
        }

        if (ClientTokens.arm == null) {
            return null;
        }

        // ===== AUTHENTICATE SERVICE =====
        if (!authenticateService(command, socket, ClientTokens.arm.clientService_key, uid)) {
            System.out.println("Could not authenticate service server.");
            return null;
        }

        // ===== SEND 3 =====
        //{ len + { len + arguments || Nonce }Kc,s }
        long nonce = CryptoStuff.getRandom();
        if(willSendFiles){
            String[] args = cmdArgs.split(" ");

            //==== Prepare file to send ====
            Path pathToFile = Paths.get(DEFAULT_PUT_DIR).resolve(uid).resolve(args[2]);
            byte[] sendFile;
            try {
                sendFile = Files.readAllBytes(pathToFile);
            } catch (Exception e) {
                System.out.println("Could not send file.");
                return null;
            }
            sendFileAndArguments(socket, ClientTokens.arm, cmdArgs, nonce, sendFile);
        }
        else{
            sendArguments(socket, ClientTokens.arm, cmdArgs, nonce);
        }

        // ===== RECEIVE 3 =====
        // Receive-3 -> { len +  { len + response || Nonce }Kc,s }
        return receiveResponse(socket, nonce);
    }

    private static void sendFileAndArguments(SSLSocket socket, AccessResponseModel arm, String cmdArgs, long nonce, byte[] file) {
        // mkdir username path
        // ["mkdir", "username path"]
        String[] cmdArgsNoCommand = cmdArgs.split(" ", 2);
        String[] arguments = cmdArgsNoCommand[1].split(" ");

        int argNonceSize = 0;
        for (String arg : arguments) {
            argNonceSize += Integer.BYTES + arg.getBytes().length;
        }
        argNonceSize += Integer.BYTES + file.length;
        argNonceSize += Long.BYTES;

        byte[] argNonce = new byte[argNonceSize];
        ByteBuffer bb = ByteBuffer.wrap(argNonce);

        for (String arg : arguments) {
            MySSLUtils.putLengthAndBytes(bb, arg.getBytes());
        }
        bb.putLong(nonce);
        MySSLUtils.putLengthAndBytes(bb, file);

        byte[] argNonceEncrypted = CryptoStuff.symEncrypt(arm.clientService_key, argNonce);

        byte[] dataToSend3 = new byte[Integer.BYTES + argNonceEncrypted.length];
        bb = ByteBuffer.wrap(dataToSend3);

        MySSLUtils.putLengthAndBytes(bb, argNonceEncrypted);
        MySSLUtils.sendData(socket, dataToSend3);
    }

    private static void sendArguments(SSLSocket socket, AccessResponseModel arm, String cmdArgs, long nonce) {
        // mkdir username path
        // ["mkdir", "username path"]
        String[] cmdArgsNoCommand = cmdArgs.split(" ", 2);
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

    private static byte[] receiveResponse(SSLSocket socket, long nonce) {
        byte[] receivedPayload3 = MySSLUtils.receiveData(socket);
        ResponsePackage rp3 = ResponsePackage.parse(receivedPayload3);

        if (rp3.code() == CommonValues.ERROR_CODE) {
            //System.out.println("Error retrieving response.");
            return null;
        }

        byte[] content3 = rp3.content();
        ByteBuffer bb = ByteBuffer.wrap(content3);

        byte[] encryptedResponseNonce = MySSLUtils.getNextBytes(bb);
        byte[] responseNonceDecrypted = CryptoStuff.symDecrypt(ClientTokens.arm.clientService_key, encryptedResponseNonce);

        bb = ByteBuffer.wrap(responseNonceDecrypted);
        byte[] responseBytes2 = MySSLUtils.getNextBytes(bb);
        long nonce2 = bb.getLong();

        if (nonce != nonce2) {
            //System.out.println("Could not .");
            return null;
        }

        return responseBytes2;
    }

    private static boolean authenticateService(Command command, SSLSocket socket, Key client_service_key, String uid) {
        // ===== SEND 2 =====
        // { len + Kvtoken || len + AUTHclient2 || R (long) }
        byte[] clientAuth2 = createClientAuthenticator(uid, client_service_key);
        long rChallenge = CryptoStuff.getRandom();
        byte[] dataToSend2 = new byte[2 * Integer.BYTES + ClientTokens.arm.kvtoken.length + clientAuth2.length + Long.BYTES];

        ByteBuffer bb = ByteBuffer.wrap(dataToSend2);

        MySSLUtils.putLengthAndBytes(bb, ClientTokens.arm.kvtoken, clientAuth2);
        bb.putLong(rChallenge);

        byte[] payload2 = MySSLUtils.buildPackage(command, dataToSend2);
        MySSLUtils.sendData(socket, payload2);

        // ===== RECEIVE 2 =====
        // { { R }Kc,s }
        byte[] receivedPayload2 = MySSLUtils.receiveData(socket);
        ResponsePackage rp = ResponsePackage.parse(receivedPayload2);

        if (rp.code() == CommonValues.ERROR_CODE) {
            System.out.println("Error authenticating service.");
            return false;
        }

        byte[] rChallengeResponseDecrypted = CryptoStuff.symDecrypt(ClientTokens.arm.clientService_key, rp.content());

        bb = ByteBuffer.wrap(rChallengeResponseDecrypted);
        long rChallengeResponseLong = bb.getLong();
        if (rChallengeResponseLong != rChallenge) {
            //System.out.println("Service could not respond to challenge");
            return false;
        }

        return true;
    }

    private static byte[] createClientAuthenticator(String uid, Key key) {
        try {
            long nonce = CryptoStuff.getRandom();
            byte[] uid_bytes = uid.getBytes();
            byte[] instant_bytes = Instant.now().toString().getBytes();

            byte[] auth_Client = new byte[2 * Integer.BYTES + uid_bytes.length + instant_bytes.length + Long.BYTES];

            ByteBuffer bb = ByteBuffer.wrap(auth_Client);

            MySSLUtils.putLengthAndBytes(bb, uid_bytes, instant_bytes);
            bb.putLong(nonce);
            return CryptoStuff.symEncrypt(key, auth_Client);
        } catch (Exception e) {
            System.out.println("Could not create client's authenticator.");
            e.printStackTrace();
        }
        return new byte[0];
    }

    private static SSLSocket startConnectionToMDServer() {
        String keystorePath = String.format("certs/clients/%sCrypto/keystore_%s_cl.jks", ClientTokens.lrm.username, ClientTokens.lrm.username);
        SSLSocketFactory factory = MySSLUtils.createClientSocketFactory(keystorePath, "cl123456");
        SSLSocket socket = MySSLUtils.startNewConnectionToServer(factory, CommonValues.MD_HOSTNAME, CommonValues.MD_PORT_NUMBER);

        return socket;
    }
}