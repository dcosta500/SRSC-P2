package servers.StorageSystemService;

import utils.Command;
import utils.CommonValues;
import utils.CryptoStuff;
import utils.MySSLUtils;

import javax.net.ssl.SSLContext;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;

public class StorageServiceServer {


    public static byte[] list(Socket mdSocket, byte[] content, Set<Long> nonceSet) {
        /* *
         * Data flow:
         * Receive-1 -> { len + IPClient || len + KvToken || len + AuthClient2 || R }
         * AuthClient2 = { len + { len + IDClient || len + TS || Nonce }Kc,s }
         * Kvtoken = { len + { len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms ||
         *               SIGac(len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms) } Kac,s }
         *
         * Send-1 -> { len + { R }Kc,s }
         * Receive-2 -> { len + IPClient || { len + arguments || Nonce }Kc,s }
         * Send-2 -> { len + { len + Response || Nonce }Kc,s }
         * */

        // len + clientServiceKey.Encoded || len + arguments || nonce
        byte[] receivedContent = receiveRequest(Command.LIST, mdSocket, content, nonceSet);
        if (receivedContent == null) {
            return MySSLUtils.buildErrorResponse();
        }

        ByteBuffer bb = ByteBuffer.wrap(receivedContent);

        byte[] clientServiceKeyBytes = MySSLUtils.getNextBytes(bb);
        byte[] arguments = MySSLUtils.getNextBytes(bb);
        long nonce2 = bb.getLong();

        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(clientServiceKeyBytes);

        // TODO: actual codigo do LS
        byte[] response = new byte[0];

        // ===== SEND 2 =====
        // { len + { len + Response || Nonce }Kc,s }
        byte[] responseDecrypted = new byte[Integer.BYTES + response.length + Long.BYTES];
        bb = ByteBuffer.wrap(responseDecrypted);

        MySSLUtils.putLengthAndBytes(bb, response);
        bb.putLong(nonce2);
        byte[] responseEncrypted = CryptoStuff.symEncrypt(clientServiceKey, responseDecrypted);
        byte[] dataToSend = new byte[Integer.BYTES + responseEncrypted.length];
        bb = ByteBuffer.wrap(dataToSend);
        MySSLUtils.putLengthAndBytes(bb, responseEncrypted);


        return MySSLUtils.buildResponse(CommonValues.OK_CODE, dataToSend);
    }


    public static byte[] put(Socket mdSocket, byte[] content, Set<Long> nonceSet) {
        /* *
         * Data flow:
         * Receive-1 -> { len + IPClient || len + KvToken || len + AuthClient2 || R }
         * AuthClient2 = { len + { len + IDClient || len + TS || Nonce }Kc,s }
         * Kvtoken = { len + { len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms ||
         *               SIGac(len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms) } Kac,s }
         *
         * Send-1 -> { len + { R }Kc,s }
         * Receive-2 -> { len + IPClient || { len + arguments || Nonce }Kc,s }
         * Send-2 -> { len + { len + Response || Nonce }Kc,s }
         * */

        byte[] receivedContent = receiveRequest(Command.LIST, mdSocket, content, nonceSet);
        if (receivedContent == null) {
            return MySSLUtils.buildErrorResponse();
        }

        ByteBuffer bb = ByteBuffer.wrap(receivedContent);

        byte[] clientServiceKeyBytes = MySSLUtils.getNextBytes(bb);
        byte[] arguments = MySSLUtils.getNextBytes(bb);
        long nonce2 = bb.getLong();

        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(clientServiceKeyBytes);
        String directoryPath = DEFAULT_DIR + "/" + userPath + "/" + path;
        Path directory = Paths.get(directoryPath);
        if (!Files.exists(directory.getParent()) || !Files.isDirectory(directory.getParent())) {
            System.out.println("Directory does not exist.");
            return MySSLUtils.buildErrorResponse();
        }
        byte[] contentEncrypted;
        byte[] response;
        try {
            if (!Files.exists(directory)) {
                Files.createFile(directory);
                contentEncrypted = ServiceFilePackage.createFileBytes(fileContent, username, path);
            } else {
                byte[] contentOfExistingFile = Files.readAllBytes(directory);
                contentEncrypted = ServiceFilePackage.writeFileBytes(new ServiceFilePackage(contentOfExistingFile), fileContent, userPath);
            }
            Files.write(directory, contentEncrypted != null ? contentEncrypted : new byte[0], StandardOpenOption.CREATE);
            response = "Sucessfully created file".getBytes();
        } catch (Exception e) {
            response = "Failed to create file".getBytes();
            System.out.println("username: " + username);
            System.out.println("userPath: " + userPath);
            System.out.println("path: " + path);
        }

        // ===== SEND 2 =====
        // { len + { len + Response || Nonce }Kc,s }
        byte[] responseDecrypted = new byte[Integer.BYTES + response.length + Long.BYTES];
        bb = ByteBuffer.wrap(responseDecrypted);

        MySSLUtils.putLengthAndBytes(bb, response);
        bb.putLong(nonce2);
        byte[] responseEncrypted = CryptoStuff.symEncrypt(clientServiceKey, responseDecrypted);
        byte[] dataToSend = new byte[Integer.BYTES + responseEncrypted.length];
        bb = ByteBuffer.wrap(dataToSend);
        MySSLUtils.putLengthAndBytes(bb, responseEncrypted);


        return MySSLUtils.buildResponse(CommonValues.OK_CODE, dataToSend);
    }

    public static byte[] get(Socket mdSocket, byte[] content, Set<Long> nonceSet) {
        byte[] receivedContent = receiveRequest(Command.LIST, mdSocket, content, nonceSet);
        if (receivedContent == null) {
            return MySSLUtils.buildErrorResponse();
        }

        ByteBuffer bb = ByteBuffer.wrap(receivedContent);

        byte[] clientServiceKeyBytes = MySSLUtils.getNextBytes(bb);
        byte[] arguments = MySSLUtils.getNextBytes(bb);
        long nonce2 = bb.getLong();

        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(clientServiceKeyBytes);

        // TODO: actual codigo do PUT
        byte[] response = new byte[0];

        // ===== SEND 2 =====
        // { len + { len + Response || Nonce }Kc,s }
        byte[] responseDecrypted = new byte[Integer.BYTES + response.length + Long.BYTES];
        bb = ByteBuffer.wrap(responseDecrypted);

        MySSLUtils.putLengthAndBytes(bb, response);
        bb.putLong(nonce2);
        byte[] responseEncrypted = CryptoStuff.symEncrypt(clientServiceKey, responseDecrypted);
        byte[] dataToSend = new byte[Integer.BYTES + responseEncrypted.length];
        bb = ByteBuffer.wrap(dataToSend);
        MySSLUtils.putLengthAndBytes(bb, responseEncrypted);


        return MySSLUtils.buildResponse(CommonValues.OK_CODE, dataToSend);
    }

    public static byte[] copy(Socket mdSocket, byte[] content, Set<Long> nonceSet) {
        byte[] receivedContent = receiveRequest(Command.LIST, mdSocket, content, nonceSet);
        if (receivedContent == null) {
            return MySSLUtils.buildErrorResponse();
        }

        ByteBuffer bb = ByteBuffer.wrap(receivedContent);

        byte[] clientServiceKeyBytes = MySSLUtils.getNextBytes(bb);
        byte[] arguments = MySSLUtils.getNextBytes(bb);
        long nonce2 = bb.getLong();

        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(clientServiceKeyBytes);

        // TODO: actual codigo do PUT
        byte[] response = new byte[0];

        // ===== SEND 2 =====
        // { len + { len + Response || Nonce }Kc,s }
        byte[] responseDecrypted = new byte[Integer.BYTES + response.length + Long.BYTES];
        bb = ByteBuffer.wrap(responseDecrypted);

        MySSLUtils.putLengthAndBytes(bb, response);
        bb.putLong(nonce2);
        byte[] responseEncrypted = CryptoStuff.symEncrypt(clientServiceKey, responseDecrypted);
        byte[] dataToSend = new byte[Integer.BYTES + responseEncrypted.length];
        bb = ByteBuffer.wrap(dataToSend);
        MySSLUtils.putLengthAndBytes(bb, responseEncrypted);


        return MySSLUtils.buildResponse(CommonValues.OK_CODE, dataToSend);

    }


    public static byte[] remove(Socket mdSocket, byte[] content, Set<Long> nonceSet) {
        byte[] receivedContent = receiveRequest(Command.LIST, mdSocket, content, nonceSet);
        if (receivedContent == null) {
            return MySSLUtils.buildErrorResponse();
        }

        ByteBuffer bb = ByteBuffer.wrap(receivedContent);

        byte[] clientServiceKeyBytes = MySSLUtils.getNextBytes(bb);
        byte[] arguments = MySSLUtils.getNextBytes(bb);
        long nonce2 = bb.getLong();

        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(clientServiceKeyBytes);

        // TODO: actual codigo do PUT
        byte[] response = new byte[0];

        // ===== SEND 2 =====
        // { len + { len + Response || Nonce }Kc,s }
        byte[] responseDecrypted = new byte[Integer.BYTES + response.length + Long.BYTES];
        bb = ByteBuffer.wrap(responseDecrypted);

        MySSLUtils.putLengthAndBytes(bb, response);
        bb.putLong(nonce2);
        byte[] responseEncrypted = CryptoStuff.symEncrypt(clientServiceKey, responseDecrypted);
        byte[] dataToSend = new byte[Integer.BYTES + responseEncrypted.length];
        bb = ByteBuffer.wrap(dataToSend);
        MySSLUtils.putLengthAndBytes(bb, responseEncrypted);


        return MySSLUtils.buildResponse(CommonValues.OK_CODE, dataToSend);

    }

    public static byte[] mkdir(Socket mdSocket, byte[] content, Set<Long> nonceSet) {
        byte[] receivedContent = receiveRequest(Command.MKDIR, mdSocket, content, nonceSet);
        if (receivedContent == null) {
            return MySSLUtils.buildErrorResponse();
        }
        ByteBuffer bb = ByteBuffer.wrap(receivedContent);
        byte[] userIdBytes = MySSLUtils.getNextBytes(bb);
        byte[] clientServiceKeyBytes = MySSLUtils.getNextBytes(bb);
        byte[] arguments = MySSLUtils.getNextBytes(bb); //len+(len + userPath || len + path || len + content)
        bb = ByteBuffer.wrap(arguments);
        String userPath = new String(MySSLUtils.getNextBytes(bb));
        String path = new String(MySSLUtils.getNextBytes(bb));
        long nonce2 = bb.getLong();
        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(clientServiceKeyBytes);
        String directoryPath = DEFAULT_DIR + "/" + userPath + "/" + path;
        Path directory = Paths.get(directoryPath);
        byte[] response;

        if (Files.exists(directory.getParent())) {
            try {
                Files.createDirectories(directory); // createDirectories() creates parent directories if they don't exist
                response = "Directory created successfully".getBytes();
            } catch (IOException e) {
                response = ("Failed to create directory: " + e.getMessage()).getBytes();
                System.err.println("Failed to create directory: " + e.getMessage());
                System.out.println("userPath: " + userPath);
                System.out.println("path: " + path);
            }
        } else {
            response = "Directory parent does not exist".getBytes();
            System.out.println("Directory parent does not exist");
        }

        // ===== SEND 2 =====
        // { len + { len + Response || Nonce }Kc,s }

        byte[] responseDecrypted = new byte[Integer.BYTES + response.length + Long.BYTES];
        bb = ByteBuffer.wrap(responseDecrypted);

        MySSLUtils.putLengthAndBytes(bb, response);
        bb.putLong(nonce2);
        byte[] responseEncrypted = CryptoStuff.symEncrypt(clientServiceKey, responseDecrypted);
        byte[] dataToSend = new byte[Integer.BYTES + responseEncrypted.length];
        bb = ByteBuffer.wrap(dataToSend);
        MySSLUtils.putLengthAndBytes(bb, responseEncrypted);


        return MySSLUtils.buildResponse(CommonValues.OK_CODE, dataToSend);
    }

    public static byte[] file(Socket mdSocket, byte[] content, Set<Long> nonceSet) {
        byte[] receivedContent = receiveRequest(Command.FILECMD, mdSocket, content, nonceSet);
        if (receivedContent == null) {
            return MySSLUtils.buildErrorResponse();
        }








    // ===== AUX METHODS =====
    private static byte[] receiveRequest(Command command, Socket mdSocket, byte[] content, Set<Long> nonceSet) {
        // ===== RECEIVE 1 =====
        ByteBuffer bb = ByteBuffer.wrap(content);
        byte[] ipClient = MySSLUtils.getNextBytes(bb);
        byte[] kvToken = MySSLUtils.getNextBytes(bb);
        byte[] authClient2 = MySSLUtils.getNextBytes(bb);
        long rChallenge = bb.getLong();

        // KvToken Decryption
        Key asAcSymmetricKey = CryptoStuff.parseSymKeyFromBase64(System.getProperty("SYM_KEY_AC_SS"));
        byte[] kvtokenDecrypted = CryptoStuff.symDecrypt(asAcSymmetricKey, kvToken);
        bb = ByteBuffer.wrap(kvtokenDecrypted);

        byte[] kvtokenContent = MySSLUtils.getNextBytes(bb);
        byte[] kvtokenSig = MySSLUtils.getNextBytes(bb);

        PublicKey acPublicKey = CryptoStuff.getPublicKeyFromTruststore("ac", "ss123456");
        if (CryptoStuff.verifySignature(acPublicKey, kvtokenContent, kvtokenSig)) {
            System.out.println("Signature wasn't Valid");
            return null;
        }

        // Kvtoken
        bb = ByteBuffer.wrap(kvtokenContent);

        byte[] idClient = MySSLUtils.getNextBytes(bb);
        byte[] ipClientToken = MySSLUtils.getNextBytes(bb);
        byte[] idService = MySSLUtils.getNextBytes(bb);
        Instant timestampInitial = Instant.parse(new String(MySSLUtils.getNextBytes(bb), StandardCharsets.UTF_8));
        Instant timestampFinal = Instant.parse(new String(MySSLUtils.getNextBytes(bb), StandardCharsets.UTF_8));
        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(MySSLUtils.getNextBytes(bb));
        byte[] permissions = MySSLUtils.getNextBytes(bb);

        //Check permissions
        if (!checkPerms(permissions, command)) return null;

        //AuthClient2
        bb = ByteBuffer.wrap(authClient2);

        byte[] idClientAuth = MySSLUtils.getNextBytes(bb);
        Instant timeStampAuth = Instant.parse(new String(MySSLUtils.getNextBytes(bb), StandardCharsets.UTF_8));
        long nonce = bb.getLong();

        if (nonceSet.contains(nonce)) {
            System.out.println("Retransmission detected.");
            return null;
        }
        nonceSet.add(nonce);

        if (Arrays.equals(idClientAuth, idClient) && Arrays.equals(ipClientToken, ipClient)) {
            System.out.println("idClientFromToken and idClientFromAuth didn't match");
            return null;
        }

        Instant now = Instant.now();
        if (now.isAfter(timeStampAuth.plus(Duration.ofSeconds(5))) && now.isAfter(timestampFinal)) {
            System.out.println("Auth Client Expired");
            return null;
        }

        // ===== SEND 1 ====
        byte[] rChallengeBytes = new byte[Long.BYTES];
        bb = ByteBuffer.wrap(rChallengeBytes);
        bb.putLong(rChallenge);

        byte[] encryptedRChallenge = CryptoStuff.symEncrypt(clientServiceKey, rChallengeBytes);
        byte[] payloadToSend = MySSLUtils.buildResponse(CommonValues.OK_CODE, encryptedRChallenge);

        MySSLUtils.sendData(mdSocket, payloadToSend);

        // ===== RECEIVE 2 =====
        // { len + IPClient || len + { len + arguments || Nonce }Kc,s }

        byte[] receive2 = MySSLUtils.receiveData(mdSocket);
        bb = ByteBuffer.wrap(receive2);

        byte[] ipClient2 = MySSLUtils.getNextBytes(bb);
        if (!Arrays.equals(ipClient, ipClient2)) {
            System.out.println("ClientIP from 1st receive was different from the 2nd");
            return null;
        }

        byte[] encryptedArgsAndNonce = MySSLUtils.getNextBytes(bb);
        byte[] argsAndNonce = CryptoStuff.symDecrypt(clientServiceKey, encryptedArgsAndNonce);

        byte[] dataReceived = new byte[2 * Integer.BYTES + clientServiceKey.getEncoded().length + argsAndNonce.length];
        bb = ByteBuffer.wrap(dataReceived);

        MySSLUtils.putLengthAndBytes(bb, clientServiceKey.getEncoded(), argsAndNonce);

        return dataReceived;
    }

}
