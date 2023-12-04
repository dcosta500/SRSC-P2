package servers.StorageSystemService;

import utils.*;


import java.io.IOException;
import java.nio.file.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

public class StorageServiceServer {
    private static final String DEFAULT_DIR = System.getProperty("user.dir") + "/data";
    /* *
     * Data flow:
     * Receive-1 -> { len + IPClient || len + KvToken || len + AuthClient2 || R }
     * AuthClient2 = { len + { len + IDClient || len + TS || Nonce }Kc,s }
     * Kvtoken = { len + { len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms ||
     *               SIGac(len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms) } Kac,s }
     *
     * Send-1 -> { { R }Kc,s }
     * Receive-2 -> { len + IPClient || { len + arguments || Nonce }Kc,s }
     * Send-2 -> { len + { len + Response || Nonce }Kc,s }
     * */

    public static byte[] list(Socket mdSocket, byte[] content, Set<Long> nonceSet) {

        // len + clientServiceKey.Encoded || len + arguments || nonce
        byte[] receivedContent = receiveRequest(Command.LIST, mdSocket, content, nonceSet);
        if (receivedContent == null) {
            return MySSLUtils.buildErrorResponse();
        }

        ByteBuffer bb = ByteBuffer.wrap(receivedContent);
        byte[] userIdBytes = MySSLUtils.getNextBytes(bb);
        byte[] clientServiceKeyBytes = MySSLUtils.getNextBytes(bb);
        byte[] arguments = MySSLUtils.getNextBytes(bb);
        long nonce2 = bb.getLong();

        // arguments = len + username
        bb = ByteBuffer.wrap(arguments);
        String username = new String(MySSLUtils.getNextBytes(bb));
        String path = new String(MySSLUtils.getNextBytes(bb));
        Path directory;
        if (path.length() <= 1) {
            directory = Paths.get(DEFAULT_DIR + "/" + username);
        } else {
            directory = Paths.get(DEFAULT_DIR + "/" + username + "/" + path);
        }

        byte[] response;
        try {
            DirectoryStream<Path> directoryStream;
            directoryStream = Files.newDirectoryStream(directory);
            String directories = "";
            for (Path entry : directoryStream)
                directories = directories.concat(entry.getFileName() + "\n");
            response = directories.getBytes();
        } catch (Exception e) {
            System.err.println("directory: " + directory);
            System.err.println("username: " + username);
            return MySSLUtils.buildErrorResponse();
        }
        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(clientServiceKeyBytes);


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
         * Receive-2.1 -> { len+fileContent }Kc,s
         * Send-2 -> { len + { len + Response || Nonce }Kc,s }
         * */

        // ===== RECEIVE-SEND-1 & RECEIVE-2 =====
        byte[] receivedContent = receiveRequest(Command.MKDIR, mdSocket, content, nonceSet);
        if (receivedContent == null) {
            return MySSLUtils.buildErrorResponse();
        }

        // Unpack from receiveRequest
        ByteBuffer bb = ByteBuffer.wrap(receivedContent);
        byte[] username = MySSLUtils.getNextBytes(bb);
        byte[] clientServiceKeyBytes = MySSLUtils.getNextBytes(bb);
        byte[] arguments = MySSLUtils.getNextBytes(bb);

        // Unpack arguments and nonce
        bb = ByteBuffer.wrap(arguments);
        String userPath = new String(MySSLUtils.getNextBytes(bb));
        String path = new String(MySSLUtils.getNextBytes(bb));
        long nonce = bb.getLong();

        // Command Logic
        String directoryPath = DEFAULT_DIR + "/" + userPath + "/" + path;
        Path directory = Paths.get(directoryPath);

        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(clientServiceKeyBytes);

        // Signal to send content
        MySSLUtils.sendData(mdSocket, new byte[1]);

        byte[] fileEncryptedWithlen = MySSLUtils.receiveFile(mdSocket);
        bb = ByteBuffer.wrap(fileEncryptedWithlen);

        byte[] fileEncrypted = MySSLUtils.getNextBytes(bb);

        byte[] fileContent = CryptoStuff.symDecrypt(clientServiceKey, fileEncrypted);
        System.out.println(Base64.getEncoder().encodeToString(fileEncryptedWithlen));

        if (!Files.exists(directory.getParent()) || !Files.isDirectory(directory.getParent())) {
            System.out.println("Directory does not exist.");
            return MySSLUtils.buildErrorResponse();
        }
        byte[] contentEncrypted;
        byte[] response;
        try {
            if (!Files.exists(directory)) {
                contentEncrypted = ServiceFilePackage.createFileBytes(fileContent, new String(username,StandardCharsets.UTF_8), path);
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
        bb.putLong(nonce);


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
        byte[] userIdBytes = MySSLUtils.getNextBytes(bb);
        byte[] clientServiceKeyBytes = MySSLUtils.getNextBytes(bb);
        byte[] arguments = MySSLUtils.getNextBytes(bb);
        long nonce2 = bb.getLong();
        // arguments = len + username || len + path/file
        bb = ByteBuffer.wrap(arguments);
        String userPath = new String(MySSLUtils.getNextBytes(bb));
        String username = Arrays.toString(userIdBytes);
        String path = new String(MySSLUtils.getNextBytes(bb));

        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(clientServiceKeyBytes);

        String directoryPath = DEFAULT_DIR + "/" + userPath + "/" + path;
        Path file = Paths.get(directoryPath);
        if (!Files.exists(file)) {
            System.err.println("File does not exist");
            return MySSLUtils.buildErrorResponse();
        }
        byte[] encryptedFile;
        ServiceFilePackage fileRead;
        try {
            encryptedFile = Files.readAllBytes(file);
            fileRead = new ServiceFilePackage(encryptedFile);
            byte[] newFile = ServiceFilePackage.readFileBytes(fileRead, username);
            Files.write(file, newFile != null ? newFile : new byte[0], StandardOpenOption.CREATE);
        } catch (IOException e) {
            System.err.println("Catastrophic failure");
            System.out.println("username: " + username);
            System.out.println("userPath: " + userPath);
            System.out.println("path: " + path);
            return MySSLUtils.buildErrorResponse();
        }
        byte[] response = fileRead.getContent();


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
        byte[] userIdBytes = MySSLUtils.getNextBytes(bb);
        byte[] clientServiceKeyBytes = MySSLUtils.getNextBytes(bb);
        byte[] arguments = MySSLUtils.getNextBytes(bb);
        long nonce2 = bb.getLong();
        // arguments = len + username || len + path1/file1 || len + path2/file2
        bb = ByteBuffer.wrap(arguments);
        String userPath = new String(MySSLUtils.getNextBytes(bb));
        String username = Arrays.toString(userIdBytes);
        String path1 = new String(MySSLUtils.getNextBytes(bb));
        String path2 = new String(MySSLUtils.getNextBytes(bb));

        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(clientServiceKeyBytes);

        String directoryPath = DEFAULT_DIR + "/" + userPath + "/" + path1;

        String toDirectoryPath = DEFAULT_DIR + "/" + userPath + "/" + path2;
        Path file1 = Paths.get(directoryPath);
        Path file2 = Paths.get(toDirectoryPath);
        if (!Files.exists(file1)) {
            System.err.println("File does not exist");
            return MySSLUtils.buildErrorResponse();
        }
        byte[] encryptedFile;
        ServiceFilePackage fileRead;
        try {
            encryptedFile = Files.readAllBytes(file1);
            fileRead = new ServiceFilePackage(encryptedFile);
            byte[] newFile = ServiceFilePackage.copyFileBytes(fileRead, username, path2);
            Files.write(file2, newFile != null ? newFile : new byte[0], StandardOpenOption.CREATE);
        } catch (IOException e) {
            System.err.println("Catastrophic failure");
            System.out.println("username: " + username);
            System.out.println("userPath: " + userPath);
            System.out.println("path1: " + path1);
            System.out.println("path2: " + path2);
            return MySSLUtils.buildErrorResponse();
        }
        byte[] response = fileRead.getContent();
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
        byte[] userIdBytes = MySSLUtils.getNextBytes(bb);
        byte[] clientServiceKeyBytes = MySSLUtils.getNextBytes(bb);
        byte[] arguments = MySSLUtils.getNextBytes(bb);
        long nonce2 = bb.getLong();

        // arguments = len + username || len + path
        bb = ByteBuffer.wrap(arguments);
        String username = new String(MySSLUtils.getNextBytes(bb));
        Path filePath = Paths.get(DEFAULT_DIR + "/" + username + "/" + new String(MySSLUtils.getNextBytes(bb)));
        try {
            Files.delete(filePath);
        } catch (NoSuchFileException e) {
            System.err.println("File does not exist");
            return MySSLUtils.buildErrorResponse();
        } catch (DirectoryNotEmptyException e) {
            System.err.println("File is a directory and could not otherwise be deleted because the directory is not empty");
            return MySSLUtils.buildErrorResponse();
        } catch (Exception e) {
            System.err.println("Catastrophic Failure");
            return MySSLUtils.buildErrorResponse();
        }

        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(clientServiceKeyBytes);
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

        // ===== RECEIVE-SEND-1 & RECEIVE-2 =====
        byte[] receivedContent = receiveRequest(Command.MKDIR, mdSocket, content, nonceSet);
        if (receivedContent == null) {
            return MySSLUtils.buildErrorResponse();
        }

        // Unpack from receiveRequest
        ByteBuffer bb = ByteBuffer.wrap(receivedContent);
        byte[] userIdBytes = MySSLUtils.getNextBytes(bb);
        byte[] clientServiceKeyBytes = MySSLUtils.getNextBytes(bb);
        byte[] arguments = MySSLUtils.getNextBytes(bb);

        // Unpack arguments and nonce
        bb = ByteBuffer.wrap(arguments);
        String userPath = new String(MySSLUtils.getNextBytes(bb));
        String path = new String(MySSLUtils.getNextBytes(bb));
        long nonce = bb.getLong();

        // Command Logic
        String directoryPath = DEFAULT_DIR + "/" + userPath + "/" + path;
        Path directory = Paths.get(directoryPath);
        byte[] response;
        try {
            Files.createDirectories(directory); // createDirectories() creates parent directories if they don't exist
            response = "Directory created successfully".getBytes();
        } catch (IOException e) {
            System.out.println("Failed to create directory.");
            return MySSLUtils.buildErrorResponse();
        }

        // ===== SEND 2 =====
        // { len + { len + Response || Nonce }Kc,s }

        byte[] responseDecrypted = new byte[Integer.BYTES + response.length + Long.BYTES];
        bb = ByteBuffer.wrap(responseDecrypted);

        MySSLUtils.putLengthAndBytes(bb, response);
        bb.putLong(nonce);

        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(clientServiceKeyBytes);
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

        ByteBuffer bb = ByteBuffer.wrap(receivedContent);
        byte[] userIdBytes = MySSLUtils.getNextBytes(bb);
        byte[] clientServiceKeyBytes = MySSLUtils.getNextBytes(bb);
        byte[] arguments = MySSLUtils.getNextBytes(bb);
        long nonce2 = bb.getLong();
        // arguments = len + username || len + path/file
        bb = ByteBuffer.wrap(arguments);
        String userPath = new String(MySSLUtils.getNextBytes(bb));
        String username = Arrays.toString(userIdBytes);
        String path = new String(MySSLUtils.getNextBytes(bb));

        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(clientServiceKeyBytes);

        String directoryPath = DEFAULT_DIR + "/" + userPath + "/" + path;
        Path file = Paths.get(directoryPath);
        if (!Files.exists(file)) {
            System.err.println("File does not exist");
            return MySSLUtils.buildErrorResponse();
        }
        byte[] encryptedFile;
        ServiceFilePackage fileRead;
        try {
            encryptedFile = Files.readAllBytes(file);
            fileRead = new ServiceFilePackage(encryptedFile);
        } catch (IOException e) {
            System.err.println("Catastrophic failure");
            System.out.println("username: " + username);
            System.out.println("userPath: " + userPath);
            System.out.println("path: " + path);
            return MySSLUtils.buildErrorResponse();
        }
        byte[] response = fileRead.getMetadata().getBytes();

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


    // ===== AUX METHODS =====
    private static byte[] receiveRequest(Command command, Socket mdSocket, byte[] content, Set<Long> nonceSet) {
        /* *
         * Data flow:
         * Receive-1 -> { len + IPClient || len + KvToken || len + AuthClient2 || R }
         * AuthClient2 = { len + { len + IDClient || len + TS || Nonce }Kc,s }
         * Kvtoken = { len + { len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms ||
         *               SIGac(len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms) } Kac,s }
         * */
        // ===== RECEIVE 1 =====
        ByteBuffer bb = ByteBuffer.wrap(content);
        byte[] ipClient = MySSLUtils.getNextBytes(bb);
        byte[] kvToken = MySSLUtils.getNextBytes(bb);
        byte[] authClient2 = MySSLUtils.getNextBytes(bb);
        long rChallenge = bb.getLong();


        // Kvtoken
        // Kvtoken = { len + { len + kvtoken_content || len + SIGac( kvtoken_content ) } Kac,s }
        // kvtoken_content = { len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms }

        // KvToken Decryption
        Key acSsSymKey = CryptoStuff.parseSymKeyFromBase64(System.getProperty("SYM_KEY_AC_SS"));
        byte[] kvtokenDecrypted = CryptoStuff.symDecrypt(acSsSymKey, kvToken);
        bb = ByteBuffer.wrap(kvtokenDecrypted);

        byte[] kvtokenContent = MySSLUtils.getNextBytes(bb);
        byte[] kvtokenSig = MySSLUtils.getNextBytes(bb);

        PublicKey acPublicKey = CryptoStuff.getPublicKeyFromTruststore("ac", "ss123456");
        if (!CryptoStuff.verifySignature(acPublicKey, kvtokenContent, kvtokenSig)) {
            System.out.println("Signature wasn't Valid");
            return null;
        }

        bb = ByteBuffer.wrap(kvtokenContent);
        byte[] idClientToken = MySSLUtils.getNextBytes(bb);
        byte[] ipClientToken = MySSLUtils.getNextBytes(bb);
        byte[] idServiceToken = MySSLUtils.getNextBytes(bb);

        String idServiceNameToken = new String(idServiceToken, StandardCharsets.UTF_8);
        if (!idServiceNameToken.equals(CommonValues.SS_ID)) {
            System.out.println("Token not valid for this service, expected " + CommonValues.SS_ID + " got " + idServiceNameToken);
            return null;
        }

        Instant timestampInitial = Instant.parse(new String(MySSLUtils.getNextBytes(bb), StandardCharsets.UTF_8));
        Instant timestampFinal = Instant.parse(new String(MySSLUtils.getNextBytes(bb), StandardCharsets.UTF_8));
        Key clientServiceKey = CryptoStuff.parseSymKeyFromBytes(MySSLUtils.getNextBytes(bb));
        byte[] permissions = MySSLUtils.getNextBytes(bb);

        // Check permissions
        if (!checkPerms(permissions, command)) {
            System.out.println("Not enough permissions for this command.");
            return null;
        }

        // AuthClient2
        if (!checkAuth(clientServiceKey, authClient2, nonceSet, idClientToken, ipClient, ipClientToken, timestampFinal)) {
            System.out.println("Client Authenticator is invalid.");
            return null;
        }

        // ===== SEND 1 ====
        byte[] rChallengeBytes = new byte[Long.BYTES];
        bb = ByteBuffer.wrap(rChallengeBytes);
        bb.putLong(rChallenge);

        byte[] encryptedRChallenge = CryptoStuff.symEncrypt(clientServiceKey, rChallengeBytes);
        byte[] payloadToSend = MySSLUtils.buildResponse(CommonValues.OK_CODE, encryptedRChallenge);

        MySSLUtils.sendData(mdSocket, payloadToSend);

        System.out.println("Authenticated Myself");

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

        byte[] dataReceived = new byte[3 * Integer.BYTES + idClientToken.length + clientServiceKey.getEncoded().length + argsAndNonce.length];
        bb = ByteBuffer.wrap(dataReceived);

        MySSLUtils.putLengthAndBytes(bb, idClientToken, clientServiceKey.getEncoded(), argsAndNonce);

        return dataReceived;
    }

    private static boolean checkAuth(Key key_client_service, byte[] authClient2Encrypted, Set<Long> nonceSet, byte[] idClient,
                                     byte[] ipClient, byte[] ipClientToken, Instant timestampFinal) {

        // AuthClient = { len + IdClient || len + TS || Nonce }Kc,ss
        byte[] authClient2 = CryptoStuff.symDecrypt(key_client_service, authClient2Encrypted);

        ByteBuffer bb = ByteBuffer.wrap(authClient2);

        byte[] idClientAuth = MySSLUtils.getNextBytes(bb);
        Instant timeStampAuth = Instant.parse(new String(MySSLUtils.getNextBytes(bb), StandardCharsets.UTF_8));
        long nonce = bb.getLong();

        if (nonceSet.contains(nonce)) {
            System.out.println("Retransmission detected.");
            return false;
        }
        nonceSet.add(nonce);

        if (!Arrays.equals(idClientAuth, idClient) || !Arrays.equals(ipClientToken, ipClient)) {
            System.out.println("idClientFromToken and idClientFromAuth didn't match");
            return false;
        }

        Instant now = Instant.now();
        if (now.isAfter(timeStampAuth.plus(Duration.ofSeconds(5))) || now.isAfter(timestampFinal)) {
            System.out.println("Auth Client Expired");
            return false;
        }

        return true;
    }

    private static boolean checkPerms(byte[] permissions, Command command) {
        String perms = new String(permissions, StandardCharsets.UTF_8);

        switch (command) {
            case GET, LIST, FILECMD:
                if (perms.equals(CommonValues.PERM_DENY)) return false;
                break;
            case PUT, REMOVE, COPY, MKDIR:
                if (!perms.equals(CommonValues.PERM_READ_WRITE)) return false;
                break;
            default:
                return false;
        }
        return true;
    }
}
