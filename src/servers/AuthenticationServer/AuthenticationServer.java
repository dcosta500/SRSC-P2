package servers.AuthenticationServer;

import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.sql.ResultSet;
import java.time.Duration;
import java.time.Instant;

import utils.CommonValues;
import utils.CryptoStuff;
import utils.MySSLUtils;
import utils.SQL;

public class AuthenticationServer {

    public static byte[] login(Socket mdSocket, SQL users, byte[] content) {
        /* 
        * Data flow:
        * Receive-1 -> { len+IPclient || len+uid }
        * Send-1 -> { Secure Random (long) || len+Yauth }
        * Receive-2 -> { len+IPclient || len+Yclient || len+{ Secure Random }Kpwd }
        * Send-2 -> { len+{ len+"auth" || len+Ktoken1024 || len+TSf || Secure Random (long) || len+Kclient,ac }Kdh || 
        * len+{ len+"auth" || len+Ktoken1024 || len+TSf || Secure Random (long) || len+Kclient,ac }SIGauth }
        *
        * Ktoken1024 = { len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac } ||
        *              len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }SIGauth } Kauth,ac
        */

        // ===== RECEIVE 1 =====
        // Receive-1 -> { len+IPclient || len+uid }
        // Extract
        String ipClientR1;
        String uidR1;

        ByteBuffer bb = ByteBuffer.wrap(content);

        byte[] ipClientBytesR1 = MySSLUtils.getNextBytes(bb);
        ipClientR1 = new String(ipClientBytesR1, StandardCharsets.UTF_8);

        byte[] uidBytesR1 = MySSLUtils.getNextBytes(bb);
        uidR1 = new String(uidBytesR1, StandardCharsets.UTF_8);

        // Processing
        String conditionR1 = String.format("uid = '%s'", uidR1);
        ResultSet rs = users.select("uid, canBeAuthenticated, hPwd", conditionR1);

        String hPwd = null;
        try {
            if (!rs.next())
                return MySSLUtils.buildErrorResponse();

            hPwd = rs.getString("hPwd");
            boolean canBeAuthenticated = rs.getBoolean("canBeAuthenticated");
            if (!canBeAuthenticated)
                return MySSLUtils.buildErrorResponse();
        } catch (Exception e) {
            e.printStackTrace();
            return MySSLUtils.buildErrorResponse();
        }

        // ===== SEND 1 =====
        // Send-1 -> { Secure Random (long) || len+Yauth }
        long srS1 = CryptoStuff.getRandom();

        KeyPair dhKeyPairS1 = CryptoStuff.dhGenerateKeyPair();

        Key publicKeyS1 = dhKeyPairS1.getPublic();

        // Pack and Send
        byte[] publicKeyBytesS1 = publicKeyS1.getEncoded();
        int totalSize = Long.BYTES + Integer.BYTES + publicKeyBytesS1.length;

        byte[] dataToSendS1 = new byte[totalSize];
        bb = ByteBuffer.wrap(dataToSendS1);


        bb.putLong(srS1);

        MySSLUtils.putLengthAndBytes(bb, publicKeyBytesS1);

        MySSLUtils.sendData(mdSocket, MySSLUtils.buildResponse(CommonValues.OK_CODE, dataToSendS1));

        // ===== RECEIVE 2 =====
        // Receive-2 -> { len+IPclient || len+Yclient || len+{ Secure Random }Kpwd }
        byte[] contentR2 = MySSLUtils.receiveData(mdSocket);

        // Extract
        String ipClientR2;

        bb = ByteBuffer.wrap(contentR2);

        // len + array
        byte[] ipClientBytesR2 = MySSLUtils.getNextBytes(bb);
        ipClientR2 = new String(ipClientBytesR2, StandardCharsets.UTF_8);

        byte[] publicKeyClientBytesR2 = MySSLUtils.getNextBytes(bb);
        byte[] cipheredSrR2 = MySSLUtils.getNextBytes(bb);

        // Processing
        if (!ipClientR1.equals(ipClientR2))
            return MySSLUtils.buildErrorResponse();

        Key pbeKey = CryptoStuff.pbeCreateKeyFromPassword(hPwd);

        byte[] receivedSrR2 = CryptoStuff.pbeDecrypt(pbeKey, cipheredSrR2);
        if (receivedSrR2.length == 0) {
            // Password is probably wrong
            return MySSLUtils.buildErrorResponse();
        }

        long srR2 = ByteBuffer.wrap(receivedSrR2).getLong(0);

        if (srS1 != srR2)
            return MySSLUtils.buildErrorResponse();

        byte[] dhSecret = CryptoStuff.dhGenerateSharedSecret(dhKeyPairS1.getPrivate(), publicKeyClientBytesR2);
        Key dhKey = CryptoStuff.dhCreateKeyFromSharedSecret(dhSecret);

        // ===== SEND 2 =====
        /**
        * Send-2 -> { len+{ len+"auth" || len+Ktoken1024 || len+TSf || Secure Random (long) || len+Kclient,ac }Kdh || 
        * len+{ len+"auth" || len+Ktoken1024 || len+TSf || Secure Random (long) || len+Kclient,ac }SIGauth }
        *
        * Ktoken1024 = { len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac } ||
        *              len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }SIGauth } Kauth,ac
        */

        // Ktoken1024

        // Private key for signing
        //PrivateKey privKey = CryptoStuff.parsePrivateKeyFromPemFormat("certs/asCrypto/as_priv.key");
        PrivateKey privKey = CryptoStuff.getPrivateKeyFromKeystore("as", "as123456");
        if (privKey == null)
            return MySSLUtils.buildErrorResponse();

        Instant tsi_S2 = Instant.now();
        Instant tsf_S2 = tsi_S2.plus(Duration.ofHours(CommonValues.TOKEN_VALIDITY_HOURS));

        byte[] tsi_bytes_S2 = tsi_S2.toString().getBytes();
        byte[] tsf_bytes_S2 = tsf_S2.toString().getBytes();

        byte[] clientACSymKey_bytes_S2 = CryptoStuff.createSymKey().getEncoded();

        byte[] ktoken1024 = createKToken1024(uidBytesR1, ipClientBytesR1, tsi_bytes_S2, tsf_bytes_S2,
                clientACSymKey_bytes_S2, privKey);

        byte[] finalSend = createLoginFinalSend(ktoken1024, tsf_bytes_S2, clientACSymKey_bytes_S2, srS1, dhKey,
                privKey);

        return MySSLUtils.buildResponse(CommonValues.OK_CODE, finalSend);
    }

    // ===== Aux Methods =====
    // Login
    private static byte[] createLoginFinalSend(byte[] ktoken1024, byte[] tsfBytes, byte[] client_ac_symKey_bytes,
            long secureRandom, Key dhKey, PrivateKey privKey) {
        byte[] authId_S2 = CommonValues.AUTH_ID.getBytes();

        int finalSend_firstHalf_size = 4 * Integer.BYTES + authId_S2.length + ktoken1024.length + tsfBytes.length
                + Long.BYTES + client_ac_symKey_bytes.length;

        byte[] finalSendFirstHalf = new byte[finalSend_firstHalf_size];
        ByteBuffer bb = ByteBuffer.wrap(finalSendFirstHalf);

        MySSLUtils.putLengthAndBytes(bb, authId_S2);
        MySSLUtils.putLengthAndBytes(bb, ktoken1024);
        MySSLUtils.putLengthAndBytes(bb, tsfBytes);

        bb.putLong(secureRandom);
        MySSLUtils.putLengthAndBytes(bb, client_ac_symKey_bytes);

        byte[] finalSendFirstHalfEncrypted = CryptoStuff.symEncrypt(dhKey, finalSendFirstHalf);
        byte[] finalSendFirstHalfSigned = CryptoStuff.sign(privKey, finalSendFirstHalf);

        int finalSendLength = 2 * Integer.BYTES + finalSendFirstHalfEncrypted.length + finalSendFirstHalfSigned.length;

        byte[] finalSend = new byte[finalSendLength];
        bb = ByteBuffer.wrap(finalSend);

        MySSLUtils.putLengthAndBytes(bb, finalSendFirstHalfEncrypted);
        MySSLUtils.putLengthAndBytes(bb, finalSendFirstHalfSigned);

        return finalSend;
    }

    private static byte[] createKToken1024(byte[] uidBytes, byte[] ipClientBytes, byte[] tsI, byte[] tsF,
            byte[] client_ac_symKey_bytes, PrivateKey privKey) {
        ByteBuffer bb;
        byte[] authId_S2 = CommonValues.AC_ID.getBytes();

        // First half
        int lengthKtoken1024FirstHalf = 6 * Integer.BYTES + uidBytes.length + ipClientBytes.length
                + authId_S2.length
                + tsI.length + tsF.length + client_ac_symKey_bytes.length;

        byte[] Ktoken1024FirstHalf_bytes = new byte[lengthKtoken1024FirstHalf];
        bb = ByteBuffer.wrap(Ktoken1024FirstHalf_bytes);

        // Pack First Half of Ktoken1024
        MySSLUtils.putLengthAndBytes(bb, uidBytes);
        MySSLUtils.putLengthAndBytes(bb, ipClientBytes);
        MySSLUtils.putLengthAndBytes(bb, authId_S2);
        MySSLUtils.putLengthAndBytes(bb, tsI);
        MySSLUtils.putLengthAndBytes(bb, tsF);
        MySSLUtils.putLengthAndBytes(bb, client_ac_symKey_bytes);

        // Second Half
        byte[] signedFirstHalfKtoken1024_S2 = CryptoStuff.sign(privKey, Ktoken1024FirstHalf_bytes);

        // Create token
        int lengthKtoken1024_plain = 2 * Integer.BYTES + Ktoken1024FirstHalf_bytes.length
                + signedFirstHalfKtoken1024_S2.length;
        byte[] ktoken1024_plain = new byte[lengthKtoken1024_plain];
        bb = ByteBuffer.wrap(ktoken1024_plain);

        MySSLUtils.putLengthAndBytes(bb, Ktoken1024FirstHalf_bytes);
        MySSLUtils.putLengthAndBytes(bb, signedFirstHalfKtoken1024_S2);

        Key asAcSymmetricKey = CryptoStuff.parseSymKeyFromBase64(System.getProperty("SYM_KEY_AUTH_AC"));

        byte[] ktoken1024 = CryptoStuff.symEncrypt(asAcSymmetricKey, ktoken1024_plain);

        return ktoken1024;
    }
}
