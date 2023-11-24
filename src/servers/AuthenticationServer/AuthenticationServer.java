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

import javax.crypto.KeyAgreement;

import utils.CommonValues;
import utils.CryptoStuff;
import utils.MySSLUtils;
import utils.ResponsePackage;

public class AuthenticationServer {

    public static byte[] login(Socket mdSocket, AuthUsersSQL users, byte[] content) {
        /* 
        * Data flow:
        * Receive-1 -> { len+IPclient || len+uid }
        * Send-1 -> { Secure Random (long) || len+Yauth }
        * Receive-2 -> { len+IPclient || len+Yclient || len+{ Secure Random }Kpwd }
        * Send-2 -> { len+"auth" || len+Ktoken1024 || len+TSf || Secure Random (long) || len+Kclient,ac }Kdh || 
        * { len+"auth" || len+Ktoken1024 || len+TSf || Secure Random (long) || len+Kclient,ac }SIGauth
        *
        * Ktoken1024 = { { len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac } ||
        *              { len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }SIGauth } Kac
        */

        // ===== RECEIVE 1 =====
        // Receive-1 -> { len+IPclient || len+uid }
        // Extract
        String ipClientR1;
        String uidR1;

        int curIdx = 0;
        ByteBuffer bb = ByteBuffer.wrap(content);

        int ipClientLengthR1 = bb.getInt(curIdx);
        curIdx += Integer.BYTES;

        byte[] ipClientBytesR1 = new byte[ipClientLengthR1];
        bb.get(curIdx, ipClientBytesR1);
        ipClientR1 = new String(ipClientBytesR1, StandardCharsets.UTF_8);
        curIdx += ipClientBytesR1.length;

        int uidLengthR1 = bb.getInt(curIdx);
        curIdx += Integer.BYTES;

        byte[] uidBytesR1 = new byte[uidLengthR1];
        bb.get(curIdx, uidBytesR1);
        uidR1 = new String(uidBytesR1, StandardCharsets.UTF_8);
        curIdx += uidBytesR1.length;

        // Processing
        String conditionR1 = String.format("uid = '%s'", uidR1);
        ResultSet rs = users.select("uid, canBeAuthenticated", conditionR1);

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
        KeyAgreement keyAgreementS1 = CryptoStuff.dhCreateKeyAgreement(dhKeyPairS1);

        Key publicKeyS1 = dhKeyPairS1.getPublic();

        // Pack and Send
        byte[] publicKeyBytesS1 = publicKeyS1.getEncoded();
        int totalSize = Long.BYTES + Integer.BYTES + publicKeyBytesS1.length;

        byte[] dataToSendS1 = new byte[totalSize];
        bb = ByteBuffer.wrap(dataToSendS1);

        curIdx = 0;

        bb.putLong(curIdx, srS1);
        curIdx += Long.BYTES;

        curIdx = putLengthAndBytes(bb, publicKeyBytesS1, curIdx);

        MySSLUtils.sendData(mdSocket, dataToSendS1);

        // ===== RECEIVE 2 =====
        // Receive-2 -> { len+IPclient || len+Yclient || len+{ Secure Random }Kpwd }

        byte[] receiveDataR2 = MySSLUtils.receiveData(mdSocket);
        ResponsePackage rp = ResponsePackage.parse(receiveDataR2);

        byte[] contentR2 = rp.getContent();

        // Extract
        String ipClientR2;
        Key publicKeyClientR2;

        bb = ByteBuffer.wrap(contentR2);

        curIdx = 0;

        int ipClientLengthR2 = bb.getInt(curIdx);
        curIdx += Integer.BYTES;

        byte[] ipClientBytesR2 = new byte[ipClientLengthR2];
        bb.get(curIdx, ipClientBytesR2);
        ipClientR2 = new String(ipClientBytesR2, StandardCharsets.UTF_8);
        curIdx += ipClientBytesR2.length;

        int publicKeyClientLengthR2 = bb.getInt(curIdx);
        curIdx += Integer.BYTES;

        byte[] publicKeyClientBytesR2 = new byte[publicKeyClientLengthR2];
        bb.get(curIdx, publicKeyClientBytesR2);
        publicKeyClientR2 = CryptoStuff.dhRecreatePublicKeyFromBytes(publicKeyBytesS1);
        curIdx += publicKeyClientBytesR2.length;

        int cipheredSrLengthR2 = bb.getInt(curIdx);
        curIdx += Integer.BYTES;

        byte[] cipheredSrR2 = new byte[cipheredSrLengthR2];
        bb.get(curIdx, cipheredSrR2);
        curIdx += cipheredSrLengthR2;

        // Processing
        if (!ipClientR1.equals(ipClientR2))
            return MySSLUtils.buildErrorResponse();

        Key pbeKey = CryptoStuff.pbeCreateKeyFromPassword(hPwd);
        byte[] receivedSrR2 = CryptoStuff.pbeDecrypt(pbeKey, cipheredSrR2);
        long srR2 = ByteBuffer.wrap(receivedSrR2).getLong(0);

        if (srS1 != srR2)
            return MySSLUtils.buildErrorResponse();

        byte[] dhSecret = CryptoStuff.dhGenerateSecret(keyAgreementS1, publicKeyClientR2);
        Key dhKey = CryptoStuff.dhCreateKeyFromSharedSecret(dhSecret);

        // ===== SEND 2 =====
        /**
        * Send-2 -> { len+{ len+"auth" || len+Ktoken1024 || len+TSf || Secure Random (long) || len+Kclient,ac }Kdh || 
        * len+{ len+"auth" || len+Ktoken1024 || len+TSf || Secure Random (long) || len+Kclient,ac }SIGauth }
        *
        * Ktoken1024 = { len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac } ||
        *              len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }SIGauth } Kac
        */

        // Ktoken1024
        PrivateKey privKey = CryptoStuff.parsePrivateKeyFromPemFormat("certs/asCrypto/as_priv.key");

        Instant tsi_S2 = Instant.now();
        Instant tsf_S2 = tsi_S2.plus(Duration.ofHours(CommonValues.TOKEN_VALIDITY_HOURS));

        byte[] tsi_bytes_S2 = tsi_S2.toString().getBytes();
        byte[] tsf_bytes_S2 = tsf_S2.toString().getBytes();

        byte[] clientACSymKey_bytes_S2 = CryptoStuff.createSymKey().getEncoded();

        byte[] ktoken1024 = createKToken1024(uidBytesR1, ipClientBytesR1, tsi_bytes_S2, tsf_bytes_S2,
                clientACSymKey_bytes_S2, privKey);

        return createLoginFinalSend(ktoken1024, tsf_bytes_S2, clientACSymKey_bytes_S2, srS1, dhKey, privKey);
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

        int curIdx = 0;
        curIdx = putLengthAndBytes(bb, authId_S2, curIdx);
        curIdx = putLengthAndBytes(bb, ktoken1024, curIdx);
        curIdx = putLengthAndBytes(bb, tsfBytes, curIdx);

        bb.putLong(curIdx, secureRandom);
        curIdx += Long.BYTES;

        curIdx = putLengthAndBytes(bb, client_ac_symKey_bytes, curIdx);

        byte[] finalSendFirstHalfEncrypted = CryptoStuff.symEncrypt(dhKey, finalSendFirstHalf);
        byte[] finalSendFirstHalfSigned = CryptoStuff.sign(privKey, finalSendFirstHalf);

        int finalSendLength = 2 * Integer.BYTES + finalSendFirstHalfEncrypted.length + finalSendFirstHalfSigned.length;

        byte[] finalSend = new byte[finalSendLength];
        bb = ByteBuffer.wrap(finalSend);

        curIdx = 0;
        curIdx = putLengthAndBytes(bb, finalSendFirstHalfEncrypted, curIdx);
        curIdx = putLengthAndBytes(bb, finalSendFirstHalfSigned, curIdx);

        return finalSend;
    }

    private static byte[] createKToken1024(byte[] uidBytes, byte[] ipClientBytes, byte[] tsI, byte[] tsF,
            byte[] client_ac_symKey_bytes, PrivateKey privKey) {
        int curIdx = 0;
        ByteBuffer bb;
        byte[] authId_S2 = CommonValues.AUTH_ID.getBytes();

        // First half
        int lengthKtoken1024FirstHalf = 6 * Integer.BYTES + uidBytes.length + ipClientBytes.length
                + authId_S2.length
                + tsI.length + tsF.length + client_ac_symKey_bytes.length;

        byte[] Ktoken1024FirstHalf_bytes = new byte[lengthKtoken1024FirstHalf];
        bb = ByteBuffer.wrap(Ktoken1024FirstHalf_bytes);

        // Pack First Half of Ktoken1024
        curIdx = 0;
        curIdx = putLengthAndBytes(bb, uidBytes, curIdx);
        curIdx = putLengthAndBytes(bb, ipClientBytes, curIdx);
        curIdx = putLengthAndBytes(bb, authId_S2, curIdx);
        curIdx = putLengthAndBytes(bb, tsI, curIdx);
        curIdx = putLengthAndBytes(bb, tsF, curIdx);
        curIdx = putLengthAndBytes(bb, client_ac_symKey_bytes, curIdx);

        // Second Half
        byte[] signedFirstHalfKtoken1024_S2 = CryptoStuff.sign(privKey, Ktoken1024FirstHalf_bytes);

        // Create token
        int lengthKtoken1024_plain = 2 * Integer.BYTES + Ktoken1024FirstHalf_bytes.length
                + signedFirstHalfKtoken1024_S2.length;
        byte[] ktoken1024_plain = new byte[lengthKtoken1024_plain];
        bb = ByteBuffer.wrap(ktoken1024_plain);

        curIdx = 0;

        curIdx = putLengthAndBytes(bb, Ktoken1024FirstHalf_bytes, curIdx);
        curIdx = putLengthAndBytes(bb, signedFirstHalfKtoken1024_S2, curIdx);

        Key asAcSymmetricKey = CryptoStuff.parseSymKeyFromBase64(System.getProperty("SYM_KEY_AUTH_AC"));

        byte[] ktoken1024 = CryptoStuff.symEncrypt(asAcSymmetricKey, ktoken1024_plain);

        return ktoken1024;
    }

    // ===== General =====
    private static int putLengthAndBytes(ByteBuffer bb, byte[] array, int curIdx) {
        bb.putInt(curIdx, array.length);
        curIdx += Integer.BYTES;

        bb.put(curIdx, array);
        curIdx += array.length;

        return curIdx;
    }
}
