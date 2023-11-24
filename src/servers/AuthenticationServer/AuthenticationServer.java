package servers.AuthenticationServer;

import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.sql.ResultSet;

import javax.crypto.KeyAgreement;

import utils.CryptoStuff;
import utils.MySQLiteUtils;
import utils.MySSLUtils;

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
        int curIdx = 0;
        ByteBuffer bb = ByteBuffer.wrap(content);

        int ipClientLengthR1 = bb.getInt(curIdx);
        curIdx += Integer.BYTES;

        byte[] ipClientBytesR1 = new byte[ipClientLengthR1];
        bb.get(curIdx, ipClientBytesR1);
        String ipClientR1 = new String(ipClientBytesR1, StandardCharsets.UTF_8);
        curIdx += ipClientBytesR1.length;

        int uidLengthR1 = bb.getInt(curIdx);
        curIdx += Integer.BYTES;

        byte[] uidBytesR1 = new byte[uidLengthR1];
        bb.get(curIdx, uidBytesR1);
        String uidR1 = new String(uidBytesR1, StandardCharsets.UTF_8);
        curIdx += uidBytesR1.length;

        // Check
        String conditionR1 = String.format("uid = '%s'", uidR1);
        ResultSet rs = users.select("uid, canBeAuthenticated", conditionR1);

        try {
            if (!rs.next())
                return MySSLUtils.buildErrorResponse();

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

        curIdx = 0;
        byte[] dataToSendS1 = new byte[totalSize];
        bb = ByteBuffer.wrap(dataToSendS1);

        bb.putLong(curIdx, srS1);
        curIdx += Long.BYTES;

        bb.putInt(curIdx, publicKeyBytesS1.length);
        curIdx += Integer.BYTES;

        bb.put(curIdx, publicKeyBytesS1);
        curIdx += publicKeyBytesS1.length;

        MySSLUtils.sendData(mdSocket, dataToSendS1);

        // ===== RECEIVE 2 =====
        // ===== SEND 2 =====

        return new byte[0];
    }

}
