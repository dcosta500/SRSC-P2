package servers.AccessControlServer;

import utils.CommonValues;
import utils.CryptoStuff;
import utils.MySSLUtils;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

public class AccessControlServer {
    public static byte[] access(Socket mdSocket, Set<Long> nonceSet, byte[] content) {
        /*
         * Data flow:
         * Receive-1-> { len+ipClient || len+IdServiço || len+Ktoken1024 || len+AuthClient}
         * AuthClient = { len+IdClient || len+ IpClient || len+TS || NONCE }Kc,AC
         * Ktoken1024 = { len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac } ||
         *              len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }SIGauth } Kauth,ac
         * Send-1 -> { len+KeyC,Serviço || len+IdServiço || len+TSf || len+KvToken }
         * Kvtoken = { len+Kc,serive || len+uid || len+IpClient || len+IdClient || len+TSi || len+TSf || len+perms}
         */

        // ===== Receive-1 =====
        // { len+ipClient || len+IdServiço || len+Ktoken1024 || len+AuthClient}
        // AuthClient = { len+IdClient || len+ IpClient || len+TS || NONCE }Kc,AC
        // Ktoken1024 = { len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac } ||
        //              len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }SIGauth } Kauth,ac

        String ipClient;
        String idService;

        int curIdx = 0;
        ByteBuffer bb = ByteBuffer.wrap(content);

        byte[] ipClientBytes = MySSLUtils.getNextBytes(bb, curIdx);
        ipClient = new String(ipClientBytes, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + ipClientBytes.length;

        byte[] idBytesService = MySSLUtils.getNextBytes(bb, curIdx);
        idService = new String(idBytesService, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + idBytesService.length;

        byte[] Ktoken1024 = MySSLUtils.getNextBytes(bb, curIdx);
        curIdx += Integer.BYTES + Ktoken1024.length;

        byte[] authClientEncrypted = MySSLUtils.getNextBytes(bb, curIdx);
        curIdx += Integer.BYTES + authClientEncrypted.length;

        //Unpack token
        Key asAcSymmetricKey = CryptoStuff.parseSymKeyFromBase64(System.getProperty("SYM_KEY_AUTH_AC"));
        byte[] decipheredToken = CryptoStuff.symDecrypt(asAcSymmetricKey, Ktoken1024);

        Key clientAC = checkTokenValidity(decipheredToken, /* idClient que vem do authenticator */ ,ipClient);
        if (clientAC == null)
            return MySSLUtils.buildErrorResponse();

        //AuthClient = {len+IdClient || len+ IpClient || len+TS || NOUNCE}Kc,AC
        byte[] authClientDecrypted = CryptoStuff.symDecrypt(clientAC, authClientEncrypted);

        bb = ByteBuffer.wrap(authClientDecrypted);
        curIdx = 0;

        byte[] idClientB = MySSLUtils.getNextBytes(bb, curIdx);
        String idClient = new String(idClientB, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + idClientB.length;

        byte[] ipClientB_auth = MySSLUtils.getNextBytes(bb, curIdx);
        String ipClient_auth = new String(ipClientB_auth, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + ipClientB_auth.length;

        byte[] timestampB_auth = MySSLUtils.getNextBytes(bb, curIdx);
        Instant timestamp_auth = Instant.parse(new String(timestampB_auth, StandardCharsets.UTF_8));
        curIdx += Integer.BYTES + timestampB_auth.length;

        long nonce = bb.getLong(curIdx);
        if (nonceSet.contains(nonce)) {
            System.out.println("Retransmission detected.");
            return MySSLUtils.buildErrorResponse();
        }
        nonceSet.add(nonce);

        // ===== Send-1 =====
        // { len+KeyC,Serviço || len+IdServiço || len+TSf || len+KvToken }
        // Kvtoken = { len+Kc,serive || len+uid || len+IpClient || len+IdClient || len+TSi || len+TSf || len+perms}

        Instant tsi = Instant.now();
        Instant tsf = tsi.plus(Duration.ofHours(CommonValues.TOKEN_VALIDITY_HOURS));
        byte[] clientSSSymKey_bytes = CryptoStuff.createSymKey().getEncoded();

        // TODO: Fazer um método que constroi o KvToken, tal como há um no auth que constroi o Ktoken1024
        //KvToken
        byte[] kvTokenDecrypted = new byte[Integer.BYTES + clientSSSymKey_bytes.length + Integer.BYTES + Integer.BYTES
                + idClientB.length + Integer.BYTES + ipClientB_auth.length +
                Integer.BYTES + idBytesService.length + Integer.BYTES + tsi.toString().getBytes().length
                + Integer.BYTES + tsf.toString().getBytes().length];
        bb = ByteBuffer.wrap(kvTokenDecrypted);
        curIdx = 0;
        curIdx = MySSLUtils.putLengthAndBytes(bb, clientSSSymKey_bytes, curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, idBytesService, curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, ipClientBytes, curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, idBytesService, curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, tsi.toString().getBytes(), curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, tsf.toString().getBytes(), curIdx);
        byte[] kvTokenEncrypted = CryptoStuff
                .symEncrypt(CryptoStuff.parseSymKeyFromBase64(System.getProperty("SYM_KEY_AC_SS")), kvTokenDecrypted);

        byte[] sendDecrypted = new byte[Integer.BYTES + clientSSSymKey_bytes.length + Integer.BYTES
                + idBytesService.length +
                Integer.BYTES + tsf.toString().getBytes().length + Integer.BYTES + kvTokenEncrypted.length];

        bb = ByteBuffer.wrap(sendDecrypted);
        curIdx = 0;
        curIdx = MySSLUtils.putLengthAndBytes(bb, clientSSSymKey_bytes, curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, idBytesService, curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, tsf.toString().getBytes(), curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, kvTokenEncrypted, curIdx);

        byte[] sendEncrypted = CryptoStuff.symEncrypt(clientAC, sendDecrypted);

        return MySSLUtils.buildResponse(CommonValues.OK_CODE, sendEncrypted);
    }

    // ===== AUX METHODS =====
    private static boolean checkClientAuthenticatorValidity() {
        // TODO: Fazer este método
        // 
        return false;
    }

    private static Key checkTokenValidity(byte[] token, String idClient, String ipClient) {
        // token = { len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac } ||
        //                len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }SIGauth }

        ByteBuffer bb = ByteBuffer.wrap(token);

        int curIdx = 0;
        byte[] tokenFirstHalf = MySSLUtils.getNextBytes(bb, curIdx);
        curIdx += Integer.BYTES + tokenFirstHalf.length;

        byte[] tokenSig = MySSLUtils.getNextBytes(bb, curIdx);
        curIdx += Integer.BYTES + tokenSig.length;

        PublicKey pubKey = CryptoStuff.getPublicKeyFromTruststore("as", "ac123456");
        if (!CryptoStuff.verifySignature(pubKey, tokenFirstHalf, tokenSig)) {
            System.out.println("Signature does not match.");
            return null;
        }

        // Unpack further
        bb = ByteBuffer.wrap(tokenFirstHalf);

        curIdx = 0;
        byte[] idClientBytes = MySSLUtils.getNextBytes(bb, curIdx);
        String idClient2 = new String(idClientBytes, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + idClientBytes.length;

        if (!idClient.equals(idClient2)) {
            System.out.println("Client ids do not match.");
            return null;
        }

        byte[] ipClientBytes = MySSLUtils.getNextBytes(bb, curIdx);
        String ipClient2 = new String(ipClientBytes, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + idClientBytes.length;

        if (!ipClient.equals(ipClient2)) {
            System.out.println("Client ips do not match.");
            return null;
        }

        byte[] idACBytes = MySSLUtils.getNextBytes(bb, curIdx);
        String idAC = new String(idACBytes, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + idACBytes.length;

        if (!idAC.equals(CommonValues.AC_ID)) {
            System.out.println("Access Control Ids do not match.");
            return null;
        }

        byte[] tsiBytes = MySSLUtils.getNextBytes(bb, curIdx);
        Instant timestampInitial = Instant.parse(new String(tsiBytes, StandardCharsets.UTF_8));
        curIdx += Integer.BYTES + tsiBytes.length;

        byte[] tsfBytes = MySSLUtils.getNextBytes(bb, curIdx);
        Instant timestampFinal = Instant.parse(new String(tsfBytes, StandardCharsets.UTF_8));
        curIdx += Integer.BYTES + tsfBytes.length;

        if (Instant.now().isAfter(timestampFinal)) {
            System.out.println("Token life expired.");
            return null;
        }

        byte[] keyClientACBytes = MySSLUtils.getNextBytes(bb, curIdx);
        Key keyClientAC = CryptoStuff.parseSymKeyFromBytes(keyClientACBytes);
        curIdx += Integer.BYTES + keyClientACBytes.length;

        return keyClientAC;
    }
}
