package servers.AccessControlServer;

import utils.CommonValues;
import utils.CryptoStuff;
import utils.MySSLUtils;
import utils.SQL;

import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.sql.Connection;
import java.sql.ResultSet;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

public class AccessControlServer {

    private static String idClient_token;
    public static byte[] access(Socket mdSocket, Set<Long> nonceSet, byte[] content, SQL users) {
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


        Key clientAC = checkTokenValidity(decipheredToken,ipClient);
        if (clientAC == null)
            return MySSLUtils.buildErrorResponse();

        //AuthClient = {len+IdClient || len+ IpClient || len+TS || NOUNCE}Kc,AC
        byte[] authClientDecrypted = CryptoStuff.symDecrypt(clientAC, authClientEncrypted);

        bb = ByteBuffer.wrap(authClientDecrypted);
        curIdx = 0;

        byte[] idClientB_auth = MySSLUtils.getNextBytes(bb, curIdx);
        String idClient_auth = new String(idClientB_auth, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + idClientB_auth.length;

        byte[] ipClientB_auth = MySSLUtils.getNextBytes(bb, curIdx);
        String ipClient_auth = new String(ipClientB_auth, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + ipClientB_auth.length;

        byte[] timestampB_auth = MySSLUtils.getNextBytes(bb, curIdx);
        Instant timestamp_auth = Instant.parse(new String(timestampB_auth, StandardCharsets.UTF_8));
        curIdx += Integer.BYTES + timestampB_auth.length;

        if(!checkClientAuthenticatorValidity(ipClient,ipClient_auth,idClient_token,idClient_auth)) {
            System.out.println("Not matching id or ip");
            return MySSLUtils.buildErrorResponse();
        }

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
        //KvToken
        byte[] kvToken = buildTokenV(idClientB_auth,ipClientBytes,idBytesService,ipClientB_auth,clientSSSymKey_bytes,tsi,tsf,users);

        byte[] sendDecrypted = new byte[Integer.BYTES + clientSSSymKey_bytes.length + Integer.BYTES
                + idBytesService.length +
                Integer.BYTES + tsf.toString().getBytes().length + Integer.BYTES + kvToken.length];

        bb = ByteBuffer.wrap(sendDecrypted);
        curIdx = 0;
        curIdx = MySSLUtils.putLengthAndBytes(bb, clientSSSymKey_bytes, curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, idBytesService, curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, tsf.toString().getBytes(), curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, kvToken, curIdx);
        byte[] sendEncrypted = CryptoStuff.symEncrypt(clientAC, sendDecrypted);
        return MySSLUtils.buildResponse(CommonValues.OK_CODE, sendEncrypted);
    }

    // ===== AUX METHODS =====
    private static boolean checkClientAuthenticatorValidity(String ipClient_rc,String ipClient_auth,String idClient_auth,String idClient_token) {
        System.out.println(ipClient_rc+ " " + ipClient_auth +" " + idClient_auth + " " + idClient_token);
        return ipClient_rc.equals(ipClient_auth) && idClient_auth.equals(idClient_token);
    }

    private static Key checkTokenValidity(byte[] token, String ipClient) {
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
            MySSLUtils.printToLogFile("AccessControl","Signature does not match.");
            return null;
        }

        // Unpack further
        bb = ByteBuffer.wrap(tokenFirstHalf);

        curIdx = 0;
        byte[] idClientBytes = MySSLUtils.getNextBytes(bb, curIdx);
        idClient_token = new String(idClientBytes, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + idClientBytes.length;

        byte[] ipClientBytes = MySSLUtils.getNextBytes(bb, curIdx);
        String ipClient2 = new String(ipClientBytes, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + ipClientBytes.length;

        if (!ipClient.equals(ipClient2)) {
            MySSLUtils.printToLogFile("AccessControl","Client ips do not match.");
            return null;
        }

        byte[] idACBytes = MySSLUtils.getNextBytes(bb, curIdx);
        String idAC = new String(idACBytes, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + idACBytes.length;

        if (!idAC.equals(CommonValues.AC_ID)) {
            MySSLUtils.printToLogFile("AccessControl","Access Control Ids do not match.");
            return null;
        }

        byte[] tsiBytes = MySSLUtils.getNextBytes(bb, curIdx);
        Instant timestampInitial = Instant.parse(new String(tsiBytes, StandardCharsets.UTF_8));
        curIdx += Integer.BYTES + tsiBytes.length;

        byte[] tsfBytes = MySSLUtils.getNextBytes(bb, curIdx);
        Instant timestampFinal = Instant.parse(new String(tsfBytes, StandardCharsets.UTF_8));
        curIdx += Integer.BYTES + tsfBytes.length;

        if (Instant.now().isAfter(timestampFinal)) {
            MySSLUtils.printToLogFile("AccessControl","Token life expired.");
            return null;
        }

        byte[] keyClientACBytes = MySSLUtils.getNextBytes(bb, curIdx);
        Key keyClientAC = CryptoStuff.parseSymKeyFromBytes(keyClientACBytes);
        curIdx += Integer.BYTES + keyClientACBytes.length;
        System.out.println("Auth key: "+keyClientAC.toString());

        return keyClientAC;
    }

    private static byte[] buildTokenV(byte[] idClientB,byte[] ipClientBytes,byte[] idBytesService,
                                      byte[] ipClientB_auth,byte[] clientSSSymKey_bytes,Instant tsi,Instant tsf,SQL users){
        ByteBuffer bb;
        int curIdx=0;



        String serviceID = new String(idBytesService,StandardCharsets.UTF_8);
        String idClient = new String(idClientB,StandardCharsets.UTF_8);
        String perms;
        try{
            System.out.println("Service ID: " + serviceID);
            System.out.println("Id client " + idClient);
            ResultSet result = users.select("permission",String.format("uid='%s' AND serviceID='%s'",idClient,serviceID));
            System.out.println(result);
            perms = result.getString("permission");
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
        byte[] kvTokenDecrypted = new byte[Integer.BYTES + clientSSSymKey_bytes.length + Integer.BYTES + idBytesService.length+Integer.BYTES
                + idClientB.length + Integer.BYTES + ipClientB_auth.length +
                Integer.BYTES + idBytesService.length + Integer.BYTES + tsi.toString().getBytes().length
                + Integer.BYTES + tsf.toString().getBytes().length + Integer.BYTES + perms.getBytes().length];
        bb = ByteBuffer.wrap(kvTokenDecrypted);
        curIdx = MySSLUtils.putLengthAndBytes(bb, clientSSSymKey_bytes, curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, idBytesService, curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, ipClientBytes, curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, idBytesService, curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, tsi.toString().getBytes(), curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb, tsf.toString().getBytes(), curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb,perms.getBytes(),curIdx);
        byte[] kvTokenEncrypted = CryptoStuff
                .symEncrypt(CryptoStuff.parseSymKeyFromBase64(System.getProperty("SYM_KEY_AC_SS")), kvTokenDecrypted);
        return kvTokenEncrypted;
    }
}
