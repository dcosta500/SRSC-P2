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
import java.sql.ResultSet;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

public class AccessControlServer {

    private static String idClient_token;

    public static byte[] access(Socket mdSocket, Set<Long> nonceSet, byte[] content, SQL users) {
        /*
         * Data flow:
         * Receive-1-> { len + ipClient || len + IdServiço || len + Ktoken1024 || len + AuthClient}
         * Send-1 -> { len+KeyC,Serviço || len+IdServiço || len+TSf || len+KvToken }
         *
         * AuthClient = { len + IdClient || len + TS || Nonce }Kc,AC
         *
         * Ktoken1024 = { len + { len + uid || len + IPclient || len + IDac || len + TSi || len + TSf || len + Kclient,ac } ||
         *              len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }SIGauth } Kauth,ac
         *
         * Kvtoken = { len + { len + kvtoken_content || len + SIGac( kvtoken_content ) } Kac,s }
         * kvtoken_content = { len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms }
         */

        // ===== Receive-1 =====
        // { len+ipClient || len+IdServiço || len+Ktoken1024 || len+AuthClient}
        // AuthClient = { len+IdClient || len+ IpClient || len+TS || NONCE }Kc,AC
        // Ktoken1024 = { len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac } ||
        //  Kvtoken=  {len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }{len+SIGauth} } Kauth,ac

        String ipClient;
        String idService;

        ByteBuffer bb = ByteBuffer.wrap(content);

        byte[] ipClientBytes = MySSLUtils.getNextBytes(bb);
        byte[] idBytesService = MySSLUtils.getNextBytes(bb);
        byte[] Ktoken1024 = MySSLUtils.getNextBytes(bb);
        byte[] authClientEncrypted = MySSLUtils.getNextBytes(bb);

        ipClient = new String(ipClientBytes, StandardCharsets.UTF_8);
        idService = new String(idBytesService, StandardCharsets.UTF_8);

        //Unpack token
        Key asAcSymmetricKey = CryptoStuff.parseSymKeyFromBase64(System.getProperty("SYM_KEY_AUTH_AC"));
        byte[] decipheredToken = CryptoStuff.symDecrypt(asAcSymmetricKey, Ktoken1024);

        Key clientAC = checkTokenValidity(decipheredToken, ipClient);
        if (clientAC == null) return MySSLUtils.buildErrorResponse();

        //AuthClient = {len+IdClient || len+TS || NOUNCE}Kc,AC
        byte[] authClientDecrypted = CryptoStuff.symDecrypt(clientAC, authClientEncrypted);

        bb = ByteBuffer.wrap(authClientDecrypted);

        byte[] idClientB_auth = MySSLUtils.getNextBytes(bb);
        byte[] timestampB_auth = MySSLUtils.getNextBytes(bb);

        String idClient_auth = new String(idClientB_auth, StandardCharsets.UTF_8);
        Instant timestamp_auth = Instant.parse(new String(timestampB_auth, StandardCharsets.UTF_8));

        if(Instant.now().isAfter(timestamp_auth.plus(Duration.ofSeconds(5)))){
            System.out.println("Auth Client Expired");
            return MySSLUtils.buildErrorResponse();
        }

        if (!checkClientAuthenticatorValidity(idClient_token, idClient_auth)) {
            System.out.println("Not matching id");
            return MySSLUtils.buildErrorResponse();
        }

        long nonce = bb.getLong();
        if (nonceSet.contains(nonce)) {
            System.out.println("Retransmission detected.");
            return MySSLUtils.buildErrorResponse();
        }
        nonceSet.add(nonce);

        // ===== Send-1 =====
        // { len+KeyC,Serviço || len+IdServiço || len+TSf || len+KvToken }
        //Kvtoken = {  len+uid || len+IpClient || len+IdService|| ||len+TSi || len+TSf || len+Kc,servive  || len+perms || AssAc(token}Kac,s

        Instant tsi = Instant.now();
        Instant tsf = tsi.plus(Duration.ofHours(CommonValues.TOKEN_VALIDITY_HOURS));
        byte[] clientSSSymKey_bytes = CryptoStuff.createSymKey().getEncoded();

        //KvToken
        byte[] kvToken = buildTokenV(idClientB_auth, ipClientBytes, idBytesService, clientSSSymKey_bytes, tsi, tsf, users);
        if(kvToken == null)
            return MySSLUtils.buildErrorResponse();

        byte[] sendDecrypted = new byte[Integer.BYTES + clientSSSymKey_bytes.length + Integer.BYTES +
                idBytesService.length + Integer.BYTES + tsf.toString().getBytes().length + Integer.BYTES + kvToken.length];

        bb = ByteBuffer.wrap(sendDecrypted);
        MySSLUtils.putLengthAndBytes(bb, clientSSSymKey_bytes);
        MySSLUtils.putLengthAndBytes(bb, idBytesService);
        MySSLUtils.putLengthAndBytes(bb, tsf.toString().getBytes());
        MySSLUtils.putLengthAndBytes(bb, kvToken);

        byte[] sendEncrypted = CryptoStuff.symEncrypt(clientAC, sendDecrypted);
        return MySSLUtils.buildResponse(CommonValues.OK_CODE, sendEncrypted);
    }

    // ===== AUX METHODS =====
    private static boolean checkClientAuthenticatorValidity(String idClient_auth, String idClient_token) {
        return idClient_auth.equals(idClient_token);
    }

    private static Key checkTokenValidity(byte[] token, String ipClient) {
        // token = { len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac } ||
        //                len+{ len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }SIGauth }

        ByteBuffer bb = ByteBuffer.wrap(token);

        byte[] tokenContent = MySSLUtils.getNextBytes(bb);
        byte[] tokenSig = MySSLUtils.getNextBytes(bb);

        PublicKey pubKey = CryptoStuff.getPublicKeyFromTruststore("as", "ac123456");
        if (!CryptoStuff.verifySignature(pubKey, tokenContent, tokenSig)) {
            System.out.println("Signature does not match.");
            return null;
        }

        // Unpack further
        bb = ByteBuffer.wrap(tokenContent);

        byte[] idClientBytes = MySSLUtils.getNextBytes(bb);
        byte[] ipClientBytes = MySSLUtils.getNextBytes(bb);
        byte[] idACBytes = MySSLUtils.getNextBytes(bb);
        byte[] tsiBytes = MySSLUtils.getNextBytes(bb);
        byte[] tsfBytes = MySSLUtils.getNextBytes(bb);
        byte[] keyClientACBytes = MySSLUtils.getNextBytes(bb);

        idClient_token = new String(idClientBytes, StandardCharsets.UTF_8);
        String ipClientFromToken = new String(ipClientBytes, StandardCharsets.UTF_8);
        if (!ipClient.equals(ipClientFromToken)) {
            System.out.println("Client ips do not match.");
            return null;
        }

        String idAC = new String(idACBytes, StandardCharsets.UTF_8);
        if (!idAC.equals(CommonValues.AC_ID)) {
            System.out.println("Access Control Ids do not match.");
            return null;
        }

        //Instant timestampInitial = Instant.parse(new String(tsiBytes, StandardCharsets.UTF_8));
        Instant timestampFinal = Instant.parse(new String(tsfBytes, StandardCharsets.UTF_8));
        if (Instant.now().isAfter(timestampFinal)) {
            MySSLUtils.printToLogFile("AccessControl", "Token life expired.");
            return null;
        }

        return CryptoStuff.parseSymKeyFromBytes(keyClientACBytes);
    }

    private static byte[] buildTokenV(byte[] idClientB, byte[] ipClientBytes, byte[] idBytesService,
                                      byte[] clientSSSymKey_bytes, Instant tsi, Instant tsf, SQL users) {
        ByteBuffer bb;

        String serviceID = new String(idBytesService, StandardCharsets.UTF_8);
        String idClient = new String(idClientB, StandardCharsets.UTF_8);
        String perms;

        String condition = String.format("uid='%s' AND serviceID='%s'", idClient, serviceID);
        try(ResultSet result = users.select("permission", condition)) {
            if(!result.next()){
                System.out.println("User does not have permissions registered for this service");
                return null;
            }

            perms = result.getString("permission");
        } catch (Exception e) {
            System.out.println("Could not complete query for permissions");
            e.printStackTrace();
            return null;
        }

        if(perms.equals(CommonValues.PERM_DENY)){
            System.out.println("Permission denied for user");
            return null;
        }
        //Kvtoken = {  len+uid || len+IpClient || len+IdService|| ||len+TSi || len+TSf || len+Kc,servive  || len+perms || AssAc(token}Kac,s
        byte[] kvTokenDecrypted1stPart = new byte[7 * Integer.BYTES + clientSSSymKey_bytes.length + +idClientB.length +
                ipClientBytes.length + idBytesService.length + tsi.toString().getBytes().length +
                tsf.toString().getBytes().length + perms.getBytes().length];

        bb = ByteBuffer.wrap(kvTokenDecrypted1stPart);
        MySSLUtils.putLengthAndBytes(bb, idClientB);
        MySSLUtils.putLengthAndBytes(bb, ipClientBytes);
        MySSLUtils.putLengthAndBytes(bb, idBytesService);
        MySSLUtils.putLengthAndBytes(bb, tsi.toString().getBytes());
        MySSLUtils.putLengthAndBytes(bb, tsf.toString().getBytes());
        MySSLUtils.putLengthAndBytes(bb, clientSSSymKey_bytes);
        MySSLUtils.putLengthAndBytes(bb, perms.getBytes());


        byte[] signature = CryptoStuff.sign(CryptoStuff.getPrivateKeyFromKeystore("ac","ac123456"),kvTokenDecrypted1stPart);
        byte[] fullToken = new byte[2*Integer.BYTES + kvTokenDecrypted1stPart.length + signature.length];
        bb = ByteBuffer.wrap(fullToken);
        MySSLUtils.putLengthAndBytes(bb,kvTokenDecrypted1stPart);
        MySSLUtils.putLengthAndBytes(bb,signature);

        return CryptoStuff.symEncrypt(
                CryptoStuff.parseSymKeyFromBase64(System.getProperty("SYM_KEY_AC_SS")), fullToken);
    }
}
