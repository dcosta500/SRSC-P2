package srsc.servers.AccessControl;

import srsc.utils.CommonValues;
import srsc.utils.CryptoStuff;
import srsc.utils.MySSLUtils;
import srsc.utils.SQL;

import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.ResultSet;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

public abstract class AccessControlCommands {

    private static String idClient_token;

    public static byte[] access(Socket mdSocket, Set<Long> nonceSet, byte[] content, SQL users) {
        /* *
         * Data flow:
         * Receive-1-> { len + ipClient || len + IdServiço || len + Ktoken1024 || len + AuthClient}
         * Send-1 -> { len+KeyC,Serviço || len+IdServiço || len+TSf || len+KvToken }Kc,ac
         *
         * AuthClient = { len + IdClient || len + TS || Nonce }Kc,AC
         *
         * Ktoken1024 = { len + Ktoken1024_content || len + { Ktoken1024_content }SIGauth }Kauth,ac
         * Ktoken1024_content = { len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }
         *
         * Kvtoken = { len + { len + kvtoken_content || len + SIGac( kvtoken_content ) } Kac,s }
         * kvtoken_content = { len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms }
         * */

        // ===== Receive-1 =====
        // { len + ipClient || len + IdServiço || len + Ktoken1024 || len + AuthClient}

        String ipClient;

        ByteBuffer bb = ByteBuffer.wrap(content);

        byte[] ipClientBytes = MySSLUtils.getNextBytes(bb);
        byte[] idBytesService = MySSLUtils.getNextBytes(bb);
        byte[] Ktoken1024 = MySSLUtils.getNextBytes(bb);
        byte[] authClient = MySSLUtils.getNextBytes(bb);

        ipClient = new String(ipClientBytes, StandardCharsets.UTF_8);

        // Unpack token
        Key asAcSymmetricKey = CryptoStuff.parseSymKeyFromBase64(System.getProperty("SYM_KEY_AUTH_AC"));
        byte[] ktoken1024_deciphered = CryptoStuff.symDecrypt(asAcSymmetricKey, Ktoken1024);

        Key clientAC = checkKtoken1024Validity(ktoken1024_deciphered, ipClient);
        if (clientAC == null){
            System.out.println("Ktoken1024 is not valid.");
            return MySSLUtils.buildErrorResponse();
        }

        byte[] idClientBytes = checkClientAuthenticatorValidity(authClient, clientAC, nonceSet);
        if(idClientBytes == null){
            System.out.println("Invalid client authenticator.");
            return MySSLUtils.buildErrorResponse();
        }

        // ===== Send-1 =====
        // { len+KeyC,Serviço || len+IdServiço || len+TSf || len+KvToken }Kc,ac

        Instant tsi = Instant.now();
        Instant tsf = tsi.plus(Duration.ofHours(CommonValues.TOKEN_VALIDITY_HOURS));

        Key client_service_key = CryptoStuff.generateSymKey();
        if(client_service_key == null){
            System.out.println("Could not generate a symmetric key for client and service.");
            return MySSLUtils.buildErrorResponse();
        }
        byte[] client_service_key_bytes = client_service_key.getEncoded();

        byte[] kvToken = buildTokenV(idClientBytes, ipClientBytes, idBytesService, client_service_key_bytes, tsi, tsf, users);
        if (kvToken == null){
            System.out.println("Could not build Kvtoken.");
            return MySSLUtils.buildErrorResponse();
        }

        // Pack, Encrypt and send
        byte[] sendDecrypted = new byte[Integer.BYTES + client_service_key_bytes.length + Integer.BYTES +
                idBytesService.length + Integer.BYTES + tsf.toString().getBytes().length + Integer.BYTES + kvToken.length];
        bb = ByteBuffer.wrap(sendDecrypted);

        MySSLUtils.putLengthAndBytes(bb, client_service_key_bytes, idBytesService, tsf.toString().getBytes(), kvToken);

        byte[] sendEncrypted = CryptoStuff.symEncrypt(clientAC, sendDecrypted);
        return MySSLUtils.buildResponse(CommonValues.OK_CODE, sendEncrypted);
    }

    // ===== AUX METHODS =====
    private static byte[] checkClientAuthenticatorValidity(byte[] clientAuth, Key clientAC, Set<Long> nonceSet) {
        // AuthClient = { len + IdClient || len + TS || Nonce }Kc,ac
        byte[] authClientDecrypted = CryptoStuff.symDecrypt(clientAC, clientAuth);
        ByteBuffer bb = ByteBuffer.wrap(authClientDecrypted);

        byte[] idClientBytes_auth = MySSLUtils.getNextBytes(bb);
        byte[] timestampBytes_auth = MySSLUtils.getNextBytes(bb);
        long nonce = bb.getLong();

        String idClient_auth = new String(idClientBytes_auth, StandardCharsets.UTF_8);
        Instant timestamp_auth = Instant.parse(new String(timestampBytes_auth, StandardCharsets.UTF_8));

        if (Instant.now().isAfter(timestamp_auth.plus(Duration.ofSeconds(CommonValues.CLIENT_AUTHENTICATOR_VALIDITY_SECONDS)))) {
            System.out.println("Auth Client Expired.");
            return null;
        }

        if (!idClient_token.equals(idClient_auth)) {
            System.out.println("Client authenticator is invalid.");
            return null;
        }

        if (nonceSet.contains(nonce)) {
            System.out.println("Retransmission detected.");
            return null;
        }
        nonceSet.add(nonce);

        return idClientBytes_auth;
    }

    private static Key checkKtoken1024Validity(byte[] token, String ipClient) {
        // Ktoken1024 = { len + Ktoken1024_content || len + { Ktoken1024_content }SIGauth }Kauth,ac
        // Ktoken1024_content = { len+uid || len+IPclient || len+IDac || len+TSi || len+TSf || len+Kclient,ac }

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
        /*byte[] tsiBytes =*/ MySSLUtils.getNextBytes(bb);
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

        Instant timestampFinal = Instant.parse(new String(tsfBytes, StandardCharsets.UTF_8));
        if (Instant.now().isAfter(timestampFinal)) {
            MySSLUtils.printToLogFile("AccessControl", "Token life expired.");
            return null;
        }

        return CryptoStuff.parseSymKeyFromBytes(keyClientACBytes);
    }

    private static byte[] buildTokenV(byte[] idClientB, byte[] ipClientBytes, byte[] idBytesService,
                                      byte[] clientSSSymKey_bytes, Instant tsi, Instant tsf, SQL users) {

        // Kvtoken = { len + kvtoken_content || len + SIGac( kvtoken_content ) } Kac,s
        // kvtoken_content = { len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms }

        String serviceID = new String(idBytesService, StandardCharsets.UTF_8);
        String idClient = new String(idClientB, StandardCharsets.UTF_8);
        String perms;

        String condition = String.format("uid='%s' AND serviceID='%s'", idClient, serviceID);
        try (ResultSet result = users.select("permission", condition)) {
            if (!result.next()) {
                System.out.println("User does not have permissions registered for this service");
                return null;
            }

            perms = result.getString("permission");
        } catch (Exception e) {
            System.out.println("Could not complete query for permissions");
            return null;
        }

        if (perms.equals(CommonValues.PERM_DENY)) {
            System.out.println("Permission denied for user");
            return null;
        }

        // kvtoken_content = { len + uid || len + IpClient || len + IdService || len + TSi || len + TSf || len + Kc,s  || len + perms }
        byte[] kvtoken_content = new byte[7 * Integer.BYTES + idClientB.length + ipClientBytes.length + idBytesService.length +
                tsi.toString().getBytes().length + tsf.toString().getBytes().length + clientSSSymKey_bytes.length + perms.length()];

        ByteBuffer bb = ByteBuffer.wrap(kvtoken_content);
        MySSLUtils.putLengthAndBytes(bb, idClientB, ipClientBytes, idBytesService, tsi.toString().getBytes(),
                tsf.toString().getBytes(), clientSSSymKey_bytes, perms.getBytes());

        PrivateKey privateKey = CryptoStuff.getPrivateKeyFromKeystore("ac", "ac123456");
        byte[] signature = CryptoStuff.sign(privateKey, kvtoken_content);

        byte[] fullToken = new byte[2 * Integer.BYTES + kvtoken_content.length + signature.length];
        bb = ByteBuffer.wrap(fullToken);

        MySSLUtils.putLengthAndBytes(bb, kvtoken_content, signature);

        return CryptoStuff.symEncrypt(
                CryptoStuff.parseSymKeyFromBase64(System.getProperty("SYM_KEY_AC_SS")), fullToken);
    }
}
