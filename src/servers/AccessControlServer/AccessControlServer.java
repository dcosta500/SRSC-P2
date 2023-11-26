package servers.AccessControlServer;

import servers.AuthenticationServer.AuthUsersSQL;
import utils.CommonValues;
import utils.CryptoStuff;
import utils.MySSLUtils;

import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;

public class AccessControlServer {
    public static byte[] access(Socket mdSocket,byte[] content) {
        /*
         * Data flow:
         * Receive-1-> { len+ipClient || len+IdServiço || len+token1024 || len+AuthClient}
         * AuthClient = {len+IdClient || len+ IpClient || len+TS || NOUNCE}Kc,AC
         * Send-1 -> { len+KeyC,Serviço || len+IdServiço || len+TSf || len+KvToken }
         */

        String ipClient;
        String uidService;

        int curIdx = 0;
        ByteBuffer bb = ByteBuffer.wrap(content);


        //Receive-1-> { len+ipClient || len+IdServiço || len+token1024 || len+AuthClient}
        byte[] ipClientBytes = MySSLUtils.getNextBytes(bb, curIdx);
        ipClient = new String(ipClientBytes, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + ipClientBytes.length;

        byte[] uidBytesService = MySSLUtils.getNextBytes(bb, curIdx);
        uidService = new String(uidBytesService, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + uidBytesService.length;

        byte[] cipheredToken= MySSLUtils.getNextBytes(bb, curIdx);
        curIdx += Integer.BYTES +cipheredToken.length;

        byte[] authClientEncrypted = MySSLUtils.getNextBytes(bb, curIdx);
        curIdx += Integer.BYTES + authClientEncrypted.length;


        //Unpack token
        Key asAcSymmetricKey = CryptoStuff.parseSymKeyFromBase64(System.getProperty("SYM_KEY_AUTH_AC"));
        byte[] decipheredToken = CryptoStuff.symDecrypt(asAcSymmetricKey,cipheredToken);

        Key clientAC = checkToken(decipheredToken,ipClient);
        if(clientAC==null) return null;

        //AuthClient = {len+IdClient || len+ IpClient || len+TS || NOUNCE}Kc,AC
        byte[] authClientDecrypted = CryptoStuff.symDecrypt(clientAC,authClientEncrypted);

        bb = ByteBuffer.wrap(authClientDecrypted);
        curIdx=0;


        byte[] idClientB = MySSLUtils.getNextBytes(bb,curIdx);
        String idClient = new String(idClientB,StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + idClientB.length;

        byte[] ipClientB_auth = MySSLUtils.getNextBytes(bb,curIdx);
        String ipClient_auth = new String(ipClientB_auth,StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + ipClientB_auth.length;

        byte[] timestampB_auth = MySSLUtils.getNextBytes(bb,curIdx);
        Instant timestamp_auth = Instant.parse(new String(timestampB_auth,StandardCharsets.UTF_8));
        curIdx += Integer.BYTES + timestampB_auth.length;

        long nounce = bb.getLong(curIdx); //TODO guarantee that Nounce doesnt repeat

        //Send-1 -> { len+KeyC,Serviço || len+IdServiço || len+TSf || len+KvToken }

        Instant tsi = Instant.now();
        Instant tsf= tsi.plus(Duration.ofHours(CommonValues.TOKEN_VALIDITY_HOURS));
        byte[] clientSSSymKey_bytes = CryptoStuff.createSymKey().getEncoded();

        //KvToken -> {len+KcService || len+IdClient || len+IpClient || len+IdService || len+Tsi || len+Tsf
        byte[] kvTokenDecrypted = new byte[Integer.BYTES + clientSSSymKey_bytes.length+Integer.BYTES +Integer.BYTES+idClientB.length+Integer.BYTES+ipClientB_auth.length+
                Integer.BYTES + uidBytesService.length+ Integer.BYTES+tsi.toString().getBytes().length + Integer.BYTES + tsf.toString().getBytes().length];
        bb = ByteBuffer.wrap(kvTokenDecrypted);
        curIdx=0;
        curIdx = MySSLUtils.putLengthAndBytes(bb,clientSSSymKey_bytes,curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb,uidBytesService,curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb,ipClientBytes,curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb,uidBytesService,curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb,tsi.toString().getBytes(),curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb,tsf.toString().getBytes(),curIdx);
        byte[] kvTokenEncrypted = CryptoStuff.symEncrypt(CryptoStuff.parseSymKeyFromBase64(System.getProperty("SYM_KEY_AC_SS")),kvTokenDecrypted);


        byte[] sendDecrypted = new byte[Integer.BYTES + clientSSSymKey_bytes.length + Integer.BYTES+uidBytesService.length+
                Integer.BYTES+tsf.toString().getBytes().length+Integer.BYTES+ kvTokenEncrypted.length];

        bb = ByteBuffer.wrap(sendDecrypted);
        curIdx=0;
        curIdx= MySSLUtils.putLengthAndBytes(bb,clientSSSymKey_bytes,curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb,uidBytesService,curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb,tsf.toString().getBytes(),curIdx);
        curIdx = MySSLUtils.putLengthAndBytes(bb,kvTokenEncrypted,curIdx);

        byte[] sendEncrypted = CryptoStuff.symEncrypt(clientAC,sendDecrypted);


        return MySSLUtils.buildResponse(CommonValues.OK_CODE, sendEncrypted);
    }


    private static Key checkToken(byte[] token, String ip){
        ByteBuffer bb;
        int curIdx=0;
        //Ktoken -> {len+IdClient || len+IpClient || len+IdAC || len+TSi || len+TSf || len+Kcac || len+Ass(All)
        bb = ByteBuffer.wrap(token);


        byte[] idClient_tokenB = MySSLUtils.getNextBytes(bb,curIdx);
        String idClient_token = new String(idClient_tokenB,StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + idClient_tokenB.length;


        byte[] ipClient_token = MySSLUtils.getNextBytes(bb,curIdx);
        String ipClient = new String(ipClient_token,StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + idClient_tokenB.length;

        byte[] idAC_tokenB = MySSLUtils.getNextBytes(bb,curIdx);
        String idAC_token = new String(idAC_tokenB,StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + idAC_tokenB.length;


        byte[] tsi_tokenB = MySSLUtils.getNextBytes(bb,curIdx);
        Instant timestampInitial = Instant.parse(new String(tsi_tokenB, StandardCharsets.UTF_8));
        curIdx += Integer.BYTES + tsi_tokenB.length;

        byte[] tsf_tokenB = MySSLUtils.getNextBytes(bb,curIdx);
        Instant timestampFinal = Instant.parse(new String(tsf_tokenB, StandardCharsets.UTF_8));
        curIdx += Integer.BYTES + tsf_tokenB.length;



        byte[] key_tokenB = MySSLUtils.getNextBytes(bb,curIdx);
        Key key = CryptoStuff.parseSymKeyFromBytes(key_tokenB);
        curIdx += Integer.BYTES + key_tokenB.length;

        byte[] tokenNoSign = new byte[curIdx];
        System.arraycopy(token ,0, tokenNoSign, 0, curIdx);

        byte[] sign_tokenB = MySSLUtils.getNextBytes(bb,curIdx);
        PublicKey pubKey = CryptoStuff.getPublicKeyFromTruststore("as", "ac123456");

        boolean checkSignature = CryptoStuff.verifySignature(pubKey,tokenNoSign,sign_tokenB);


        return (ip.equals(ipClient) && checkSignature && idAC_token.equals(CommonValues.AC_ID) && Instant.now().isAfter(timestampFinal)) ? key : null;
    }
}
