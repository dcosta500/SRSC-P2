package servers.AccessControlServer;

import servers.AuthenticationServer.AuthUsersSQL;
import utils.CryptoStuff;
import utils.MySSLUtils;

import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class AccessControlServer {
    public static byte[] access(Socket mdSocket,byte[] content) {
        /*
         * Data flow:
         * Receive-1-> { len+ipClient || len+IdServiço || len+token1024 || len+AuthClient}
         * AuthClient = {len+IdClient || len+ IpClient || len+TS || NOUNCE}Kc,AC
         * Send-1 -> { len+KeyC,Serviço || len+IdServiço || len+TSf || len+KvToken }
         */

        String ipClientR1;
        String uidService;

        int curIdx = 0;
        ByteBuffer bb = ByteBuffer.wrap(content);


        //Receive-1-> { len+ipClient || len+IdServiço || len+token1024 || len+AuthClient}
        byte[] ipClientBytesR1 = MySSLUtils.getNextBytes(bb, curIdx);
        ipClientR1 = new String(ipClientBytesR1, StandardCharsets.UTF_8);
        curIdx += Integer.BYTES + ipClientBytesR1.length;

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


        //Ktoken -> {len+IdClient || len+IpClient || len+IdAC || len+TSi || len+TSf || len+Kcac || len+Ass(All)
        bb = ByteBuffer.wrap(decipheredToken);
        curIdx = 0;

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
        Key keyClientAc = CryptoStuff.parseSymKeyFromBytes(key_tokenB);
        curIdx += Integer.BYTES + key_tokenB.length;

        byte[] ass_tokenB = MySSLUtils.getNextBytes(bb,curIdx);
        PublicKey privKey = CryptoStuff.getPublicKeyFromTruststore("as", "ac123456");




















        return null;
    }
}
