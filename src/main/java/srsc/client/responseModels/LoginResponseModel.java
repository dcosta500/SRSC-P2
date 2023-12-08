package srsc.client.responseModels;

import srsc.utils.CryptoStuff;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;

public class LoginResponseModel {
    public String username;
    public byte[] ktoken1024;
    public Instant timestampFinal;
    public Key clientAc_SymKey;

    public LoginResponseModel(String username, byte[] ktoken1024, Instant timestampFinal, Key clientAc_SymKey) {
        this.username = username;
        this.ktoken1024 = ktoken1024;
        this.timestampFinal = timestampFinal;
        this.clientAc_SymKey = clientAc_SymKey;
    }

    public static LoginResponseModel parse(String username, byte[] ktoken1024, byte[] tsf, byte[] symKey) {
        Instant timestampFinal = Instant.parse(new String(tsf, StandardCharsets.UTF_8));
        Key k = CryptoStuff.parseSymKeyFromBytes(symKey);
        return new LoginResponseModel(username, ktoken1024, timestampFinal, k);
    }
}
