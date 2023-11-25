package client.responseModels;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;

import utils.CryptoStuff;

public class LoginResponseModel {
    public byte[] ktoken1024;
    public Instant timestampFinal;
    public Key clientAc_SymKey;

    public LoginResponseModel(byte[] ktoken1024, Instant timestampFinal, Key clientAc_SymKey) {
        this.ktoken1024 = ktoken1024;
        this.timestampFinal = timestampFinal;
        this.clientAc_SymKey = clientAc_SymKey;
    }

    public static LoginResponseModel parse(byte[] ktoken1024, byte[] tsf, byte[] symKey) {
        Instant timestampFinal = Instant.parse(new String(tsf, StandardCharsets.UTF_8));
        Key k = CryptoStuff.parseSymKeyFromBytes(symKey);

        return new LoginResponseModel(ktoken1024, timestampFinal, k);
    }
}
