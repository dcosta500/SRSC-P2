package client.responseModels;

import utils.CryptoStuff;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;

public class AccessResponseModel {
    public byte[] kvtoken;
    public Instant timestampFinal;
    public Key clientService_key;

    public String serviceId;

    public AccessResponseModel(byte[] kvtoken, Instant timestampFinal, Key clientService_key, String serviceId) {
        this.kvtoken = kvtoken;
        this.timestampFinal = timestampFinal;
        this.clientService_key = clientService_key;
        this.serviceId = serviceId;
    }

    public static AccessResponseModel parse(byte[] symKey, byte[] service, byte[] tsf, byte[] kvtoken1024) {
        Instant timestampFinal = Instant.parse(new String(tsf, StandardCharsets.UTF_8));
        Key k = CryptoStuff.parseSymKeyFromBytes(symKey);
        String serviceId = new String(service, StandardCharsets.UTF_8);
        return new AccessResponseModel(kvtoken1024, timestampFinal, k, serviceId);
    }
}
