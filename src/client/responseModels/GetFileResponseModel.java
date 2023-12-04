package client.responseModels;

public class GetFileResponseModel {

    private byte[] response;

    public GetFileResponseModel(byte[] response) {
        this.response = response;
    }

    public byte[] getResponse() {
        return response;
    }
}
