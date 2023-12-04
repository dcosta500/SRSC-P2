package client.responseModels;

public class PutFileResponseModel {
    private String message;

    public PutFileResponseModel(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
