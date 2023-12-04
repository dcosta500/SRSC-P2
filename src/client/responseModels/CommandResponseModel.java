package client.responseModels;

public class CommandResponseModel {
    private final String response;

    public CommandResponseModel(String response) {
        this.response = response;
    }

    public String getResponse() {
        return response;
    }
}
