package client.responseModels;

public class ListResponseModel {
    private String files;

    public ListResponseModel(String files) {
        this.files = files;
    }

    public String getFiles() {
        return files;
    }
}
