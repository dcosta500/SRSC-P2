package srsc.client;

public abstract class ClientValidator {
    public static boolean loginValidator(String cmd){
        return cmd.split(" ").length == 3;
    }

    public static boolean mkdirValidator(String cmd) {
        return cmd.split(" ").length == 3;
    }

    public static boolean putValidator(String cmd){
        return cmd.split(" ").length == 3;
    }

    public static boolean listValidator(String cmd) {
        return cmd.split(" ").length == 2 || cmd.split(" ").length == 3;
    }

    public static boolean copyValidator(String cmd){
        return cmd.split(" ").length == 4;
    }

    public static boolean fileValidator(String cmd){
        return cmd.split(" ").length == 3;
    }

    public static boolean getValidator(String cmd) {
        return cmd.split(" ").length == 3;
    }

    public static boolean removeValidator(String cmd) {
        return cmd.split(" ").length == 3;
    }
}
