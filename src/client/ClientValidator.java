package client;

// TODO: Check validity of commands
public abstract class ClientValidator {
    public static boolean loginValidator(String cmd){
        return cmd.split(" ").length == 3;
    }

    public static boolean makedirValidator(String cmd) {
        return cmd.split(" ").length == 3;
    }

    public static boolean putValidator(String cmd){
        return cmd.split(" ").length == 3;
    }

    public static boolean listValidator(String cmd) {
        return cmd.split(" ").length == 2 || cmd.split(" ").length == 3;
    }
}
