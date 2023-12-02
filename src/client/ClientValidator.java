package client;

// TODO: Check validity of commands
public abstract class ClientValidator {
    public static boolean loginValidator(String cmd){
        return cmd.split(" ").length == 3;
    }

    public static boolean accessValidator(String cmd){
        return cmd.split(" ").length == 2;
    }
}
