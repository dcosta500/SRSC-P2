package utils;

public enum Command {

    LOGIN("login", true), ACCESS("access", true), // Access is an internal command and is not available to users

    LIST("ls", true), PUT("put", true), GET("get", true),
    COPY("cp", true), REMOVE("rm", true), MKDIR("mkdir", true),
    FILE("file", true),

    HELP("help", false), EXIT("exit", false), UNKNOWN("unknown", false);

    public final String value;
    private final boolean needsConnection;

    Command(String value, boolean needsConnection) {
        this.value = value;
        this.needsConnection = needsConnection;
    }

    public static Command getCommandFromOrdinal(int ordinal) {
        for (Command c : Command.values()) {
            if (c.ordinal() == ordinal)
                return c;
        }
        return null;
    }

    public boolean needsConnection() {
        return this.needsConnection;
    }
}
