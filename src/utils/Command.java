package utils;

public enum Command {

    STATS("stats"),
    LOGIN("login"), ACCESS("access"),
    LIST("ls"), PUT("put"), GET("get"), COPY("cp"), REMOVE("rm"), MKDIR("mkdir"), FILECMD("file");

    public String value;

    Command(String value){
        this.value = value;
    }

    public static Command getCommandFromOrdinal(int ordinal) {
        for (Command c : Command.values()) {
            if (c.ordinal() == ordinal)
                return c;
        }
        return null;
    }
}
