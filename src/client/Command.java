package client;

public enum Command {
    SUM, MULT, LOGIN;

    public static Command getCommandFromOrdinal(int ordinal) {
        for (Command c : Command.values()) {
            if (c.ordinal() == ordinal)
                return c;
        }
        return null;
    }
}
