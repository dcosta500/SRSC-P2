package utils;

public enum Command {
    SUM, MULT, STATS, LOGIN, ACCESS, STORAGE;

    public static Command getCommandFromOrdinal(int ordinal) {
        for (Command c : Command.values()) {
            if (c.ordinal() == ordinal)
                return c;
        }
        return null;
    }
}
