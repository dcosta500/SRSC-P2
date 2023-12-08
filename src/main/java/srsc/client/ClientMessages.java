package srsc.client;


public abstract class ClientMessages {
    public static final String CLIENT_BOOT_MESSAGE =
            """
                       _____  _  _               _  \s
                      / ____|| |(_)             | | \s
                     | |     | | _   ___  _ __  | |_\s
                     | |     | || | / _ \\| '_ \\ | __|
                     | |____ | || ||  __/| | | || |_\s
                      \\_____||_||_| \\___||_| |_| \\__|
                                                    \s
                                                     \
                    """;

    // Command, Parameters, Description
    private static final String COMMAND_TEMPLATE = "%s : %s - %s\n\n";

    private static final String LOGIN_FORMAT_MESSAGE = String.format(COMMAND_TEMPLATE, "login", "[username] [password]", "[username] Log into the system.");

    private static final String MKDIR_FORMAT_MESSAGE = String.format(COMMAND_TEMPLATE, "mkdir", "[username] [path]", "Creates a new directory in the path [path].");

    private static final String PUT_FORMAT_MESSAGE = String.format(COMMAND_TEMPLATE, "put", "[username] [path]/[file]", "Places a file [file] in the path [path].");

    private static final String GET_FORMAT_MESSAGE = String.format(COMMAND_TEMPLATE, "get", "[username] [path]/[file]", "Gets the file [file] on the path [path].");

    private static final String LIST_FORMAT_MESSAGE = String.format(COMMAND_TEMPLATE, "ls", "[username] [path]",
            "Lists files or directories in path [path], where path is specified as a/b/c starting from [username]'s home directory, on [username]'s home-root on the remote file repository.");

    private static final String LIST_ALL_FORMAT_MESSAGE = String.format(COMMAND_TEMPLATE,"ls", "[username]", "Lists files or directories on [username]'s home-root on the remote file repository.");

    private static final String COPY_FORMAT_MESSAGE = String.format(COMMAND_TEMPLATE, "cp", "[username] [path1]/[file1] [path2]/[file2]",
                                                                                    "Copies file [file1] in path [path1] to file [file2] in path [path2].");

    private static final String FILE_FORMAT_MESSAGE = String.format(COMMAND_TEMPLATE, "file", "[username] [path]/[file]",
            "Shows metadata for file [file] in path [path], showing it's name, whether it's a file or directory, the type of file, creation date and last modification date.");

    private static final String REMOVE_FORMAT_MESSAGE = String.format(COMMAND_TEMPLATE, "rm", "[username] [path]/[file]", "Removes/deletes the file [file] in path [path].");

    private static final String EXIT_FORMAT_MESSAGE = String.format("%s %s", "exit :", "Exits the system.\n");

    public static final String HELP_MESSAGE = "Available Commands: \n\n" +
            LOGIN_FORMAT_MESSAGE +
            LIST_ALL_FORMAT_MESSAGE +
            LIST_ALL_FORMAT_MESSAGE +
            MKDIR_FORMAT_MESSAGE +
            PUT_FORMAT_MESSAGE +
            GET_FORMAT_MESSAGE +
            COPY_FORMAT_MESSAGE +
            REMOVE_FORMAT_MESSAGE +
            FILE_FORMAT_MESSAGE +
            EXIT_FORMAT_MESSAGE;
}
