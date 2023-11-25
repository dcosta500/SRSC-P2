package utils;

public abstract class CommonValues {
    public static final String MD_HOSTNAME = "localhost";
    public static final String AS_HOSTNAME = "localhost";
    public static final String AC_HOSTNAME = "localhost";
    public static final String SS_HOSTNAME = "localhost";

    public static final int CLIENT_PORT_NUMBER = 9000;
    public static final int MD_PORT_NUMBER = 8080;
    public static final int AS_PORT_NUMBER = 8081;
    public static final int AC_PORT_NUMBER = 8082;
    public static final int SS_PORT_NUMBER = 8083;

    // Server IDs
    public static final String AUTH_ID = "auth";

    // Time
    public static final int TOKEN_VALIDITY_HOURS = 24;

    // Packages
    public static final int DATA_SIZE = 4096;

    // Error Codes
    public static final int OK_CODE = 0;
    public static final int ERROR_CODE = -1;
}
