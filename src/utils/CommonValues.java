package utils;

public abstract class CommonValues {

    //Hostname Values
    public static final String MD_HOSTNAME = "localhost";
    public static final String AS_HOSTNAME = "authentication";
    public static final String AC_HOSTNAME = "access_control";
    public static final String SS_HOSTNAME = "storage_service";

    // Service IDs
    public static final String STORAGE_SERVICE_ID = "storage";

    // Port values
    public static final int CLIENT_PORT_NUMBER = 9000;
    public static final int MD_PORT_NUMBER = 8080;
    public static final int AS_PORT_NUMBER = 8081;
    public static final int AC_PORT_NUMBER = 8082;
    public static final int SS_PORT_NUMBER = 8083;

    // Access Permissions
    public static final String PERM_DENY = "deny";
    public static final String PERM_READ = "allow read";
    public static final String PERM_READ_WRITE = "allow read write";

    // Server IDs
    public static final String AUTH_ID = "auth";
    public static final String AC_ID = "access_control";

    public static final String SS_ID = "storage";

    // Time
    public static final int CLIENT_AUTHENTICATOR_VALIDITY_SECONDS = 5;
    public static final int TOKEN_VALIDITY_HOURS = 24;

    // Packages
    public static final int DATA_SIZE = 16_383; // Max buffer size for macOS

    // Error Codes
    public static final int OK_CODE = 0;
    public static final int ERROR_CODE = -1;
}
