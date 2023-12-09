package srsc.servers.AccessControl;

import srsc.utils.CommonValues;
import srsc.utils.DataPackage;
import srsc.utils.MySSLUtils;
import srsc.utils.SQL;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;


public class AccessControlServer {

    private static final String SERVER_TRUSTSTORE_PATH = "certs/acCrypto/ac_truststore";
    private static final String SERVER_KEYSTORE_PATH = "certs/acCrypto/keystore_ac.jks";
    private static final String PASSWORD = "ac123456";

    private static final String[] usernames = {"alice", "bob", "carol", "david", "eric"};

    private static final Set<Long> nonceSet = new HashSet<>();

    private static SQL users;

    private static byte[] executeCommand(Socket socket, DataPackage dp) {
        switch (dp.command()) {
            case ACCESS:
                return AccessControlCommands.access(socket, nonceSet, dp.content(), users);
            default:
                System.out.println("Received unknown command.");
                return new byte[0];
        }
    }

    private static void launchWorker(Socket socket) {
        new Thread() {
            @Override
            public void run() {
                try {
                    byte[] dataIn = MySSLUtils.receiveData(socket);
                    DataPackage dp = DataPackage.parse(dataIn);

                    byte[] result = executeCommand(socket, dp);
                    MySSLUtils.sendData(socket, result);

                    socket.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }.start();
    }

    private static void initConf() {
        Properties props = new Properties();
        String curDir = System.getProperty("user.dir");

        try (FileInputStream input = new FileInputStream(curDir + "/configs/access_control_server.conf")) {
            props.load(input);
            System.setProperty("SYM_KEY_AUTH_AC", props.getProperty("SYM_KEY_AUTH_AC"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        try (FileInputStream input = new FileInputStream(curDir + "/configs/access_control_server.conf")) {
            props.load(input);
            System.setProperty("SYM_KEY_AC_SS", props.getProperty("SYM_KEY_AC_SS"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void initDb() {
        try {
            Class.forName("org.sqlite.JDBC");

            users = new AccessControlUsersSQL("users", "perms.db");
            users.insert(usernames[0], CommonValues.SS_ID, CommonValues.PERM_READ_WRITE);
            users.insert(usernames[1], CommonValues.SS_ID, CommonValues.PERM_READ_WRITE);
            users.insert(usernames[2], CommonValues.SS_ID, CommonValues.PERM_READ);
            users.insert(usernames[3], CommonValues.SS_ID, CommonValues.PERM_DENY);
            users.insert(usernames[4], CommonValues.SS_ID, CommonValues.PERM_DENY);
        } catch (Exception e) {
            System.out.println("Error while trying to initialize database.");
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.ssl.trustStore", SERVER_TRUSTSTORE_PATH);

        initDb();
        initConf();

        ServerSocket ss = MySSLUtils.createServerSocket(CommonValues.AC_PORT_NUMBER, SERVER_KEYSTORE_PATH, PASSWORD);

        while (true) {
            Socket socket;
            try {
                System.out.println("Waiting for connection...");
                socket = ss.accept();
                System.out.println("Accepted a connection.");
            } catch (IOException e) {
                System.out.println("Server died: " + e.getMessage());
                e.printStackTrace();
                break;
            }
            launchWorker(socket);
        }
        ss.close();
    }
}
