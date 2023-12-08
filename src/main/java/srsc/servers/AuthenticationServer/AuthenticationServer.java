package srsc.servers.AuthenticationServer;

import srsc.utils.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Properties;


public class AuthenticationServer {
    private static final String SERVER_TRUSTSTORE_PATH = "certs/asCrypto/as_truststore";
    private static final String SERVER_KEYSTORE_PATH = "certs/asCrypto/keystore_as.jks";

    private static final String[] usernames = { "alice", "bob", "carol", "david", "eric" };
    private static final String PASSWORD = "as123456";

    private static SQL users;

    private static byte[] executeCommand(Socket socket, DataPackage dp) {
        switch (dp.command()) {
            case LOGIN:
                return AuthenticationCommands.login(socket, users, dp.content());
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

    private static void initDb() {
        try {
            Class.forName("org.sqlite.JDBC");

            users = new AuthenticationUsersSQL("users","auth.db");

            String keyb64 = System.getProperty("PRIV_SYM_KEY");

            Key key = CryptoStuff.parseSymKeyFromBase64(keyb64);
            for (String uname : usernames) {
                String hPwd = CryptoStuff.pbeHashing(uname + "123456");

                String hPwdEncrypted = Base64.getEncoder().encodeToString(CryptoStuff.symEncrypt(key, hPwd.getBytes()));
                users.insert(uname, uname + "@mail.com", hPwdEncrypted, true);
            }

        } catch (Exception e) {
            System.out.println("Error while trying to initialize database.");
            e.printStackTrace();
        }
    }

    private static void initConf() {
        Properties props = new Properties();
        String curDir = System.getProperty("user.dir");
        try (FileInputStream input = new FileInputStream(curDir + "/configs/auth_server.conf")) {
            props.load(input);
            System.setProperty("SYM_KEY_AUTH_AC", props.getProperty("SYM_KEY_AUTH_AC"));
            System.setProperty("PRIV_SYM_KEY", props.getProperty("PRIV_SYM_KEY"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.ssl.trustStore", SERVER_TRUSTSTORE_PATH);

        initConf();
        initDb();

        ServerSocket ss = MySSLUtils.createServerSocket(CommonValues.AS_PORT_NUMBER, SERVER_KEYSTORE_PATH, PASSWORD);

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