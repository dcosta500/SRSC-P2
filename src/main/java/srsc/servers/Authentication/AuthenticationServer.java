package srsc.servers.Authentication;

import srsc.utils.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;


public class AuthenticationServer {
    private static final String SERVER_TRUSTSTORE_PATH = "certs/asCrypto/as_truststore";
    private static final String SERVER_KEYSTORE_PATH = "certs/asCrypto/keystore_as.jks";

    private static final String[] usernames = { "alice", "bob", "carol", "david", "eric" };
    private static final String PASSWORD = "as123456";

    private static SQL users;

    private static  final Map<String, byte[]> SALT_MAP = new HashMap<>(Map.ofEntries(
            Map.entry("alice", new byte[]{(byte) 14, (byte) 7, (byte) 212, (byte) 157, (byte) 18, (byte) 147, (byte) 221, (byte) 49}),
            Map.entry("bob", new byte[]{(byte) 15, (byte) 8, (byte) 213, (byte) 158, (byte) 19, (byte) 148, (byte) 222, (byte) 50}),
            Map.entry("carol", new byte[]{(byte) 16, (byte) 9, (byte) 214, (byte) 159, (byte) 20, (byte) 149, (byte) 223, (byte) 51}),
            Map.entry("david", new byte[]{(byte) 17, (byte) 10, (byte) 215, (byte) 160, (byte) 21, (byte) 150, (byte) 224, (byte) 52}),
            Map.entry("eric", new byte[]{(byte) 18, (byte) 11, (byte) 216, (byte) 161, (byte) 22, (byte) 151, (byte) 225, (byte) 53})
    ));

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
                byte[] salt = SALT_MAP.get(uname);
                String hPwd = CryptoStuff.pbeHashing(salt,uname + "123456");

                String hPwdEncrypted = CryptoStuff.bytesToB64(CryptoStuff.symEncrypt(key, hPwd.getBytes()));
                String saltb64 = CryptoStuff.bytesToB64(salt);
                users.insert(uname, uname + "@mail.com", hPwdEncrypted, saltb64, true);
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