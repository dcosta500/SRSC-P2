package srsc.servers.StorageService;


import srsc.utils.CommonValues;
import srsc.utils.CryptoStuff;
import srsc.utils.DataPackage;
import srsc.utils.MySSLUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;


public class StorageServiceServer {

    private static final String SERVER_TRUSTSTORE_PATH = "certs/ssCrypto/ss_truststore";
    private static final String SERVER_KEYSTORE_PATH = "certs/ssCrypto/keystore_ss.jks";
    private static final String PASSWORD = "ss123456";
    private static final Set<Long> nonceSet = new HashSet<>();
    private static final String[] usernames = { "alice", "bob", "carol", "david", "eric" };
    private static final String DEFAULT_DIR = System.getProperty("user.dir")+"/data";

    private static byte[] executeCommand(Socket socket, DataPackage dp) {
        switch (dp.command()) {
            case GET:
                return StorageServiceCommands.get(socket,dp.content(),nonceSet);
            case PUT:
                return StorageServiceCommands.put(socket,dp.content(),nonceSet);
            case LIST:
                return StorageServiceCommands.list(socket,dp.content(), nonceSet);
            case REMOVE:
                return StorageServiceCommands.remove(socket,dp.content(),nonceSet);
            case COPY:
                return StorageServiceCommands.copy(socket,dp.content(),nonceSet);
            case MKDIR:
                return StorageServiceCommands.mkdir(socket,dp.content(),nonceSet);
            case FILE:
                return StorageServiceCommands.file(socket,dp.content(),nonceSet);
            default:
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
        try (FileInputStream input = new FileInputStream(curDir + "/configs/storage_server.conf")) {
            props.load(input);
            System.setProperty("SYM_KEY_AC_SS", props.getProperty("SYM_KEY_AC_SS"));
            System.setProperty("PRIVATE_SYM_KEY", props.getProperty("PRIVATE_SYM_KEY"));
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private static void initDirs(){
        Key key = CryptoStuff.parseSymKeyFromBase64(System.getProperty("PRIVATE_SYM_KEY"));

        for (String user : usernames){

            //Encrypt userName to string using base 64 and key
            byte[] encryptedUserName = CryptoStuff.symEncrypt(key, user.getBytes());
            String encryptedUserNameString = CryptoStuff.bytesToB64(encryptedUserName);
            String directoryPath = DEFAULT_DIR+"/"+encryptedUserNameString;
            // Create a File object representing the directory
            File directory = new File(directoryPath);
            // Check if the directory doesn't exist, then create it
            if (!directory.exists()) {
                boolean success = directory.mkdirs(); // mkdirs() creates parent directories if they don't exist
                if (success) {
                    System.out.println("Directory created successfully");
                } else {
                    System.err.println("Failed to create directory");
                }
            } else {
                System.out.println("Directory already exists");
            }
        }
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.ssl.trustStore", SERVER_TRUSTSTORE_PATH);

        initConf();
        initDirs();

        ServerSocket ss = MySSLUtils.createServerSocket(CommonValues.SS_PORT_NUMBER, SERVER_KEYSTORE_PATH, PASSWORD);


        while (true) {
            Socket socket;
            try {
                System.out.println("Waiting for connection...");
                assert ss != null;
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
