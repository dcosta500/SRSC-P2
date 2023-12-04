package servers.StorageSystemService;


import utils.CommonValues;
import utils.DataPackage;
import utils.MySSLUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;


public class SSServer {

    private static final String SERVER_TRUSTSTORE_PATH = "certs/ssCrypto/ss_truststore";
    private static final String SERVER_KEYSTORE_PATH = "certs/ssCrypto/keystore_ss.jks";
    private static final String PASSWORD = "ss123456";
    private static final boolean DO_CLIENT_AUTH = true;
    private static final Set<Long> nonceSet = new HashSet<>();
    private static final String[] usernames = { "alice", "bob", "carol", "david", "eric" };
    private static final String DEFAULT_DIR = System.getProperty("user.dir")+"/data";

    private static byte[] executeCommand(Socket socket, DataPackage dp) {
        switch (dp.getCommand()) {
            case GET:
                return StorageServiceServer.get(socket,dp.getContent(),nonceSet);
            case PUT:
                return StorageServiceServer.put(socket,dp.getContent(),nonceSet);
            case LIST:
                return StorageServiceServer.list(socket,dp.getContent(), nonceSet);
            case REMOVE:
                return StorageServiceServer.remove(socket,dp.getContent(),nonceSet);
            case COPY:
                return StorageServiceServer.copy(socket,dp.getContent(),nonceSet);
            case MKDIR:
                return StorageServiceServer.mkdir(socket,dp.getContent(),nonceSet);
            case FILECMD:
                return StorageServiceServer.file(socket,dp.getContent(),nonceSet);
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
        for (String user : usernames){
            String directoryPath = DEFAULT_DIR+"/"+user;
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

        ServerSocket ss = MySSLUtils.createServerSocket(CommonValues.SS_PORT_NUMBER, SERVER_KEYSTORE_PATH, PASSWORD,
                DO_CLIENT_AUTH);


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
