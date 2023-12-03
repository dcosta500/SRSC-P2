package client;

import javax.net.ssl.*;

import client.responseModels.LoginResponseModel;
import client.responseModels.MakedirResponseModel;
import utils.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.util.Properties;
import java.util.Scanner;

public class Client {
    private static final String CLIENT_BOOT_MESSAGE =
            "   _____  _  _               _   \n" +
                    "  / ____|| |(_)             | |  \n" +
                    " | |     | | _   ___  _ __  | |_ \n" +
                    " | |     | || | / _ \\| '_ \\ | __|\n" +
                    " | |____ | || ||  __/| | | || |_ \n" +
                    "  \\_____||_||_| \\___||_| |_| \\__|\n" +
                    "                                 \n" +
                    "                                 ";
    private static String uid;

    private static SSLSocketFactory factory;
    private static SSLSocket socket;
    private static String USERNAME_LOGGED = "";
    private static final String PASSWORD = "cl123456";

    private static byte[] auth_ktoken1024;
    private static Key client_ac_key;

    private static byte[] control_vtoken1024;
    private static Key client_ss_key;

    private static void readCommands() {
        /* *
         * Instructions to add a new command
         * 1- Create command enum in Command.java
         * 2- Add Command enum to both switches (client and server)
         * 3- Create method in ClientCommands
         * 4- Create command in MainDispatcher class (not MainDispatcherServer class)
         * 5- Create command in respective server
         * 6- Create in this class a method and the postProcessing for that command
         */

        // TODO: Add exit and help instructions. Add support for unknown instruction
        Scanner in = new Scanner(System.in);

        masterLoop:
        while (true) {
            // TODO: Maybe we should only open the socket if the command exists.
            socket = MySSLUtils.startNewConnectionToServer(factory, CommonValues.MD_HOSTNAME,
                    CommonValues.MD_PORT_NUMBER);

            System.out.print(USERNAME_LOGGED + "Command -> ");
            String cmd = in.nextLine();
            switch (Command.valueOf(cmd.split(" ")[0].toUpperCase())) {
                case SUM:
                    ClientCommands.sum(socket);
                    break;
                case MULT:
                    ClientCommands.mult(socket);
                    break;
                case STATS:
                    ClientCommands.stats(socket);
                    break;
                case LOGIN:
                    login(cmd);
                    break;
                case MKDIR:
                    makedir(cmd);
                    break;
                default:
                    break masterLoop;
            }
            MySSLUtils.closeConnectionToServer(socket);
            System.out.println();
        }

    }

    // ===== COMMAND PROCESSING =====
    private static void login(String cmd){
        if (!ClientValidator.loginValidator(cmd)){
            System.out.println("Command is not correctly formatted");
            return;
        }

        String name = cmd.split(" ")[1];
        if(!name.equals(uid)){
            System.out.printf("This is not %s's computer.\n", name);
            return;
        }

        LoginResponseModel lrm = ClientCommands.login(socket, cmd);
        processLoginResponse(lrm);
    }

    private static void processLoginResponse(LoginResponseModel lrm) {
        if (lrm == null) {
            return;
        }

        USERNAME_LOGGED = lrm.username + ":";
        auth_ktoken1024 = lrm.ktoken1024;
        System.out.println("Login successfully done at: " + lrm.timestampFinal.toString());
        client_ac_key = lrm.clientAc_SymKey;
    }

    /*private static void access(String cmd){
        if (!ClientValidator.accessValidator(cmd)){
            System.out.println("Command is not correctly formatted");
            return;
        }

        if (auth_ktoken1024 == null || auth_ktoken1024.length == 0) {
            System.out.println("You haven't logged in yet.");
            return;
        }

        AccessResponseModel arm = ClientCommands.access(socket, auth_ktoken1024, null, client_ac_key, uid, cmd);
        processAccessControlResponse(arm);
    }

    private static void processAccessControlResponse(AccessResponseModel arm) {
        if (arm == null) {
            return;
        }

        control_vtoken1024 = arm.kvtoken;
        System.out.println("Access Control granted successfully done at: " + arm.timestampFinal.toString());
        client_ss_key = arm.clientService_key;
    }*/

    private static void makedir(String cmd) {
        if (!ClientValidator.makedirValidator(cmd)){
            System.out.println("Command is not correctly formatted");
            return;
        }

        if (auth_ktoken1024 == null || auth_ktoken1024.length == 0) {
            System.out.println("You haven't logged in yet.");
            return;
        }

        MakedirResponseModel mdm = ClientCommands.mkdir(socket, auth_ktoken1024, null, client_ac_key, uid, cmd);
        processMakedirResponse(mdm);
    }

    private static void processMakedirResponse(MakedirResponseModel mdm) {
        if (mdm == null) {
            return;
        }
        System.out.println(mdm.getResponse());
    }

    private static void processClientConfFile(){
        String client_conf_path = String.format("configs/clients/%s.conf", uid);
        Properties props = new Properties();
        try (FileInputStream input = new FileInputStream(client_conf_path)) {
            props.load(input);
        } catch (IOException e) {
            System.out.println("Could not import client's .conf file.");
            e.printStackTrace();
        }

        System.setProperty("PRIVATE_SYM_KEY", props.getProperty("PRIVATE_SYM_KEY"));
    }

    public static void main(String[] args) {
        System.out.println(CLIENT_BOOT_MESSAGE);

        if (args.length < 1) {
            System.out.println("Provide a client name.");
            return;
        }

        uid = args[0];

        // paths
        String client_keystore_path = String.format("certs/clients/%sCrypto/keystore_%s_cl.jks", uid, uid);
        String client_truststore_path = String.format("certs/clients/%sCrypto/%s_cl_truststore", uid, uid);

        // envs
        System.setProperty("javax.net.ssl.trustStore", client_truststore_path);
        processClientConfFile();

        try {
            factory = MySSLUtils.createClientSocketFactory(client_keystore_path, PASSWORD);
            readCommands();
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
