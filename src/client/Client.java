package client;

import javax.net.ssl.*;

import client.responseModels.*;
import utils.*;

import java.io.FileInputStream;
import java.io.IOException;
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
                case TEST:
                    ClientCommands.test(socket);
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
                case PUT:
                    put(cmd);
                    break;
                case GET:
                    get(cmd);
                    break;
                case LIST:
                    list(cmd);
                    break;
                default:
                    break masterLoop;
            }
            MySSLUtils.closeConnectionToServer(socket);
            System.out.println();
        }

    }

    // ===== COMMAND PROCESSING =====
    private static void login(String cmd) {
        if (!ClientValidator.loginValidator(cmd)) {
            System.out.println("Command is not correctly formatted");
            return;
        }

        String name = cmd.split(" ")[1];
        if (!name.equals(uid)) {
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

        ClientTokens.lrm = lrm;
        USERNAME_LOGGED = lrm.username + ":";
        System.out.println("Login successfully done at: " + ClientTokens.lrm.timestampFinal.toString());
    }

    private static void makedir(String cmd) {
        if (!ClientValidator.makedirValidator(cmd)) {
            System.out.println("Command is not correctly formatted");
            return;
        }

        if (ClientTokens.lrm == null) {
            System.out.println("You haven't logged in yet.");
            return;
        }

        MakedirResponseModel mdm = ClientCommands.mkdir(socket, ClientTokens.lrm.ktoken1024, ClientTokens.lrm.clientAc_SymKey, uid, cmd);
        processMakedirResponse(mdm);
    }

    private static void processMakedirResponse(MakedirResponseModel mdm) {
        if (mdm == null) {
            return;
        }

        System.out.println(mdm.getResponse());
    }

    private static void put(String cmd) {
        if (!ClientValidator.putValidator(cmd)) {
            System.out.println("Command is not correctly formatted");
            return;
        }

        if (ClientTokens.lrm.ktoken1024 == null) {
            System.out.println("You haven't logged in yet.");
            return;
        }

        PutFileResponseModel prm = ClientCommands.put(socket, ClientTokens.lrm.ktoken1024, ClientTokens.lrm.clientAc_SymKey,
                uid, cmd);
        processPutResponse(prm);
    }

    private static void processPutResponse(PutFileResponseModel prm) {
        if (prm == null) {
            return;
        }

        System.out.println(prm.getMessage());
    }


    private static void get(String cmd) {
        if (!ClientValidator.putValidator(cmd)) {
            System.out.println("Command is not correctly formatted");
            return;
        }

        if (ClientTokens.lrm.ktoken1024 == null) {
            System.out.println("You haven't logged in yet.");
            return;
        }

        GetFileResponseModel gfm = ClientCommands.get(socket, ClientTokens.lrm.ktoken1024, ClientTokens.lrm.clientAc_SymKey,
                uid, cmd);
        processGetResponse(gfm);
    }

    private static void processGetResponse(GetFileResponseModel gfm) {
        if (gfm == null) {
            return;
        }
        System.out.println(gfm.getResponse());
    }

    private static void list(String cmd) {
        if (!ClientValidator.listValidator(cmd)) {
            System.out.println("Command is not correctly formatted");
            return;
        }

        if (ClientTokens.lrm.ktoken1024 == null) {
            System.out.println("You haven't logged in yet.");
            return;
        }

        if(cmd.split(" ").length == 2){ // list home root
            cmd += " /";
        }

        ListResponseModel lrm = ClientCommands.list(socket, ClientTokens.lrm.ktoken1024, ClientTokens.lrm.clientAc_SymKey,
                uid, cmd);
        processListResponse(lrm);
    }


    private static void processListResponse(ListResponseModel lrm) {
        if (lrm == null) {
            return;
        }
        System.out.println(lrm.getFiles());
    }

    private static void processClientConfFile() {
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
