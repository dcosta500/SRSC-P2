package client;

import javax.net.ssl.*;

import utils.CommonValues;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Scanner;

public class TlsClient {
    private static SSLSocketFactory factory;
    private static SSLSocket socket;
    private static final String PASSWORD = "cl123456";

    public static void main(String[] args) throws Exception {

        if (args.length < 1) {
            System.out.println("Provide a name.");
            return;
        }

        String client_keystore_path = String.format("certs/clients/%sCrypto/keystore_%s_cl.jks", args[0], args[0]);
        System.setProperty("javax.net.ssl.trustStore",
                String.format("certs/clients/%sCrypto/%s_cl_truststore", args[0], args[0]));

        try {
            factory = buildFactory(client_keystore_path);
            readCommands();

            /* read response */
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                            socket.getInputStream()));

            String inputLine;

            while ((inputLine = in.readLine()) != null)
                System.out.println(inputLine);

            in.close();
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void readCommands() {
        /*
         * Instructions to add a new command
         * 1- Create command enum in Command.java
         * 2- Add Command enum to both switches (client and server)
         * 3- Create execute{yourcommand}Command method here in this class
         * 4- Create command in MainDispatcher class (not MainDispatcherServer class)
         * 
         * Format of packages to be sent:
         * { Command(int) | Length of Content(int) | Content(byte[]) }
         * 
         * Format of packages being received:
         * { Error Code(int) | Length of Content(int) | Content(byte[]) }
         */

        Scanner in = new Scanner(System.in);
        while (true) {
            startNewConnection();
            System.out.print("Command -> ");
            String cmd = in.nextLine();
            switch (Command.valueOf(cmd.toUpperCase())) {
                case SUM:
                    executeSumCommand();
                    break;
                case MULT:
                    executeMultCommand();
                    break;
                case LOGIN:
                    executeLoginCommand();
                    break;
                default:
            }
            closeConnection();
        }
    }

    private static void executeSumCommand() {
        // Input: { command(int) | length(int) | content(byte[]) }
        // content: {int}

        // Output: { code(int) | length(int) | content(byte[])}

        // ===== Build Content Input =====
        byte[] inputContent = new byte[Integer.BYTES];
        ByteBuffer bb = ByteBuffer.wrap(inputContent);

        bb.putInt(0, 5);

        // ===== Send Content =====
        byte[] dataOut = buildPackage(Command.SUM, inputContent);
        sendData(dataOut);

        // ===== Receive Response =====
        byte[] dataIn = receiveData();
        ResponsePackage rp = ResponsePackage.parse(dataIn);

        // ===== Unpack Response =====
        if (rp.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Error code received. Aborting...");
            return;
        }

        bb = ByteBuffer.wrap(rp.getContent());

        int result = bb.getInt(0);
        System.out.println("Result: " + result);
    }

    private static void executeMultCommand() {
        // Input: { command(int) | length(int) | content(byte[]) }
        // content: {int}

        // Output: { code(int) | length(int) | content(byte[])}

        // ===== Build Content Input =====
        byte[] inputContent = new byte[Integer.BYTES];
        ByteBuffer bb = ByteBuffer.wrap(inputContent);

        bb.putInt(0, 5);

        // ===== Send Content =====
        byte[] dataOut = buildPackage(Command.MULT, inputContent);
        sendData(dataOut);

        // ===== Receive Response =====
        byte[] dataIn = receiveData();
        ResponsePackage rp = ResponsePackage.parse(dataIn);

        // ===== Unpack Response =====
        if (rp.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Error code received. Aborting...");
            return;
        }

        bb = ByteBuffer.wrap(rp.getContent());

        int result = bb.getInt(0);
        System.out.println("Result: " + result);
    }

    private static void executeLoginCommand() {
        // Input: { command(int) | length(int) | content(byte[]) }
        // content: {string}

        // Output: { code(int) | length(int) | content(byte[])}
        // content: {string_ac}

        // ===== Build Content Input =====
        byte[] message = "hello".getBytes();

        byte[] inputContent = new byte[message.length];
        ByteBuffer bb = ByteBuffer.wrap(inputContent);

        bb.put(0, message);

        // ===== Send Content =====
        byte[] dataOut = buildPackage(Command.LOGIN, inputContent);
        sendData(dataOut);

        // ===== Receive Response =====
        byte[] dataIn = receiveData();
        ResponsePackage rp = ResponsePackage.parse(dataIn);

        // ===== Unpack Response =====
        if (rp.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Error code received. Aborting...");
            return;
        }

        bb = ByteBuffer.wrap(rp.getContent());

        byte[] response = new byte[rp.getLength()];
        bb.get(0, response);

        System.out.println("Response: " + new String(response, StandardCharsets.UTF_8));
    }

    // ===== AUX METHODS =====
    // Sends data to socket
    private static void sendData(byte[] data) {
        try {
            OutputStream out = socket.getOutputStream();
            out.write(data);
            out.flush();
        } catch (Exception e) {
            System.out.println("Error while trying to send data.");
            e.printStackTrace();
        }
    }

    // Receives 2048 bytes from socket
    private static byte[] receiveData() {
        try {
            InputStream inputStream = socket.getInputStream();
            byte[] data = new byte[CommonValues.DATA_SIZE];
            int bytesRead = inputStream.read(data, 0, data.length);
            return data;
        } catch (Exception e) {
            System.out.println("Error while trying to send data.");
            e.printStackTrace();
        }
        return new byte[0];
    }

    // Builds package ready to be sent
    private static byte[] buildPackage(Command command, byte[] content) {
        // { Command(int) | Length(int) | Content(byte[])}
        byte[] data = new byte[CommonValues.DATA_SIZE];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.putInt(0, command.ordinal());
        bb.putInt(Integer.BYTES, content.length);
        bb.put(2 * Integer.BYTES, content);

        return data;
    }

    private static SSLSocketFactory buildFactory(String clientKeystorePath) {
        try {
            // set up key manager to do server authentication
            SSLContext ctx;
            KeyManagerFactory kmf;
            KeyStore ks;

            // Keystore
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(clientKeystorePath), PASSWORD.toCharArray());

            // Key Manager Factory
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, PASSWORD.toCharArray());

            // Create SLL Context (truststore is added through the java run command
            // thus there is no need to add it here)
            ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);

            return ctx.getSocketFactory();
        } catch (Exception e) {
            return null;
        }
    }

    private static void startNewConnection() {
        try {
            socket = (SSLSocket) factory.createSocket(CommonValues.MD_HOSTNAME,
                    CommonValues.MD_PORT_NUMBER);
            socket.startHandshake();
        } catch (Exception e) {
            System.out.println("Unable to start connection.");
            e.printStackTrace();
        }
    }

    private static void closeConnection() {
        try {
            socket.close();
        } catch (Exception e) {
            System.out.println("Unable to close connection.");
            e.printStackTrace();
        }
    }

}
