package client;

import javax.net.ssl.*;

import utils.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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
            factory = MySSLUtils.createClientSocketFactory(client_keystore_path, PASSWORD);
            readCommands();
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
            socket = MySSLUtils.startNewConnectionToServer(factory, CommonValues.MD_HOSTNAME,
                    CommonValues.MD_PORT_NUMBER);
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
            MySSLUtils.closeConnectionToServer(socket);
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
        MySSLUtils.sendData(socket, dataOut);

        // ===== Receive Response =====
        byte[] dataIn = MySSLUtils.receiveData(socket);
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
        MySSLUtils.sendData(socket, dataOut);

        // ===== Receive Response =====
        byte[] dataIn = MySSLUtils.receiveData(socket);
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
        MySSLUtils.sendData(socket, dataOut);

        // ===== Receive Response =====
        byte[] dataIn = MySSLUtils.receiveData(socket);
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
}
