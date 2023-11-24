package servers.MainDispatcher;

import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import utils.MySSLUtils;
import utils.Command;
import utils.CommonValues;

public class MainDispatcher {

    public static byte[] mult(byte[] content) {
        ByteBuffer input = ByteBuffer.wrap(content);
        // Input -> content: {int}
        // Output -> content: {result_code(int) | length(int) | result(int)}

        // Unpack
        int i = input.getInt(0);

        // Start Method
        int result = i * 2;

        // Packing
        byte[] resultArray = new byte[CommonValues.DATA_SIZE];
        ByteBuffer output = ByteBuffer.wrap(resultArray);

        // Result code
        output.putInt(0, CommonValues.OK_CODE);

        // Length of result
        output.putInt(Integer.BYTES, Integer.BYTES);

        // Result
        output.putInt(2 * Integer.BYTES, result);

        return resultArray;
    }

    public static byte[] sum(byte[] content) {
        ByteBuffer input = ByteBuffer.wrap(content);
        // Input -> content: {int}
        // Output -> content: {int}

        // Unpack
        int i = input.getInt(0);

        // Start Method
        int result = i + 1;

        byte[] resultArray = new byte[CommonValues.DATA_SIZE];
        ByteBuffer output = ByteBuffer.wrap(resultArray);

        // Result code 
        output.putInt(0, CommonValues.OK_CODE);

        // Length of result
        output.putInt(Integer.BYTES, Integer.BYTES);

        // Result
        output.putInt(2 * Integer.BYTES, result);

        return resultArray;
    }

    public static byte[] clientStats(Socket clientSocket, byte[] content) {
        try {
            byte[] contentToSend = new byte[100];
            byte[] sBytes = clientSocket.getInetAddress().getHostAddress().getBytes();

            ByteBuffer bb = ByteBuffer.wrap(contentToSend);
            bb.putInt(0, sBytes.length);
            bb.put(Integer.BYTES, sBytes);

            return MySSLUtils.buildResponse(CommonValues.OK_CODE, contentToSend);
        } catch (Exception e) {
            MySSLUtils.printToLogFile("Main Dispatcher", "Error in clientStats method.");
            e.printStackTrace();
        }
        return new byte[0];
    }

    public static byte[] login(Socket clientSocket, byte[] content) {
        // ByteBuffer input = ByteBuffer.wrap(content);
        // Input -> content: {string}
        // Output -> content: {string_ac}

        // Redirect to AS Server
        SSLSocket asSocket = startConnectionToASServer();
        byte[] dataToSend = MySSLUtils.buildPackage(Command.LOGIN, content);
        MySSLUtils.sendData(asSocket, dataToSend);

        // Redirect response to client
        byte[] dataReceived = MySSLUtils.receiveData(asSocket);
        MySSLUtils.sendData(clientSocket, dataReceived);

        // Redirect to AS Server
        byte[] dataFromClient = MySSLUtils.receiveData(clientSocket);
        MySSLUtils.sendData(asSocket, dataFromClient);

        // Redirect response to client again
        byte[] dataReceived2 = MySSLUtils.receiveData(asSocket);
        MySSLUtils.sendData(clientSocket, dataReceived2);

        // Close connection to AS
        MySSLUtils.closeConnectionToServer(asSocket);

        return dataReceived;
    }

    private static SSLSocket startConnectionToASServer() {
        SSLSocketFactory factory = MySSLUtils.createClientSocketFactory("certs/mdCrypto/keystore_md.jks", "md123456");
        SSLSocket socket = MySSLUtils.startNewConnectionToServer(factory, CommonValues.AS_HOSTNAME,
                CommonValues.AS_PORT_NUMBER);

        return socket;
    }
}
