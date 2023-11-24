package servers.MainDispatcher;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

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

    public static byte[] login(byte[] content) {
        // ByteBuffer input = ByteBuffer.wrap(content);
        // Input -> content: {string}
        // Output -> content: {string_ac}

        // Unpack
        SSLSocket socket = startConnectionToASServer();
        byte[] dataToSend = MySSLUtils.buildPackage(Command.LOGIN, content);

        MySSLUtils.sendData(socket, dataToSend);
        byte[] dataReceived = MySSLUtils.receiveData(socket);

        MySSLUtils.closeConnectionToServer(socket);

        return dataReceived;
    }

    private static SSLSocket startConnectionToASServer() {
        SSLSocketFactory factory = MySSLUtils.createClientSocketFactory("certs/mdCrypto/keystore_md.jks", "md123456");
        SSLSocket socket = MySSLUtils.startNewConnectionToServer(factory, CommonValues.AS_HOSTNAME,
                CommonValues.AS_PORT_NUMBER);

        return socket;
    }
}
