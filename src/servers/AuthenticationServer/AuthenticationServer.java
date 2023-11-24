package servers.AuthenticationServer;

import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import utils.CommonValues;
import utils.MySSLUtils;
import utils.ResponsePackage;

public class AuthenticationServer {

    public static byte[] login(Socket mdSocket, byte[] content) {
        // ByteBuffer input = ByteBuffer.wrap(content);
        // Input1 -> content: {string}
        // Output1 -> content: {string_ac}
        // Input2 -> content: {string_ac}
        // Output2 -> content: {string_ac_bc}

        // Unpack
        String message1 = new String(content, StandardCharsets.UTF_8);

        // Start Method
        String response1 = message1 + "_ac";

        byte[] resultArray1 = new byte[CommonValues.DATA_SIZE];
        ByteBuffer output1 = ByteBuffer.wrap(resultArray1);

        // Result code 
        output1.putInt(0, CommonValues.OK_CODE);

        // Length of result
        output1.putInt(Integer.BYTES, response1.length());

        // Result
        output1.put(2 * Integer.BYTES, response1.getBytes());

        // Send first result to md
        MySSLUtils.sendData(mdSocket, resultArray1);

        // ===== SECOND TRIP =====

        // Receive second round
        byte[] secondRoundReceive = MySSLUtils.receiveData(mdSocket);

        ResponsePackage rp = ResponsePackage.parse(secondRoundReceive);
        content = rp.getContent();

        // Unpack
        String message2 = new String(content, StandardCharsets.UTF_8);

        MySSLUtils.printToLogFile("Authentication Server", "Received message2 content: " + message2);

        // Start Method
        String response2 = message2 + "_bc";

        byte[] resultArray2 = new byte[CommonValues.DATA_SIZE];
        ByteBuffer output2 = ByteBuffer.wrap(resultArray2);

        // Result code 
        output2.putInt(0, CommonValues.OK_CODE);

        // Length of result
        output2.putInt(Integer.BYTES, response2.length());

        // Result
        output2.put(2 * Integer.BYTES, response2.getBytes());

        return resultArray2;
    }

}
