package servers.AuthenticationServer;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import utils.CommonValues;

public class AuthenticationServer {

    public static byte[] login(byte[] content) {
        // ByteBuffer input = ByteBuffer.wrap(content);
        // Input -> content: {string}
        // Output -> content: {string_ac}

        // Unpack
        String message = new String(content, StandardCharsets.UTF_8);

        // Start Method
        String response = message + "_as";

        byte[] resultArray = new byte[CommonValues.DATA_SIZE];
        ByteBuffer output = ByteBuffer.wrap(resultArray);

        // Result code 
        output.putInt(0, CommonValues.OK_CODE);

        // Length of result
        output.putInt(Integer.BYTES, response.length());

        // Result
        output.put(2 * Integer.BYTES, response.getBytes());

        return resultArray;
    }

}
