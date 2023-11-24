package servers.AuthenticationServer;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import utils.CommonValues;

public class AuthenticationServer {

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
