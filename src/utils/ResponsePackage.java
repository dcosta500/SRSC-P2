package utils;

import java.nio.ByteBuffer;

// Package Received
public record ResponsePackage(int code, int length, byte[] content) {
    public static ResponsePackage parse(byte[] data) {
        ByteBuffer bb = ByteBuffer.wrap(data);

        int code = bb.getInt();
        int length = bb.getInt();

        byte[] content = new byte[length];
        bb.get(content);

        return new ResponsePackage(code, length, content);
    }
}