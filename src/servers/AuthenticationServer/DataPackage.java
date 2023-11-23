package servers.AuthenticationServer;

import java.nio.ByteBuffer;

public class DataPackage {

    private final Command command;
    private final int length;
    private final byte[] content;

    public DataPackage(Command command, int length, byte[] content) {
        this.command = command;
        this.length = length;
        this.content = content;
    }

    public Command getCommand() {
        return this.command;
    }

    public int getLength() {
        return this.length;
    }

    public byte[] getContent() {
        return this.content;
    }

    public static DataPackage parse(byte[] data) {
        ByteBuffer bb = ByteBuffer.wrap(data);

        Command command = Command.getCommandFromOrdinal(bb.getInt(0));
        int length = bb.getInt(Integer.BYTES);
        byte[] content = new byte[length];
        bb.get(2 * Integer.BYTES, content);

        return new DataPackage(command, length, content);
    }
}
