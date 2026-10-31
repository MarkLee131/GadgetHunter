package fixtures;

import java.io.*;

// Compiled and statically inspected only. None of these methods is executed.
public class Wrappers {
    public static Object identity(Object input) { return input; }
    public static String cast(Object input) { return (String) input; }
    public static Object local(Object input) { Object copy = input; return copy; }
    public static Object wide(long ignored, Object input) { return input; }
    public static Object constant(Object input) { return null; }
    public static ObjectInputStream stream(InputStream input) throws IOException {
        return new ObjectInputStream(input);
    }
    public static ObjectInputStream bytes(byte[] input) throws IOException {
        return new ObjectInputStream(new ByteArrayInputStream(input));
    }
    public static ObjectInputStream unrelated(byte[] input) throws IOException {
        return new ObjectInputStream(new ByteArrayInputStream(new byte[0]));
    }
    public static Object read(InputStream input) throws Exception {
        return new ObjectInputStream(input).readObject();
    }
    public static Object effect(String command, Object input) throws IOException {
        Runtime.getRuntime().exec(command); return input;
    }
    public static Object branch(boolean flag, Object input) { return flag ? input : null; }
    private static Object saved;
    public static Object mutate(Object input) { saved = input; return input; }
    public Object override(Object input) { return input; }
    public static synchronized Object sync(Object input) { return input; }
    public static Object caught(Object input) {
        try { return (String) input; } catch (ClassCastException ex) { return null; }
    }
}

class WrappedRead implements Serializable {
    private byte[] data;
    private Object readResolve() throws Exception {
        return Wrappers.bytes(data).readObject();
    }
}

class WrappedEffect implements Serializable {
    private String command;
    private Object readResolve() throws Exception {
        return Wrappers.effect(command, this);
    }
}
