import java.io.*;
// Static-analysis-only fixture; these callbacks are never executed.
public class EffectProbe implements Serializable {
    private String command;
    private Object readResolve() throws Exception {
        Runtime.getRuntime().exec(command);
        return this;
    }
}
class NestedProbe implements Serializable {
    private byte[] data;
    private Object readResolve() throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }
}
