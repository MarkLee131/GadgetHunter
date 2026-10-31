package fixtures;

import java.io.*;

// Static-analysis inputs only. Tests compile these classes; no callback is executed.
public class EffectProbe implements Serializable {
    private String command;
    private Object readResolve() throws IOException {
        Runtime.getRuntime().exec(command);
        return this;
    }
}

class ConstantProbe implements Serializable {
    private Object readResolve() throws IOException {
        Runtime.getRuntime().exec("fixture-not-executed");
        return this;
    }
}

class NestedProbe implements Serializable {
    private byte[] data;
    private Object readResolve() throws IOException, ClassNotFoundException {
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }
}
