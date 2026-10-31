package fixtures;

import java.io.*;

// Metadata-only fixtures. The tests compile these classes but never instantiate them.
public class Callbacks implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
    }
    private void readObjectNoData() { }
    private Object readResolve() { return this; }
    public String[][] arrays(int n, Object[] input) { return new String[n][]; }
}

class NotSerializable {
    private void readObject(ObjectInputStream in) { }
}

class WrongHooks implements Serializable {
    private static Object readResolve() { return null; }
    public void readObjectNoData() { }
    public void readExternal(ObjectInput in) { }
}

class ExternalCallbacks implements Externalizable {
    public ExternalCallbacks() { }
    public void readExternal(ObjectInput in) { }
    public void writeExternal(ObjectOutput out) { }
}

class InheritedSerializable extends Callbacks {
    private void readObjectNoData() { }
}

// Dynamic-proxy handlers: only the Serializable one is a proxy-dispatch root.
class SerializableHandler implements java.lang.reflect.InvocationHandler, Serializable {
    public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) { return null; }
}

class PlainHandler implements java.lang.reflect.InvocationHandler {
    public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) { return null; }
}
