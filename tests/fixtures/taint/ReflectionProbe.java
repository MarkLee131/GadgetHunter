package fixtures;

import java.io.Serializable;

// Static-analysis inputs only. None of these callbacks is executed.
public class ReflectionProbe implements Serializable {
    private String method;
    private Object readResolve() throws Exception {
        return Object.class.getMethod(method, new Class<?>[0]).invoke(this, new Object[0]);
    }
}

class ConstructorProbe implements Serializable {
    private String type;
    private Object readResolve() throws Exception {
        return Class.forName(type, false, getClass().getClassLoader())
            .getConstructor(new Class<?>[0]).newInstance(new Object[0]);
    }
}

class ConstantReflectionProbe implements Serializable {
    private Object value;
    private Object readResolve() throws Exception {
        return String.class.getMethod("valueOf", new Class<?>[]{Object.class}).invoke(null, new Object[]{value});
    }
}

class ConstantConstructorProbe implements Serializable {
    private String value;
    private Object readResolve() throws Exception {
        return String.class.getConstructor(new Class<?>[]{String.class}).newInstance(new Object[]{value});
    }
}
