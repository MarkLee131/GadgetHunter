import java.io.*;
import java.util.HashMap;
import java.util.Map;

/** A fixed, in-memory callback oracle. Its only effect is incrementing a counter. */
public final class MarkerGraphProbe {
    private static final String PROPERTY = "org.apache.commons.collections.enableUnsafeSerialization";
    public static final class Marker implements Serializable {
        private static final long serialVersionUID = 1L;
        static int visits;
        @Override public String toString() { visits++; return "marker"; }
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !(args[0].equals("org.apache.commons.collections")
                || args[0].equals("org.apache.commons.collections4"))
                || !(args[1].equals("default") || args[1].equals("enabled"))) {
            throw new IllegalArgumentException("Expected a reviewed package and default/enabled policy");
        }
        Class<?> functor = Class.forName(args[0] + ".functors.InvokerTransformer");
        String outcome;
        if (!Serializable.class.isAssignableFrom(functor)) {
            outcome = "not_serializable";
        } else {
            Class<?> transformer = Class.forName(args[0] + ".Transformer");
            Object selection = functor.getConstructor(String.class, Class[].class, Object[].class)
                .newInstance("toString", new Class<?>[0], new Object[0]);
            Map backing = new HashMap();
            String factory = args[0].endsWith("4") ? "lazyMap" : "decorate";
            Map lazy = (Map) Class.forName(args[0] + ".map.LazyMap")
                .getMethod(factory, Map.class, transformer).invoke(null, backing, selection);
            Object entry = Class.forName(args[0] + ".keyvalue.TiedMapEntry")
                .getConstructor(Map.class, Object.class).newInstance(lazy, new Marker());
            Map graph = new HashMap();
            graph.put(entry, "value");
            backing.clear();
            System.setProperty(PROPERTY, "true");
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (ObjectOutputStream output = new ObjectOutputStream(bytes)) { output.writeObject(graph); }
            if (args[1].equals("enabled")) System.setProperty(PROPERTY, "true");
            else System.clearProperty(PROPERTY);
            Marker.visits = 0;
            try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
                input.readObject();
                if (Marker.visits < 1) throw new AssertionError("Expected marker callback did not occur");
                outcome = "permitted";
            } catch (UnsupportedOperationException rejected) {
                if (Marker.visits != 0) throw new AssertionError("Marker effect occurred before rejection");
                outcome = "read_rejected";
            }
        }
        System.out.println("{\"oracle\":\"hashmap-lazymap-marker-v1\",\"policy\":\"" + args[1]
            + "\",\"outcome\":\"" + outcome + "\",\"marker_visits\":" + Marker.visits + "}");
    }
}
