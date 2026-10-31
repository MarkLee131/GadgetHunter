import java.io.*;

/** Tests one harmless functor's serialization policy, never a gadget graph. */
public final class SerializationPolicyProbe {
    private static final String PROPERTY = "org.apache.commons.collections.enableUnsafeSerialization";

    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !(args[0].equals("org.apache.commons.collections.functors.InvokerTransformer")
                || args[0].equals("org.apache.commons.collections4.functors.InvokerTransformer"))
                || !(args[1].equals("default") || args[1].equals("enabled"))) {
            throw new IllegalArgumentException("Expected a reviewed functor class and default/enabled policy");
        }
        Class<?> type = Class.forName(args[0]);
        // No transform() call occurs. The object only stores the harmless method name.
        Object marker = type.getConstructor(String.class, Class[].class, Object[].class)
            .newInstance("toString", new Class<?>[0], new Object[0]);
        boolean serializable = Serializable.class.isAssignableFrom(type);
        String outcome;
        if (!serializable) {
            outcome = "not_serializable";
        } else {
            // Permit marker creation on 3.2.2, then test the READ guard independently.
            System.setProperty(PROPERTY, "true");
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (ObjectOutputStream output = new ObjectOutputStream(buffer)) { output.writeObject(marker); }
            if (args[1].equals("enabled")) System.setProperty(PROPERTY, "true");
            else System.clearProperty(PROPERTY);
            try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(buffer.toByteArray()))) {
                Object restored = input.readObject();
                if (restored.getClass() != type) throw new AssertionError("Unexpected restored class");
                outcome = "permitted";
            } catch (UnsupportedOperationException rejected) {
                outcome = "read_rejected";
            }
        }
        System.out.println("{\"class\":\"" + args[0] + "\",\"policy\":\"" + args[1]
            + "\",\"serializable\":" + serializable + ",\"outcome\":\"" + outcome + "\"}");
    }
}
