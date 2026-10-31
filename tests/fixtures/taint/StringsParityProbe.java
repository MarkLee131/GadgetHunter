import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executors;

/** Compare backend string helpers in isolated loaders, never target code. */
public final class StringsParityProbe {
    private static Object outcome(Method method, String value) throws Exception {
        try {
            return method.invoke(null, value);
        } catch (InvocationTargetException ex) {
            return "throws:" + ex.getCause().getClass().getName();
        }
    }

    public static void main(String[] args) throws Exception {
        URL base = Path.of(args[0]).toUri().toURL();
        URL patch = Path.of(args[1]).toUri().toURL();
        try (URLClassLoader stock = new URLClassLoader(new URL[]{base}, null);
             URLClassLoader optimized = new URLClassLoader(new URL[]{patch, base}, null)) {
            Class<?> left = stock.loadClass("pascal.taie.util.Strings");
            Class<?> right = optimized.loadClass("pascal.taie.util.Strings");
            List<String> inputs = new ArrayList<>();
            inputs.add(null);
            inputs.addAll(List.of("", "param-0", "prefix-param-123-field", "param--2", "param-xparam-31",
                "param-2147483647", "param-2147483648param-3", "param-0000000000000000001",
                "param-12\nparam-3", "param-\u0661", "param-\uff11", "this-field+param-2-other",
                "+", "-", "param-", "a_z+1-.: ", "\u0000", "\ud800", "\ud83d\ude00"));
            Random random = new Random(71823);
            String alphabet = "param-0123456789+_.: abcXYZ\n\t/[]\u00e9\u0661";
            for (int n = 0; n < 6000; n++) {
                StringBuilder text = new StringBuilder(n % 3 == 0 ? "param-" : "");
                for (int i = random.nextInt(100); i > 0; i--) text.append(alphabet.charAt(random.nextInt(alphabet.length())));
                if (n % 7 == 0) text.append("param-").append(random.nextInt(Integer.MAX_VALUE));
                inputs.add(text.toString());
            }
            int checked = 0;
            for (String name : List.of("capitalize", "isLegalContrValue", "extractParamIndex", "extractFieldName", "anyMatch")) {
                Method a = left.getMethod(name, String.class), b = right.getMethod(name, String.class);
                for (String value : inputs) {
                    Object expected = outcome(a, value), actual = outcome(b, value);
                    if (!java.util.Objects.equals(expected, actual)) throw new AssertionError(name + ": " + value + " -> " + expected + " / " + actual);
                    checked++;
                }
            }
            var pool = Executors.newFixedThreadPool(4);
            try {
                Method method = right.getMethod("extractParamIndex", String.class);
                var futures = new ArrayList<java.util.concurrent.Future<?>>();
                for (int task = 0; task < 4; task++) futures.add(pool.submit(() -> {
                    for (int i = 0; i < 2000; i++) {
                        try {
                            if (!Integer.valueOf(i).equals(outcome(method, "this+xparam-" + i + "-field"))) throw new AssertionError("Concurrent parser mismatch");
                        } catch (Exception ex) { throw new RuntimeException(ex); }
                    }
                }));
                for (var future : futures) future.get();
            } finally { pool.shutdown(); }
            System.out.println("STRING_HELPER_PARITY_OK cases=" + checked + " concurrent=8000");
        }
    }
}
