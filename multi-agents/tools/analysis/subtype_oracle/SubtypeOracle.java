import java.util.*;

/**
 * Prints the transitive supertype set (superclasses + interfaces, including JDK
 * types) for each class named on the command line, one "CLASS\tSUPER" edge per
 * line. Unresolvable classes print "CLASS\t!ERROR\t<reason>". Used to seed a
 * sound, closed-world subtype relation for the SMT feasibility solver.
 */
public class SubtypeOracle {
    public static void main(String[] args) {
        ClassLoader cl = SubtypeOracle.class.getClassLoader();
        LinkedHashSet<String> names = new LinkedHashSet<>(Arrays.asList(args));
        for (String n : names) {
            try {
                Class<?> c = Class.forName(n, false, cl);
                LinkedHashSet<String> supers = new LinkedHashSet<>();
                collect(c, supers);
                for (String s : supers) {
                    System.out.println(n + "\t" + s);
                }
            } catch (Throwable t) {
                System.out.println(n + "\t!ERROR\t" + t.getClass().getSimpleName());
            }
        }
    }

    static void collect(Class<?> c, Set<String> out) {
        if (c == null || !out.add(c.getName())) return;
        collect(c.getSuperclass(), out);
        for (Class<?> i : c.getInterfaces()) collect(i, out);
    }
}
