import gadgethunter.backend.BackwardSearch;
import gadgethunter.backend.DeepeningSearch;
import java.util.*;

/** Compare suspended traversal with independent bounded path enumeration. */
public class BackwardSearchProbe {
    record Edge(int from, int to, int mask, int id) {}
    interface Cursor { boolean done(); void step(); default boolean passFinished() { return done(); } }

    static Set<List<Integer>> enumerate(List<Edge> edges, int limit) {
        Set<List<Integer>> result = new HashSet<>();
        Deque<List<Edge>> queue = new ArrayDeque<>();
        for (Edge edge : edges) if (edge.to == 0) queue.add(List.of(edge));
        while (!queue.isEmpty()) {
            List<Edge> path = queue.removeFirst();
            Set<Integer> visited = new HashSet<>();
            int taint = 3;
            boolean valid = true;
            for (Edge edge : path) {
                if (!visited.add(edge.to)) { valid = false; break; }
                taint &= edge.mask;
                if (taint == 0) { valid = false; break; }
            }
            if (!valid) continue;
            Edge last = path.get(path.size() - 1);
            if (last.from == 5) result.add(path.stream().map(Edge::id).toList());
            else if (path.size() < limit) {
                for (Edge edge : edges) if (edge.to == last.from) {
                    List<Edge> next = new ArrayList<>(path);
                    next.add(edge);
                    queue.addLast(next);
                }
            }
        }
        return result;
    }

    static Set<List<Integer>> suspended(List<Edge> edges, int limit, int quantum, boolean deepen) {
        Set<List<Integer>> result = new HashSet<>();
        BackwardSearch.Graph<Integer, Edge, Integer> graph = new BackwardSearch.Graph<>() {
            public Integer caller(Edge edge) { return edge.from; }
            public boolean source(Integer node) { return node == 5; }
            public Integer propagate(Integer input, Edge edge) { return (input & edge.mask) == 0 ? null : input & edge.mask; }
            public List<Edge> incoming(Integer node) { return edges.stream().filter(e -> e.to == node).toList(); }
            public void found(List<Edge> path) { result.add(path.stream().map(Edge::id).toList()); }
        };
        Deque<Cursor> cursors = new ArrayDeque<>();
        for (Edge edge : edges) if (edge.to == 0) {
            if (deepen) {
                var search = new DeepeningSearch<>(graph, 0, edge, 3, limit);
                cursors.add(new Cursor() {
                    public boolean done() { return search.done(); }
                    public void step() { search.step(); }
                    public boolean passFinished() { return search.passFinished(); }
                });
            } else {
                var search = new BackwardSearch<>(graph, 0, edge, 3, limit);
                cursors.add(new Cursor() {
                    public boolean done() { return search.done(); }
                    public void step() { search.step(); }
                });
            }
        }
        long steps = 0;
        while (!cursors.isEmpty()) {
            var cursor = cursors.removeFirst();
            for (int i = 0; i < quantum && !cursor.done(); i++) {
                cursor.step();
                if (++steps > 1_000_000) throw new AssertionError("Traversal did not terminate");
                if (deepen && cursor.passFinished()) break;
            }
            if (!cursor.done()) {
                if (deepen && !cursor.passFinished()) cursors.addFirst(cursor);
                else cursors.addLast(cursor);
            }
        }
        return result;
    }

    public static void main(String[] args) {
        Random random = new Random(20261031);
        int cases = 0;
        for (int sample = 0; sample < 100; sample++) {
            List<Edge> edges = new ArrayList<>();
            // Always include a boundary source, blocked edge, cycle and diamond.
            edges.add(new Edge(5, 0, 3, 0));
            edges.add(new Edge(5, 0, 0, 1));
            edges.add(new Edge(1, 0, 1, 2));
            edges.add(new Edge(2, 1, 3, 3));
            edges.add(new Edge(1, 2, 1, 4));
            edges.add(new Edge(5, 2, 1, 5));
            edges.add(new Edge(2, 0, 2, 6));
            for (int i = 0; i < 12; i++) edges.add(new Edge(random.nextInt(6), random.nextInt(5), random.nextInt(4), edges.size()));
            for (int limit = 1; limit <= 6; limit++) {
                Set<List<Integer>> expected = enumerate(edges, limit);
                for (int quantum : new int[]{1, 2, 64}) {
                    for (boolean deepen : new boolean[]{false, true}) {
                        if (!expected.equals(suspended(edges, limit, quantum, deepen))) throw new AssertionError("Lost or invented path, sample=" + sample);
                        cases++;
                    }
                }
            }
        }
        System.out.println("BACKWARD_SEARCH_OK cases=" + cases);
    }
}
