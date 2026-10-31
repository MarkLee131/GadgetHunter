// SPDX-License-Identifier: LGPL-3.0-or-later
// Traversal follows the bundled Flash collector's controllability and path checks.
// Predicate, simplification, deduplication and emission implementations are delegated
// to that exact backend, whose fingerprint is checked before this class is built.
package gadgethunter.backend;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import pascal.taie.World;
import pascal.taie.analysis.dataflow.analysis.methodsummary.Utils.ContrUtil;
import pascal.taie.analysis.dataflow.analysis.methodsummary.plugin.GCCollectorAfterProcess;
import pascal.taie.analysis.dataflow.analysis.methodsummary.plugin.Plugin;
import pascal.taie.analysis.graph.callgraph.Edge;
import pascal.taie.analysis.pta.core.cs.CSCallGraph;
import pascal.taie.language.classes.JMethod;

@SuppressWarnings({"rawtypes", "unchecked"})
public final class FairCollector implements Plugin {
    private static final int QUANTUM_STEPS = 64;
    private static final long QUANTUM_NANOS = 20_000_000L;
    private final GCCollectorAfterProcess delegate;
    private final CSCallGraph graph;
    private final Set<List<String>> chains;
    private final PrintWriter writer;
    private final Method propagate, filter, sanitize, types, simplify, stringify, dedup, emit;
    private final List<SinkWork> sinks = new ArrayList<>();
    private final Map<JMethod, Integer> callbackDistance = new HashMap<>();
    private long lastSnapshot;
    private long collectionStarted;
    private final ObjectMapper mapper = new ObjectMapper();

    private static Object field(Object object, String name) throws ReflectiveOperationException {
        Field field = GCCollectorAfterProcess.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(object);
    }

    private static Method method(String name, Class<?>... types) throws ReflectiveOperationException {
        Method method = GCCollectorAfterProcess.class.getDeclaredMethod(name, types);
        method.setAccessible(true);
        return method;
    }

    public FairCollector(GCCollectorAfterProcess delegate) throws ReflectiveOperationException {
        this.delegate = delegate;
        graph = (CSCallGraph) field(delegate, "csCallGraph");
        chains = (Set<List<String>>) field(delegate, "GCs");
        writer = (PrintWriter) field(delegate, "pw");
        propagate = method("getNewTCList", List.class, List.class);
        filter = method("filterEdge", List.class);
        sanitize = method("containsSanitizer", List.class);
        types = method("typeCheck", List.class);
        simplify = method("simplyGC", List.class);
        stringify = method("getGCString", List.class);
        dedup = method("dedup", List.class);
        emit = method("logAndWrite", List.class);
    }

    private Object call(Method method, Object... arguments) {
        try { return method.invoke(delegate, arguments); }
        catch (InvocationTargetException ex) { throw new IllegalStateException("Backend predicate failed: " + method.getName(), ex.getCause()); }
        catch (ReflectiveOperationException ex) { throw new IllegalStateException("Backend interface changed", ex); }
    }

    private List<Integer> transfer(List<Integer> input, Edge edge) {
        List<Integer> output = (List<Integer>) call(propagate, input, edge.getCSIntContr());
        return ContrUtil.allControllable(output) ? output : null;
    }

    private List<Edge> incoming(JMethod method) {
        // Prefer callers close to protocol roots, without pruning other callers.
        // Distances ignore taint/types and are only an ordering heuristic. The
        // simplifier can later mutate the graph, making this snapshot stale.
        List<Edge> edges = new ArrayList<>(graph.edgesInTo(method));
        edges.sort(Comparator.comparingInt((Edge e) -> callbackDistance.getOrDefault(CSCallGraph.getCaller(e), Integer.MAX_VALUE))
            .thenComparingInt(e -> CSCallGraph.getCaller(e).getDeclaringClass().isApplication() ? 0 : 1)
            .thenComparing(e -> CSCallGraph.getCaller(e).toString())
            .thenComparing(e -> e.toString()));
        return edges;
    }

    private void indexCallbackDistances() {
        Deque<JMethod> pending = new ArrayDeque<>();
        for (JMethod root : World.get().getGCEntries()) if (root.isSource() && callbackDistance.putIfAbsent(root, 0) == null) pending.add(root);
        while (!pending.isEmpty()) {
            JMethod caller = pending.removeFirst();
            int distance = callbackDistance.get(caller) + 1;
            graph.edgesOutOf(caller).forEach(edge -> {
                JMethod callee = CSCallGraph.getCallee(edge);
                if (callbackDistance.putIfAbsent(callee, distance) == null) pending.addLast(callee);
            });
        }
    }

    private final class EdgeWork {
        final DeepeningSearch<JMethod, Edge, List<Integer>> search;
        final Edge initialEdge;
        long activeNanos;
        boolean scheduled;
        EdgeWork(SinkWork sink, Edge edge, List<Integer> taint) {
            initialEdge = edge;
            search = new DeepeningSearch<>(new BackwardSearch.Graph<>() {
                public JMethod caller(Edge e) { return CSCallGraph.getCaller(e); }
                public boolean source(JMethod method) { return method.isSource(); }
                public List<Integer> propagate(List<Integer> input, Edge e) { return transfer(input, e); }
                public List<Edge> incoming(JMethod method) { return FairCollector.this.incoming(method); }
                public void found(List<Edge> path) { accept(sink, path); }
            }, sink.method, edge, taint, GCCollectorAfterProcess.MAX_LEN);
        }
    }

    private final class SinkWork {
        final JMethod method;
        final Deque<EdgeWork> pending = new ArrayDeque<>();
        int incomingEdges, controllableEdges, scheduledEdges, finishedEdges, exhaustedEdges, found;
        long edgeBudgetNanos, activeNanos, steps, cyclePrunes, taintPrunes, depthPrunes;
        long filterPrunes, sanitizerPrunes, typePrunes, similarityPrunes;
        long firstCandidateNanos = -1;
        SinkWork(JMethod method) {
            this.method = method;
            List<Integer> taint = Arrays.stream(method.getSink()).boxed().collect(Collectors.toList());
            List<Edge> edges = incoming(method);
            incomingEdges = edges.size();
            for (Edge edge : edges) if (transfer(taint, edge) != null) pending.add(new EdgeWork(this, edge, taint));
            controllableEdges = pending.size();
            // Preserve the stock per-incoming-edge allocation, but charge active
            // search time only. Waiting for another sink does not consume it.
            long budgetMillis = World.get().getOptions().getSINK_MAX_TIME() * 1000L;
            if (budgetMillis <= 0) throw new IllegalArgumentException("Positive sink budget required");
            edgeBudgetNanos = controllableEdges == 0 ? 0 : (budgetMillis / controllableEdges) * 1_000_000L;
        }
        void advance() {
            EdgeWork work = pending.removeFirst();
            if (!work.scheduled) { scheduledEdges++; work.scheduled = true; }
            long started = System.nanoTime();
            long limit = Math.min(QUANTUM_NANOS, Math.max(0, edgeBudgetNanos - work.activeNanos));
            int iterations = 0;
            while (!work.search.done() && iterations < QUANTUM_STEPS && System.nanoTime() - started < limit) {
                work.search.step();
                iterations++;
                if (work.search.passFinished()) break;
            }
            long elapsed = System.nanoTime() - started;
            work.activeNanos += elapsed;
            activeNanos += elapsed;
            if (work.search.done() || work.activeNanos >= edgeBudgetNanos) {
                if (work.search.done()) finishedEdges++; else exhaustedEdges++;
                steps += work.search.steps();
                cyclePrunes += work.search.cyclePrunes();
                taintPrunes += work.search.taintPrunes();
                depthPrunes += work.search.depthPrunes();
            } else if (work.search.passFinished()) {
                // Rotate at depth-pass boundaries: parked passes have no live
                // frames, so later incoming edges get a short-path opportunity
                // while only one expanded cursor is retained per sink.
                pending.addLast(work);
            } else pending.addFirst(work);
        }
    }

    private void accept(SinkWork sink, List<Edge> path) {
        if ((boolean) call(filter, path)) { sink.filterPrunes++; return; }
        if ((boolean) call(sanitize, path)) { sink.sanitizerPrunes++; return; }
        if (!(boolean) call(types, path)) { sink.typePrunes++; return; }
        List<Edge> simple = (List<Edge>) call(simplify, path);
        List<String> text = (List<String>) call(stringify, simple);
        if (!(boolean) call(dedup, text)) { sink.similarityPrunes++; return; }
        if (chains.add(text)) {
            call(emit, simple);
            sink.found++;
            if (sink.firstCandidateNanos < 0) sink.firstCandidateNanos = System.nanoTime() - collectionStarted;
        }
    }

    private void snapshot(String status, boolean force) {
        long now = System.nanoTime();
        if (!force && now - lastSnapshot < 250_000_000L) return;
        lastSnapshot = now;
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("schema_version", 1);
        report.put("strategy", "round-robin-v1");
        report.put("edge_order", "callback-distance-v1");
        report.put("depth_strategy", "round-robin-deepening-v1");
        report.put("distance_index_methods", callbackDistance.size());
        report.put("status", status);
        report.put("candidate_count", chains.size());
        report.put("collection_elapsed_millis", (now - collectionStarted) / 1_000_000L);
        report.put("sink_seconds", World.get().getOptions().getSINK_MAX_TIME());
        report.put("quantum_millis", QUANTUM_NANOS / 1_000_000L);
        report.put("quantum_steps", QUANTUM_STEPS);
        report.put("budget_exhausted", sinks.stream().anyMatch(s -> s.exhaustedEdges > 0));
        report.put("exhaustive", false);
        List<Map<String, Object>> records = new ArrayList<>();
        for (SinkWork sink : sinks) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("method", sink.method.toString());
            item.put("incoming_edges", sink.incomingEdges);
            item.put("controllable_edges", sink.controllableEdges);
            item.put("scheduled_edges", sink.scheduledEdges);
            item.put("finished_edges", sink.finishedEdges);
            item.put("budget_exhausted_edges", sink.exhaustedEdges);
            item.put("pending_edges", sink.pending.size());
            item.put("candidates", sink.found);
            item.put("first_candidate_millis", sink.firstCandidateNanos < 0 ? null : sink.firstCandidateNanos / 1_000_000L);
            item.put("active_millis", sink.activeNanos / 1_000_000L);
            item.put("completed_cursor_steps", sink.steps);
            item.put("cycle_prunes", sink.cyclePrunes);
            item.put("taint_prunes", sink.taintPrunes);
            item.put("depth_prunes", sink.depthPrunes);
            item.put("caller_filter_prunes", sink.filterPrunes);
            item.put("sanitizer_prunes", sink.sanitizerPrunes);
            item.put("type_prunes", sink.typePrunes);
            item.put("similarity_prunes", sink.similarityPrunes);
            EdgeWork next = sink.pending.peekFirst();
            item.put("next_caller", next == null ? null : CSCallGraph.getCaller(next.initialEdge).toString());
            item.put("next_depth", next == null ? null : next.search.depth);
            records.add(item);
        }
        report.put("sinks", records);
        try {
            Path output = World.get().getOptions().getOutputDir().toPath();
            Path temporary = output.resolve("collector.json.tmp"), target = output.resolve("collector.json");
            mapper.writeValue(temporary.toFile(), report);
            try { Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE); }
            catch (AtomicMoveNotSupportedException ex) { Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING); }
        } catch (java.io.IOException ex) { throw new IllegalStateException("Cannot record collector coverage", ex); }
    }

    @Override public void onFinish() {
        collectionStarted = System.nanoTime();
        indexCallbackDistances();
        List<JMethod> ordered = new ArrayList<>(World.get().getSinks());
        ordered.sort(Comparator.comparing(JMethod::toString));
        for (JMethod method : ordered) sinks.add(new SinkWork(method));
        System.out.println("fair collector starts: " + sinks.size() + " sinks");
        snapshot("running", true);
        try {
            boolean pending;
            do {
                pending = false;
                for (SinkWork sink : sinks) if (!sink.pending.isEmpty()) {
                    sink.advance();
                    pending = true;
                    snapshot("running", false);
                }
            } while (pending);
            String status = sinks.stream().anyMatch(s -> s.exhaustedEdges > 0) ? "partial" : "completed";
            snapshot(status, true);
            writer.println("total gadget chains : " + chains.size());
            writer.flush();
            System.out.println("total gadget chains : " + chains.size());
            System.out.println("fair collector finishes: " + status);
        } catch (RuntimeException ex) {
            writer.flush();
            snapshot("failed", true);
            throw ex;
        }
    }
}
