// SPDX-License-Identifier: LGPL-3.0-or-later
package gadgethunter.backend;

import java.util.AbstractMap;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/** A resumable, cycle-checked backward DFS. One step never discards a frontier. */
public final class BackwardSearch<N, E, T> {
    public interface Graph<N, E, T> {
        N caller(E edge);
        boolean source(N node);
        T propagate(T taint, E edge); // null means the edge is not controllable
        List<E> incoming(N node);
        /**
         * Handle a backward path that reached a source. Return the smallest path index whose
         * caller state can still lead to an accepted chain through this path: 0 when the path
         * may be accepted, larger when a source-side prefix is already rejected regardless of
         * the edges above it (path.size() when nothing can be accepted).
         */
        int found(List<E> backwardPath);
    }

    /**
     * Caller states (method, taint) whose explored source paths can never be accepted: none
     * reaches a source, or each is rejected on its source-side prefix. Only subtrees whose
     * cycle checks never hit a method outside the subtree are recorded, so the result does not
     * depend on the path that led there. An entry cut by the length limit holds the remaining
     * length it was explored with. New graph edges can add paths, so callers expire entries
     * with {@link #invalidate()}.
     */
    public static final class DeadEnds<N, T> {
        private static final int UNBOUNDED = Integer.MAX_VALUE;
        private static final int CAPACITY = 2_000_000;
        private final Map<Map.Entry<N, T>, long[]> states = new HashMap<>();
        private long generation;

        /** Remaining length the state is known dead for, or -1. */
        int dead(N caller, T taint) {
            long[] entry = states.get(new AbstractMap.SimpleImmutableEntry<>(caller, taint));
            if (entry == null || entry[1] != generation) return -1;
            return (int) entry[0];
        }

        void record(N caller, T taint, int remaining) {
            if (states.size() >= CAPACITY) states.clear();
            states.put(new AbstractMap.SimpleImmutableEntry<>(caller, taint), new long[]{remaining, generation});
        }

        public void invalidate() { generation++; }
        public int size() { return states.size(); }
    }

    private final class Frame {
        final N callee;
        final E edge;
        final T before;
        N caller;
        T after;
        Iterator<E> children;
        boolean entered, cut;
        int index, cycleTarget = Integer.MAX_VALUE, live = Integer.MAX_VALUE;
        Frame(N callee, E edge, T before) { this.callee = callee; this.edge = edge; this.before = before; }
    }

    private final Graph<N, E, T> graph;
    private final DeadEnds<N, T> deadEnds;
    private final int maxLength;
    private final Deque<Frame> frames = new ArrayDeque<>();
    private final Map<N, Integer> visited = new HashMap<>();
    private final List<E> path = new ArrayList<>();
    public long steps, cyclePrunes, taintPrunes, depthPrunes, deadEndPrunes;

    public BackwardSearch(Graph<N, E, T> graph, N sink, E edge, T taint, int maxLength) {
        this(graph, sink, edge, taint, maxLength, null);
    }

    public BackwardSearch(Graph<N, E, T> graph, N sink, E edge, T taint, int maxLength, DeadEnds<N, T> deadEnds) {
        if (maxLength < 1) throw new IllegalArgumentException("Positive chain length required");
        this.graph = graph;
        this.maxLength = maxLength;
        this.deadEnds = deadEnds;
        frames.push(new Frame(sink, edge, taint));
    }

    public boolean done() { return frames.isEmpty(); }

    private void leave(Frame frame) {
        frames.pop();
        if (frame.entered) {
            visited.remove(frame.callee);
            path.remove(path.size() - 1);
        }
        Frame parent = frames.peek();
        if (parent != null) {
            parent.live = Math.min(parent.live, frame.live);
            parent.cut |= frame.cut;
            parent.cycleTarget = Math.min(parent.cycleTarget, frame.cycleTarget);
        }
    }

    public void step() {
        if (done()) return;
        steps++;
        Frame frame = frames.peek();
        if (!frame.entered) {
            Integer onPath = visited.get(frame.callee);
            if (onPath != null) { cyclePrunes++; frame.cycleTarget = onPath; leave(frame); return; }
            frame.after = graph.propagate(frame.before, frame.edge);
            if (frame.after == null) { taintPrunes++; leave(frame); return; }
            frame.index = path.size();
            visited.put(frame.callee, frame.index);
            path.add(frame.edge);
            frame.entered = true;
            frame.caller = graph.caller(frame.edge);
            int remaining = maxLength - path.size();
            int known = deadEnds == null ? -1 : deadEnds.dead(frame.caller, frame.after);
            if (graph.source(frame.caller)) {
                frame.live = graph.found(new ArrayList<>(path));
                leave(frame);
            } else if (remaining == 0) {
                depthPrunes++;
                frame.cut = true;
                leave(frame);
            } else if (known >= remaining) {
                deadEndPrunes++;
                // A dead end known only within a length bound is still a length cut.
                frame.cut = known != DeadEnds.UNBOUNDED;
                if (frame.cut) depthPrunes++;
                leave(frame);
            } else {
                frame.children = graph.incoming(frame.caller).iterator();
            }
        } else if (frame.children.hasNext()) {
            frames.push(new Frame(frame.caller, frame.children.next(), frame.after));
        } else {
            // No path below this caller state can be accepted (live > index), and cycle hits
            // at or below this frame's index came only from methods inside its subtree.
            if (deadEnds != null && frame.live > frame.index && frame.cycleTarget > frame.index)
                deadEnds.record(frame.caller, frame.after, frame.cut ? maxLength - path.size() : DeadEnds.UNBOUNDED);
            leave(frame);
        }
    }
}
