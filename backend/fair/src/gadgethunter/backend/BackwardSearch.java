// SPDX-License-Identifier: LGPL-3.0-or-later
package gadgethunter.backend;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/** A resumable, cycle-checked backward DFS. One step never discards a frontier. */
public final class BackwardSearch<N, E, T> {
    public interface Graph<N, E, T> {
        N caller(E edge);
        boolean source(N node);
        T propagate(T taint, E edge); // null means the edge is not controllable
        List<E> incoming(N node);
        void found(List<E> backwardPath);
    }

    private final class Frame {
        final N callee;
        final E edge;
        final T before;
        N caller;
        T after;
        Iterator<E> children;
        boolean entered;
        Frame(N callee, E edge, T before) { this.callee = callee; this.edge = edge; this.before = before; }
    }

    private final Graph<N, E, T> graph;
    private final int maxLength;
    private final Deque<Frame> frames = new ArrayDeque<>();
    private final Set<N> visited = new HashSet<>();
    private final List<E> path = new ArrayList<>();
    public long steps, cyclePrunes, taintPrunes, depthPrunes;

    public BackwardSearch(Graph<N, E, T> graph, N sink, E edge, T taint, int maxLength) {
        if (maxLength < 1) throw new IllegalArgumentException("Positive chain length required");
        this.graph = graph;
        this.maxLength = maxLength;
        frames.push(new Frame(sink, edge, taint));
    }

    public boolean done() { return frames.isEmpty(); }

    private void leave(Frame frame) {
        frames.pop();
        if (frame.entered) {
            visited.remove(frame.callee);
            path.remove(path.size() - 1);
        }
    }

    public void step() {
        if (done()) return;
        steps++;
        Frame frame = frames.peek();
        if (!frame.entered) {
            if (visited.contains(frame.callee)) { cyclePrunes++; leave(frame); return; }
            frame.after = graph.propagate(frame.before, frame.edge);
            if (frame.after == null) { taintPrunes++; leave(frame); return; }
            visited.add(frame.callee);
            path.add(frame.edge);
            frame.entered = true;
            frame.caller = graph.caller(frame.edge);
            if (graph.source(frame.caller)) {
                graph.found(new ArrayList<>(path));
                leave(frame);
            } else if (path.size() == maxLength) {
                depthPrunes++;
                leave(frame);
            } else {
                frame.children = graph.incoming(frame.caller).iterator();
            }
        } else if (frame.children.hasNext()) {
            frames.push(new Frame(frame.caller, frame.children.next(), frame.after));
        } else {
            leave(frame);
        }
    }
}
