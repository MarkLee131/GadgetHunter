// SPDX-License-Identifier: LGPL-3.0-or-later
package gadgethunter.backend;

/** Resumable depth passes sharing an externally enforced time allowance. */
public final class DeepeningSearch<N, E, T> {
    private final BackwardSearch.Graph<N, E, T> graph;
    private final N sink;
    private final E edge;
    private final T taint;
    private final int maximum;
    private final BackwardSearch.DeadEnds<N, T> deadEnds;
    private BackwardSearch<N, E, T> current;
    private long oldSteps, oldCycles, oldTaints, oldDepths, oldDeadEnds;
    public int depth = 1;

    public DeepeningSearch(BackwardSearch.Graph<N, E, T> graph, N sink, E edge, T taint, int maximum) {
        this(graph, sink, edge, taint, maximum, null);
    }

    public DeepeningSearch(BackwardSearch.Graph<N, E, T> graph, N sink, E edge, T taint, int maximum,
                           BackwardSearch.DeadEnds<N, T> deadEnds) {
        if (maximum < 1) throw new IllegalArgumentException("Positive maximum depth required");
        this.graph = graph;
        this.sink = sink;
        this.edge = edge;
        this.taint = taint;
        this.maximum = maximum;
        this.deadEnds = deadEnds;
        current = new BackwardSearch<>(graph, sink, edge, taint, depth, deadEnds);
    }

    public boolean done() { return current.done() && (depth == maximum || current.depthPrunes == 0); }
    public boolean passFinished() { return current.done(); }

    public void step() {
        if (done()) return;
        if (current.done()) {
            oldSteps += current.steps;
            oldCycles += current.cyclePrunes;
            oldTaints += current.taintPrunes;
            oldDepths += current.depthPrunes;
            oldDeadEnds += current.deadEndPrunes;
            current = new BackwardSearch<>(graph, sink, edge, taint, ++depth, deadEnds);
        }
        current.step();
    }

    public long steps() { return oldSteps + current.steps; }
    public long cyclePrunes() { return oldCycles + current.cyclePrunes; }
    public long taintPrunes() { return oldTaints + current.taintPrunes; }
    public long depthPrunes() { return oldDepths + current.depthPrunes; }
    public long deadEndPrunes() { return oldDeadEnds + current.deadEndPrunes; }
}
