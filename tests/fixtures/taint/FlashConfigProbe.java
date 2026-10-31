import java.util.List;
import pascal.taie.World;
import pascal.taie.config.Options;
import pascal.taie.frontend.soot.SootWorldBuilder;
import pascal.taie.analysis.dataflow.analysis.methodsummary.plugin.PrioriKnowConfig;

// Integration probe: builds the analysis world and loads rules without running a scan.
public class FlashConfigProbe {
    public static void main(String[] args) {
        Options options = Options.parse("--options-file", args[0]);
        new SootWorldBuilder().build(options, List.of());
        World world = World.get();
        PrioriKnowConfig rules = PrioriKnowConfig.loadConfig(
            args[1], world.getClassHierarchy(), world.getTypeSystem());
        // Expected counts come from the generated knowledge file (args 2-4).
        if (rules.sinks().size() != Integer.parseInt(args[2]) || rules.transfers().size() != Integer.parseInt(args[3])
            || rules.imitates().size() != Integer.parseInt(args[4])) {
            throw new AssertionError("Not all prepared rules were loaded: " + rules);
        }
        boolean found = world.getGCEntries().stream().anyMatch(method -> method.getSignature()
            .equals("<fixtures.Callbacks: void readObjectNoData()>"));
        if (!found) {
            throw new AssertionError("readObjectNoData entry was not registered");
        }
        System.out.println("PREPARED_RULES_AND_CALLBACKS_LOADED");
    }
}
