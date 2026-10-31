// SPDX-License-Identifier: LGPL-3.0-or-later
package gadgethunter.backend;

import java.lang.reflect.Field;
import java.util.List;
import pascal.taie.analysis.dataflow.analysis.SummaryAnalysisDriver;
import pascal.taie.analysis.dataflow.analysis.methodsummary.plugin.CompositePlugin;
import pascal.taie.analysis.dataflow.analysis.methodsummary.plugin.GCCollectorAfterProcess;
import pascal.taie.analysis.dataflow.analysis.methodsummary.plugin.Plugin;
import pascal.taie.config.AnalysisConfig;

/** Replace only collection; graph construction and all other plugins are retained. */
public final class FairSummaryDriver extends SummaryAnalysisDriver {
    @SuppressWarnings("unchecked")
    public FairSummaryDriver(AnalysisConfig config) {
        super(config);
        try {
            Field field = SummaryAnalysisDriver.class.getDeclaredField("plugin");
            field.setAccessible(true);
            CompositePlugin composite = (CompositePlugin) field.get(this);
            Field pluginsField = CompositePlugin.class.getDeclaredField("allPlugins");
            pluginsField.setAccessible(true);
            List<Plugin> plugins = (List<Plugin>) pluginsField.get(composite);
            int replaced = 0;
            for (int i = 0; i < plugins.size(); i++) {
                if (plugins.get(i) instanceof GCCollectorAfterProcess collector) {
                    plugins.set(i, new FairCollector(collector));
                    replaced++;
                }
            }
            if (replaced != 1) throw new IllegalStateException("Expected exactly one supported post-analysis collector");
        } catch (ReflectiveOperationException ex) {
            throw new IllegalStateException("Unsupported backend collector interface", ex);
        }
    }
}
