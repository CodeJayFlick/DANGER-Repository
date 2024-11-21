Here is a translation of the Java code into equivalent Python code:

```Python
class JgtSatelliteGraphMouse:
    def load_plugins(self):
        self.scaling_plugin = SatelliteScalingGraphMousePlugin(
            CrossoverScalingControl(), 
            scaling_mask, 
            x_axis_scaling_mask, 
            y_axis_scaling_mask, 
            in_, 
            out_
        )

        # disable single selection in satellite view by setting masks to 0
        my_selecting_plugin = JgtSelectingGraphMousePlugin(0, 0)
        my_selecting_plugin.set_locked(True)
        self.selecting_plugin = my_selecting_plugin

        self.region_selecting_plugin = RegionSelectingGraphMousePlugin.builder() \
            .region_selection_mask(region_selection_mask) \
            .toggle_region_selection_mask(toggle_region_selection_mask) \
            .region_selection_complete_mask(region_selection_complete_mask) \
            .toggle_region_selection_complete_mask(toggle_region_selection_complete_mask) \
            .build()

        self.translating_plugin = SatelliteTranslatingGraphMousePlugin.builder() \
            .translating_mask(translating_mask).build()
        
        plugins = [self.selecting_plugin, 
                   self.region_selecting_plugin, 
                   self.translating_plugin, 
                   self.scaling_plugin]
        for plugin in plugins:
            add(plugin)
```

Please note that Python does not support direct translation of Java code. The above code is a manual translation and may require adjustments based on the actual usage scenario.

Here are some key differences between the original Java code and this translated Python code:

1. Inheritance: Python doesn't have explicit inheritance like Java, so we've removed it.
2. Methods: Python uses indentation to define methods instead of curly braces.
3. Class definition: Python class definitions start with `class` followed by the name of the class.
4. Method calls: Python method calls are made using dot notation (e.g., `self.scaling_plugin = ...`) whereas Java uses parentheses and a comma-separated list of arguments.
5. Data types: Python doesn't have explicit data type declarations like Java, so we've removed them.

This translation is based on the assumption that you want to keep the same functionality as in the original Java code but with a different syntax.