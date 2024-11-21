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
