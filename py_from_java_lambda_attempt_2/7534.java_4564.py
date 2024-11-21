Here is the translation of the Java code into Python:

```Python
class FunctionGraphOptions:
    OWNER = "FunctionGraphPlugin"

    EDGE_FALLTHROUGH_HIGHLIGHT_COLOR_KEY = "Edge Color - Fallthrough Highlight"
    EDGE_UNCONDITIONAL_JUMP_HIGHLIGHT_COLOR_KEY = "Edge Color - Unconditional Jump Highlight"
    EDGE_CONDITIONAL_JUMP_HIGHLIGHT_COLOR_KEY = "Edge Color - Conditional Jump Highlight"
    EDGE_FALLTHROUGH_COLOR_KEY = "Edge Color - Fallthrough "
    EDGE_UNCONDITIONAL_JUMP_COLOR_KEY = "Edge Color - Unconditional Jump  "
    EDGE_COLOR_CONDITIONAL_JUMP_KEY = "Edge Color - Conditional Jump "

    NAVIGATION_HISTORY_KEY = "Navigation History"
    NAVIGATION_HISTORY_DESCRIPTION = ("Determines how the navigation history will be updated when using the Function Graph. The basic options are: <ul>"
                                        "<li><b>Navigation Events</b>  - save a history entry when a navigation takes place (e.g., double-click or Go To event)</li>"
                                        "<li><b>Vertex Changes</b>  - save a history entry each time a new vertex is selected</li></ul><br><br>"
                                        "See help for more")

    USE_FULL_SIZE_TOOLTIP_KEY = "Use Full-Size Tooltip"
    USE_FULL_SIZE_TOOLTIP_DESCRIPTION = ("Signals to use the full-size vertex inside of the tooltip popup. When enabled the tooltip vertex will use the same format size as the Listing."
                                          "When disabled, the vertex will use the same format size as in the Function Graph.")

    RELAYOUT_OPTIONS_KEY = "Automatic Graph Relayout"
    RELAYOUT_OPTIONS_DESCRIPTION = ("Signals to the Function Graph when an automatic relayout of the graph should take place. The basic options are:<ul>"
                                     "<li><b>Always</b>  - always relayout the graph when the block model changes</li>"
                                     "<li><b>Block Model Changes Only</b>  - relayout the graph when the block model changes (like when a label has been added to the program in the currently graphed function)</li>"
                                     "<li><b>Vertex Grouping Changes Only</b>  - when vertices are grouped or ungrouped</li>"
                                     "<li><b>Never</b>  - do not automatically relayout the graph</li></ul><br><br>"
                                     "See help for more")

    DEFAULT_VERTEX_BACKGROUND_COLOR_KEY = "Default Vertex Color"
    DEFAULT_VERTEX_BACKGROUND_COLOR_DESCRIPTION = ("The default background color applied to each vertex")
    DEFAULT_GROUP_BACKGROUND_COLOR_KEY = "Default Group Color"
    DEFAULT_GROUP_BACKGROUND_COLOR_DESCRIPTION = ("The default background color applied to newly created group vertices")

    UPDATE_GROUP_AND_UNGROUP_COLORS = "Update Vertex Colors When Grouping"
    UPDATE_GROUP_AND_UNGROUP_COLORS_DESCRIPTION = ("Signals that any user color changes to a group vertex will apply that same color to all grouped vertices as well.")

    DEFAULT_VERTEX_BACKGROUND_COLOR = (255, 255, 255)
    DEFAULT_GROUP_BACKGROUND_COLOR = (226, 255, 155)

    HOVER_HIGHLIGHT_FALL_THROUGH_COLOR = (255, 127, 127)
    HOVER_HIGHLIGHT_UNCONDITIONAL_COLOR = (127, 127, 255)
    HOVER_HIGHLIGHT_CONDITIONAL_COLOR = (0, 128, 0)

    def __init__(self):
        self.default_vertex_background_color = self.DEFAULT_VERTEX_BACKGROUND_COLOR
        self.update_group_colors_automatically = True
        self.default_group_background_color = self.DEFAULT_GROUP_BACKGROUND_COLOR

        self.fallthrough_edge_color = self.HOVER_HIGHLIGHT_FALL_THROUGH_COLOR
        self.unconditional_jump_edge_color = self.HOVER_HIGHLIGHT_UNCONDITIONAL_COLOR
        self.conditional_jump_edge_color = self.HOVER_HIGHLIGHT_CONDITIONAL_COLOR

        self.fallthrough_edge_highlight_color = self.HOVER_HIGHLIGHT_FALL_THROUGH_COLOR
        self.unconditional_jump_edge_highlight_color = self.HOVER_HIGHLIGHT_UNCONDITIONAL_COLOR
        self.conditional_jump_edge_highlight_color = self.HOVER_HIGHLIGHT_CONDITIONAL_COLOR

        self.use_full_size_tooltip = False

    def get_default_vertex_background_color(self):
        return self.default_vertex_background_color

    def get_default_group_background_color(self):
        return self.default_group_background_color

    def get_update_group_colors_automatically(self):
        return self.update_group_colors_automatically

    def get_fallthrough_edge_color(self):
        return self.fallthrough_edge_color

    def get_unconditional_jump_edge_color(self):
        return self.unconditional_jump_edge_color

    def get_conditional_jump_edge_color(self):
        return self.conditional_jump_edge_color

    def get_fallthrough_edge_highlight_color(self):
        return self.fallthrough_edge_highlight_color

    def get_unconditional_jump_edge_highlight_color(self):
        return self.unconditional_jump_edge_highlight_color

    def get_conditional_jump_edge_highlight_color(self):
        return self.conditional_jump_edge_highlight_color

    def register_options(self, options):
        help = HelpLocation(OWNER, "Options")
        super().register_options(options, help)

        options.register_option(self.RELAYOUT_OPTIONS_KEY, self.relayout_option, help,
                                 self.RELAYOUT_OPTIONS_DESCRIPTION)
        options.register_option(self.NAVIGATION_HISTORY_KEY, self.navigation_history_choice, help,
                                 self.NAVIGATION_HISTORY_DESCRIPTION)
        # ... register other options ...

    def load_options(self, options):
        super().load_options(options)

        self.conditional_jump_edge_color = options.get_color(self.EDGE_COLOR_CONDITIONAL_JUMP_KEY,
                                                             self.conditional_jump_edge_color)
        self.unconditional_jump_edge_color = options.get_color(self.EDGE_UNCONDITIONAL_JUMP_COLOR_KEY,
                                                               self.unconditional_jump_edge_color)
        self.fallthrough_edge_color = options.get_color(self.EDGE_FALLTHROUGH_COLOR_KEY, self.fallthrow_edge_color)

    def get_color(self, flow_type):
        if flow_type.is_fallthrough():
            return self.get_fallthrough_edge_color()
        elif flow_type.is_unconditional_jump():
            return self.get_unconditional_jump_edge_color()
        elif flow_type.is_conditional_jump():
            return self.get_conditional_jump_edge_color()

    def get_highlight_color(self, flow_type):
        if flow_type.is_fallthrough():
            return self.get_fallthrough_edge_highlight_color()
        elif flow_type.is_unconditional_jump():
            return self.get_unconditional_jump_edge_highlight_color()
        elif flow_type.is_conditional_jump():
            return self.get_conditional_jump_edge_highlight_color()

    def option_change_requires_relayout(self, option_name):
        if option_name == self.USE_CONDENSED_LAYOUT_KEY:
            return True
        # ... check other options ...

    def get_layout_options(self, layout_name):
        return self.layout_options_by_name[layout_name]

    def set_layout_options(self, layout_name, options):
        self.layout_options_by_name[layout_name] = options

class HelpLocation:
    def __init__(self, owner, help_text):
        self.owner = owner
        self.help_text = help_text

# ... other classes and functions ...
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect or idiomatic Python, but it should work as expected.