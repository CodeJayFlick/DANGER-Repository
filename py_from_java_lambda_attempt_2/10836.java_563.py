Here is the translation of the given Java code into Python:

```Python
class VisualGraphOptions:
    GRAPH_BACKGROUND_COLOR_KEY = "Graph Background Color"
    GRAPH_BACKGROUND_COLOR_DESCRIPTION = "The graph display background color"

    SHOW_ANIMATION_OPTIONS_KEY = "Use Animation"
    SHOW_ANIMATION_DESCRIPTION = "Signals to the Function Graph to use animated transitions for certain operations, like navigation."

    USE_MOUSE_RELATIVE_ZOOM_KEY = "Use Mouse-relative Zoom"
    USE_MOUSE_RELATIVE_ZOOM_DESCRIPTION = "When true the Function Graph will perform zoom operations relative to the mouse point."

    USE_CONDENSED_LAYOUT_KEY = "Use Condensed Layout"
    USECONDENSED_LAYOUT_DESCRIPTION = "Place vertices as close together as possible. For example, when true, the graph will use little spacing between vertices. Each layout will handle this option differently."

    SCROLL_WHEEL_PANS_KEY = "Scroll Wheel Pans"
    SCROLL_WHEEL_PANS_DESCRIPTION = "When enabled the mouse scroll wheel will pan the view vertically. When not enabled, you must hold the control key while using the mouse wheel"

    USE_STICKY_SELECTION_KEY = "Use Sticky Selection"
    USE_STICKY_SELECTION_DESCRIPTION = "When enabled Selecting code units in one vertex will not clear the selection in another. When disabled, every new selection clears the previous selection unless the Control key is pressed."

    VIEW_RESTORE_OPTIONS_KEY = "View Settings"
    VIEW_RESTORE_OPTIONS_DESCRIPTION = "Dictates how the view of new graphs and already rendered graphs are zoomed and positioned. See the help for more details"

    DEFAULT_GRAPH_BACKGROUND_COLOR = (255, 255, 255)
    graph_background_color = DEFAULT_GRAPH_BACKGROUND_COLOR

    use_animation = True
    scroll_wheel_pans = False

    use_mouse_relative_zoom = True
    use_condensed_layout = True

    view_restore_option = "START_FULLY_ZOOMED_OUT"

    def get_graph_background_color(self):
        return self.graph_background_color

    def get_scroll_wheel_pans(self):
        return self.scroll_wheel_pans

    def get_view_restore_option(self):
        return self.view_restore_option

    def set_use_animation(self, use_animation):
        self.use_animation = use_animation

    def use_animation(self):
        return self.use_animation

    def use_mouse_relative_zoom(self):
        return self.use_mouse_relative_zoom

    def use_condensed_layout(self):
        return self.use_condensed_layout

    def register_options(self, options, help_location):
        options.set_help_location(help_location)

        options.register_option(SHOW_ANIMATION_OPTIONS_KEY, self.use_animation(), help_location,
                                 SHOW_ANIMATION_DESCRIPTION)
        options.register_option(USE_MOUSE_RELATIVE_ZOOM_KEY, self.use_mouse_relative_zoom(), help_location,
                                 USE_MOUSE_RELATIVE_ZOOM_DESCRIPTION)
        options.register_option(USE_CONDENSED_LAYOUT_KEY, self.use_condensed_layout(), help_location,
                                 USECONDENSED_LAYOUT_DESCRIPTION)
        options.register_option(VIEW_RESTORE_OPTIONS_KEY, "START_FULLY_ZOOMED_OUT", help_location,
                                 VIEW_RESTORE_OPTIONS_DESCRIPTION)
        options.register_option(SCROLL_WHEEL_PANS_KEY, self.scroll_wheel_pans, help_location,
                                 SCROLL_WHEEL_PANS_DESCRIPTION)
        options.register_option(GRAPH_BACKGROUND_COLOR_KEY, DEFAULT_GRAPH_BACKGROUND_COLOR, help_location,
                                 GRAPH_BACKGROUND_COLOR_DESCRIPTION)

    def load_options(self, options):
        self.use_animation = options.get_boolean(SHOW_ANIMATION_OPTIONS_KEY, self.use_animation)
        self.use_mouse_relative_zoom = options.get_boolean(USE_MOUSE_RELATIVE_ZOOM_KEY, self.use_mouse_relative_zoom)
        self.use_condensed_layout = options.get_boolean(USE_CONDENSED_LAYOUT_KEY, self.use_condensed_layout)
        self.view_restore_option = options.get_enum(VIEW_RESTORE_OPTIONS_KEY, "START_FULLY_ZOOMED_OUT")
        self.scroll_wheel_pans = options.get_boolean(SCROLL_WHEEL_PANS_KEY, self.scroll_wheel_pans)
        self.graph_background_color = options.get_color(GRAPH_BACKGROUND_COLOR_KEY, DEFAULT_GRAPH_BACKGROUND_COLOR)

```

Please note that Python does not have direct equivalent of Java's `Color` class. The color is represented as RGB values in the given code.