Here is the translation of the given Java code into Python:

```Python
class GraphPerspectiveInfo:
    LAYOUT_TRANSLATE_X = "LAYOUT_TRANSLATE_X"
    LAYOUT_TRANSLATE_Y = "LAYOUT_TRANSLATE_Y"
    VIEW_TRANSLATE_X = "VIEW_TRANSLATE_X"
    VIEW_TRANSLATE_Y = "VIEW_TRANSLATE_Y"

    VIEW_ZOOM = "VIEW_ZOOM"

    INVALID_POINT = None
    INVALID_ZOOM = -1.0

    def __init__(self):
        self.zoom = self.INVALID_ZOOM
        self.restore_zoom = False
        self.layout_translate_coordinates = self.INVALID_POINT
        self.view_translate_coordinates = self.INVALID_POINT

    @classmethod
    def create_invalid_graph_perspective_info(cls, V=None, E=None):
        return GraphPerspectiveInfo()

    def __init__(self, render_context, zoom):
        self.zoom = zoom
        self.restore_zoom = True

        transformer = render_context.get_multi_layer_transformer()
        tx = transformer.get_transformer("LAYOUT").get_translate_x()
        ty = transformer.get_transformer("LAYOUT").get_translate_y()
        self.layout_translate_coordinates = (int(tx), int(ty))

        tx = transformer.get_transformer("VIEW").get_translate_x()
        ty = transformer.get_transformer("VIEW").get_translate_y()
        self.view_translate_coordinates = (int(tx), int(ty))

    def __init__(self, save_state):
        saved_zoom = save_state.get_double(self.VIEW_ZOOM, self.INVALID_ZOOM)

        layout_translate_x = save_state.get_int(self.LAYOUT_TRANSLATE_X, float("inf"))
        layout_translate_y = save_state.get_int(self.LAYOUT_TRANSLATE_Y, float("inf"))

        if (layout_translate_x == float("inf") or layout_translate_y == float("inf")):
            self.layout_translate_coordinates = self.INVALID_POINT
            self.view_translate_coordinates = self.INVALID_POINT
            self.zoom = self.INVALID_ZOOM
            return

        view_translate_x = save_state.get_int(self.VIEW_TRANSLATE_X, float("inf"))
        view_translate_y = save_state.get_int(self.VIEW_TRANSLATE_Y, float("inf"))

        if (view_translate_x == float("inf") or view_translate_y == float("inf")):
            self.layout_translate_coordinates = self.INVALID_POINT
            self.view_translate_coordinates = self.INVALID_POINT
            self.zoom = self.INVALID_ZOOM
            return

        self.layout_translate_coordinates = (layout_translate_x, layout_translate_y)
        self.view_translate_coordinates = (view_translate_x, view_translate_y)
        self.zoom = saved_zoom
        self.restore_zoom = True  # when we are coming from a persisted state, we restore the zoom

    def save_state(self, save_state):
        if self.is_invalid():
            return

        save_state.put_double(self.VIEW_ZOOM, self.zoom)

        if not self.layout_translate_coordinates == self.INVALID_POINT:
            save_state.put_int(self.LAYOUT_TRANSLATE_X, self.layout_translate_coordinates[0])
            save_state.put_int(self.LAYOUT_TRANSLATE_Y, self.layout_translate_coordinates[1])

    def is_invalid(self):
        return (self.layout_translate_coordinates == self.INVALID_POINT or
                self.view_translate_coordinates == self.INVALID_POINT)

    @property
    def layout_translate_coordinates(self):
        return self.layout_translate_coordinates

    @property
    def view_translate_coordinates(self):
        return self.view_translate_coordinates

    @property
    def is_restore_zoom(self):
        return self.restore_zoom

    @property
    def zoom(self):
        return self.zoom

    def __str__(self):
        #  @formatter:off
        return f"{{\n\tisRestoreZoom: {self.restore_zoom},\n\tlayoutTranslateCoordinates: {self.layout_translate_coordinates},\n\tviewTranslateCoordinates: {self.view_translate_coordinates},\n\tzoom={self.zoom}\n}}"
        #  @formatter:on

```

Note that I've used Python's `@property` decorator to create getter methods for the instance variables. This is a common pattern in Python, and it allows you to access these values as if they were public attributes of your class.