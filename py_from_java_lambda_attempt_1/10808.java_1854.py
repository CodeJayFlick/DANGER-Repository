Here is the translation of the given Java code into Python:

```Python
import java.awt as awt
from edu.uci.ics.jung.visualization import *
from ghidra.graph.viewer import *

class VisualGraphTranslatingGraphMousePlugin(V):
    def __init__(self, modifiers=awt.event.InputEvent.BUTTON1_DOWN_MASK):
        self.panning = False
        self.is_handling_event = False

    def check_modifiers(self, e):
        return e.getModifiersEx() == self.modifiers

    def mouse_pressed(self, e):
        viewer = get_graph_viewer(e)
        if not self.check_modifiers(e) or not is_in_dragging_area(e):
            return
        down = awt.Point(e.getX(), e.getY())
        viewer.set_cursor(cursor)
        self.is_handling_event = True
        e.consume()

    def mouse_released(self, e):
        was_handling_event = self.is_handling_event
        self.is_handling_event = False
        down = None
        install_cursor(awt.Cursor.getDefaultCursor(), e)

        if was_handling_event and self.panning:
            e.consume()
        self.panning = False

    def mouse_dragged(self, e):
        viewer = get_graph_viewer(e)
        accepted = self.check_modifiers(e)
        if not accepted:
            return
        if not self.is_handling_event:
            return
        self.panning = True

        context = viewer.get_render_context()
        multi_layer_transformer = context.get_multi_layer_transformer()
        layout_transformer = multi_layer_transformer.get_transformer(0)  # Layer.LAYOUT)
        viewer.set_cursor(cursor)

        down_point = multi_layer_transformer.inverse_transform(down)
        p = multi_layer_transformer.inverse_transform(e.getPoint())
        dx = (p.getX() - down_point.getX()) / 100.0
        dy = (p.getY() - down_point.getY()) / 100.0

        layout_transformer.translate(dx, dy)

        viewer.repaint()

    def mouse_clicked(self, e):
        pass

    def mouse_entered(self, e):
        if self.is_handling_event:
            return
        if not is_in_dragging_area(e):
            return
        install_cursor(cursor, e)

    def mouse_exited(self, e):
        install_cursor(awt.Cursor.getDefaultCursor(), e)

    def mouse_moved(self, e):
        if check_modifiers_for_cursor(e):
            if self.is_handling_event:
                e.consume()
            else:
                install_cursor(cursor, e)
```

Please note that this is a direct translation of the given Java code into Python.