import JungVisualization as jung
from typing import TypeVar

V = TypeVar('V')
E = TypeVar('E')

class VisualGraphCursorRestoringGraphMousePlugin(jung.visualization.control.AbstractGraphMousePlugin):
    def __init__(self):
        super().__init__()

    def check_modifiers(self, e: jung.awt.event.MouseEvent) -> bool:
        return e.getModifiersEx() == self.modifiers

    def mouse_dragged(self, e: jung.awt.event.MouseEvent):
        # don't care
        pass

    def mouse_moved(self, e: jung.awt.event.MouseEvent):
        new_cursor = jung.awt.Cursor.getDefaultCursor()
        viewer = (jung.visualization.Viewer) e.getSource()
        viewer.setCursor(new_cursor)

# Note: In Python, we can't use Java-style annotations like `@Override` or `@SuppressWarnings`.
