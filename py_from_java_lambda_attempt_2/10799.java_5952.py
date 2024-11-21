Here is a translation of the Java code into equivalent Python:

```Python
import pygame
from pygame.locals import *

class VisualGraphPopupMousePlugin:
    def handle_popup(self, e):
        viewer = self.get_viewer(e)
        popup = PySimpleGUI.popup("Your popup content", "Title")
        popup.Show()

    def get_viewer(self, e):
        return e.source

# usage example
plugin = VisualGraphPopupMousePlugin()
pygame.event.post(MouseEvent(0, 0, plugin))
```

Please note that Python does not have direct equivalent of Java's Swing and AWT libraries. The above code uses PySimpleGUI for creating a popup window.

Also, the `VisualizationViewer` class is specific to Java's Jung library which doesn't have an exact equivalent in Python.