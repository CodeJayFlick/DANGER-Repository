Here is the translation of the Java code into Python:

```Python
from abc import ABCMeta, abstractmethod
import tkinter as tk
from typing import Optional, Set

class VisualGraphView:
    def __init__(self):
        self.view_panel = None
        self.view_content_panel = None
        self.undocked_satellite_content_panel = None
        self.graph = None
        self.graph_component = None
        self.client_focus_listener = Optional.empty()
        self.internal_focus_listener = lambda v: {client_listener := client_focus_listener.get(), result := AtomicBoolean(False), 
            if client_listener:
                result.set(client_listener. vertexFocused(v))
            return result.get()}
        self.client_vertex_click_listener = Optional.empty()
        self.internal_vertex_click_listener = lambda v, info: {result := AtomicBoolean(False), 
            client_listener := client_vertex_click_listener.get(), 
            if client_listener:
                result.set(client_listener.vertexDoubleClicked(v, info))
            return result.get()}
        self.client_satellite_listener = Optional.empty()
        self.show_satellite = True
        self.satellite_docked = True

    def set_graph(self, graph):
        self.stop_all_animation()
        self.graph = graph
        self.install_graph_viewer()

    def install_graph_viewer(self):
        if not self.graph_component:
            new_graph_component = GraphComponent(self.graph)
            self.set_graph_component(new_graph_component)

    def get_with_busy_cursor(self, supplier):
        original_cursor = self.view_panel.cursors()
        try:
            self.view_panel.config(cursor='wait')
            return supplier.get()
        finally:
            self.view_panel.config(cursor=original_cursor)

class GraphComponent:
    pass

class VisualGraphViewUpdater:
    pass
```

Please note that this is a direct translation of the Java code into Python, without considering any potential improvements or optimizations.