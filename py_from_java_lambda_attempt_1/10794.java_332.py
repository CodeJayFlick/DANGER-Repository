Here is the translation of the given Java code into equivalent Python:

```Python
import SwingUpdateManager

class VisualGraphHoverMousePlugin:
    def __init__(self, graph_component, viewer1, viewer2):
        self.graph_component = graph_component
        self.path_highlighter = graph_component.get_path_highlighter()
        self.graph = graph_component.get_graph()
        self.source_viewer = viewer1
        self.other_viewer = viewer2

class VisualGraphHoverMousePlugin(VisualGraphHoverMousePlugin):

    def check_modifiers(self, e):
        return e.modifiers == modifiers

    def mouse_moved(self, e):
        last_mouse_event = e
        self.mouse_hover_updater.update()

    def update_mouse_hovers(self):
        if not graph_component.is_uninitialized():
            viewer = get_graph_viewer(last_mouse_event)
            new_hovered_vertex = GraphViewerUtils.get_vertex_from_point_in_view_space(viewer, last_mouse_event.point)
            if hovered_vertex == new_hovered_vertex:
                return
            self.update_mouse_hovers_for_vertex(viewer, new_hovered_vertex)

    def update_mouse_hovers_for_vertex(self, viewer, new_hovered_vertex):
        updater = get_view_updater(viewer)
        updater.stop_edge_hover_animation()
        set_hovered(hovered_vertex, False)
        hovered_vertex = new_hovered_vertex
        set_hovered(hovered_vertex, True)

    def set_hovered(self, v, hovered):
        if v is not None:
            v.set_hovered(hovered)

    def setup_hover_edges_for_vertex(self, new_hovered_vertex):
        if graph.get_edge_count() == 0:
            return
        path_highlighter.set_hovered_vertex(new_hovered_vertex)
        self.repaint()

    def repaint(self):
        source_viewer.repaint()
        other_viewer.repaint()

class VisualGraphViewUpdater:

    def stop_edge_hover_animation(self):
        pass

def main():
    # Initialize the mouse plugin with necessary components and viewers.
    graph_component = GraphComponent()  # Replace this line
    viewer1 = VisualizationViewer()  # Replace these lines
    viewer2 = VisualizationViewer()
    
    visual_graph_hover_mouse_plugin = VisualGraphHoverMousePlugin(graph_component, viewer1, viewer2)

if __name__ == "__main__":
    main()

```

Please note that the above Python code is a direct translation of your Java code. It does not include any error handling or exception checking which you would typically do in real-world applications.

Also, I have replaced some parts with comments (`# Replace this line`, `# Replace these lines`) as they are specific to your application and may require different implementations based on the actual components and viewers used by your code.