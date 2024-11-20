Here is the translation of the Java code to Python:

```Python
class GhidraGraphCollapser:
    def __init__(self, vv):
        pass  # equivalent to super(vv)

    def ungroup_selected_vertices(self):
        self.expand(self.vv.get_selected_vertices())

    def group_selected_vertices(self):
        selected_v_state = self.vv.get_selected_vertex_state()
        selected_e_state = self.vv.get_selected_edge_state()
        selected = list(selected_v_state.selected())
        if len(selected) > 1:
            group_vertex = self.collapse(selected, lambda s: GhidraGraphCollapser.group_vertices(s))
            selected_v_state.clear()
            selected_e_state.clear()
            selected_v_state.select(group_vertex)
            return group_vertex
        return None

    @staticmethod
    def collapse(vertices, func):
        # equivalent to super(vv).collapse(selected, lambda s: GhidraGraphCollapser.group_vertices(s))
        pass  # implement this method if needed

    @classmethod
    def group_vertices(cls, vertices):
        # equivalent to GroupVertex.groupVertices(selected)
        return None  # implement this method if needed

    def convert_to_outermost_vertices(self, vertices):
        set = set()
        for v in vertices:
            set.add(self.get_outermost_vertex(v))
        return set

    def get_outermost_vertex(self, vertex):
        while not self.graph.contains_vertex(vertex):
            owner = self.find_owner_of(vertex)
            if owner is None:  # should never happen. not sure what to do here
                break
            vertex = owner
        return vertex


# Note that the above Python code does not include all the Java methods and variables, as they are specific to the Jungrapht library.
```

This translation assumes you have a `VisualizationServer` class with methods like `get_selected_vertices`, `get_selected_vertex_state`, etc. Also note that some parts of the original Java code were removed or modified for Python compatibility (like static method calls and constructor).