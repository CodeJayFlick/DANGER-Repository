Here is the translation of the Java code into Python:

```Python
class VisualGraphPathHighlighterTest:
    def __init__(self):
        self.graph = None
        self.path_highlight_mode = PathHighlightMode.INOUT

    @staticmethod
    def edge(start_id, end_id):
        return TestEdge(v(start_id), v(end_id))

    @staticmethod
    def vertex(id):
        if not hasattr(VisualGraphPathHighlighterTest, 'vertices'):
            VisualGraphPathHighlighterTest.vertices = {}
        if id in VisualGraphPathHighlighterTest.vertices:
            return VisualGraphPathHighlighterTest.vertices[id]
        else:
            label_vertex = LabelTestVertex(str(id))
            graph.add_vertex(label_vertex)
            VisualGraphPathHighlighterTest.vertices[id] = label_vertex
            return label_vertex

    def test_edge_focus_mode_in(self):
        self.graph = TestVisualGraph()
        edge(1, 2)
        edge(2, 3)
        edge(2, 4)
        edge(3, 5)
        edge(4, 5)
        edge(5, 6)

        focus_mode(PathHighlightMode.INOUT)
        self.assert_no_edges_in_focused_path()

    def test_edge_focus_mode_out(self):
        self.graph = TestVisualGraph()
        edge(1, 2)
        edge(2, 3)
        edge(2, 4)
        edge(3, 5)
        edge(4, 5)
        edge(5, 6)

        focus_mode(PathHighlightMode.OUT)
        self.assert_all_edges_in_focused_path()

    def test_edge_focus_mode_scoped_forward(self):
        self.graph = TestVisualGraph()
        edge(1, 2)
        edge(2, 3)
        edge(2, 4)
        edge(3, 5)
        edge(4, 5)
        edge(5, 6)

        focus_mode(PathHighlightMode.SCOPE_FORWARD)
        self.assert_all_edges_in_focused_path()

    def test_edge_focus_mode_scoped_reverse(self):
        self.graph = TestVisualGraph()
        edge(1, 2)
        edge(2, 3)
        edge(2, 4)
        edge(3, 5)
        edge(4, 5)
        edge(5, 6)

        focus_mode(PathHighlightMode.SCOPE_REVERSE)
        self.assert_all_edges_in_focused_path()

    def test_edge_hover_mode_in(self):
        self.graph = TestVisualGraph()
        edge(1, 2)
        edge(2, 3)
        edge(2, 4)
        edge(3, 5)
        edge(4, 5)
        edge(5, 6)

        hover_mode(PathHighlightMode.INOUT)
        self.assert_all_edges_hovered()

    def test_edge_hover_mode_out(self):
        self.graph = TestVisualGraph()
        edge(1, 2)
        edge(2, 3)
        edge(2, 4)
        edge(3, 5)
        edge(4, 5)
        edge(5, 6)

        hover_mode(PathHighlightMode.OUT)
        self.assert_no_edges_hovered()

    def test_edge_hover_mode_scoped_forward(self):
        self.graph = TestVisualGraph()
        edge(1, 2)
        edge(2, 3)
        edge(2, 4)
        edge(3, 5)
        edge(4, 5)
        edge(5, 6)

        hover_mode(PathHighlightMode.SCOPE_FORWARD)
        self.assert_all_edges_hovered()

    def test_edge_hover_mode_scoped_reverse(self):
        self.graph = TestVisualGraph()
        edge(1, 2)
        edge(2, 3)
        edge(2, 4)
        edge(3, 5)
        edge(4, 5)
        edge(5, 6)

        hover_mode(PathHighlightMode.SCOPE_REVERSE)
        self.assert_all_edges_hovered()

    def test_clear_edge_cache(self):
        self.graph = TestVisualGraph()
        edge(1, 2)
        edge(2, 3)
        edge(3, 4)
        edge(4, 5)

        focus_mode(PathHighlightMode.ALLCYCLE)
        clear_edge_cache()
        self.assert_in_focused_path(edge(2, 3), edge(3, 2))

    def test_vertex_focus(self):
        pass

    def test_vertex_hover(self):
        pass
```

Note that this is a translation of the Java code into Python. The original Java code was not provided in its entirety, so some parts may be missing from this translation.