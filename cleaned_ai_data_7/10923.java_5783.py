import unittest
from ghidra.graph import graphs as graph_module
from ghidra.util import msg as msg_util


class VisualGraphViewUpdaterTest(unittest.TestCase):

    def build_graph(self):
        g = TestVisualGraph()
        
        v1 = LabelTestVertex("1")
        v2 = LabelTestVertex("2")
        v3 = LabelTestVertex("3")
        e1 = TestEdge(v1, v2)
        e2 = TestEdge(v2, v3)

        g.add_vertex(v1)
        g.add_vertex(v2)
        g.add_vertex(v3)
        g.add_edge(e1)
        g.add_edge(e2)

        return g

    def test_ensure_vertex_visible(self):
        v = self.get_vertex("1")
        move_vertex(v, 500, 0)  # move offscreen
        assert_vertex_hidden(v)

        ensure_vertex_visible(v)
        assert_vertex_not_hidden(v)

    def assert_vertex_not_hidden(self, v):
        viewer = graph_component.get_primary_viewer()
        vertex_bounds = get_bounds(v)
        viewer_bounds = viewer.get_bounds()

        self.assertTrue(viewer_bounds.contains(vertex_bounds))

        satellite_viewer = graph_component.get_satellite_viewer()
        satellite_bounds = satellite_viewer.get_bounds()

        self.assertFalse(satellite_bounds.intersects(vertex_bounds))

    def assert_vertex_hidden(self, v):
        viewer = graph_component.get_primary_viewer()
        vertex_bounds = get_bounds(v)
        viewer_bounds = viewer.get_bounds()

        if viewer_bounds.intersects(vertex_bounds):
            msg_util.debug("vertex bounds should not be in viewer bounds\n\tvertex bounds: " + str(vertex_bounds) + "\n\viewer bounds: " + str(viewer_bounds))

        self.assertFalse(viewer_bounds.intersects(vertex_bounds))

    def get_bounds(self, v):
        return swing(lambda: graph_module.get_vertex_bounds_in_view_space(graph_component.get_primary_viewer(), v))


if __name__ == "__main__":
    unittest.main()
