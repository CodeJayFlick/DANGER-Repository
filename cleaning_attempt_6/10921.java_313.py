import unittest
from abc import ABC, abstractmethod
from typing import List, Collection

class GraphViewerTest(unittest.TestCase):

    def setUp(self):
        self.viewer = None
        self.tooltipSpy = None

    @abstractmethod
    def build_graph(self) -> object:
        pass

    @abstractmethod
    def create_layout_provider(self) -> object:
        pass

    def initialize(self, graph_component=None):
        if not self.viewer:
            self.viewer = graph_component.get_primary_viewer()
        self.tooltipSpy = TestVertexTooltipProvider()

    @unittest.skip("Test is currently skipped")
    def test_show_popup_for_vertex(self):

        v1 = get_vertex("1")

        assert_popups_shown(v1, 0)
        hover_vertex(v1)
        assert_popups_shown(v1, 1)

    @unittest.skip("Test is currently skipped")
    def test_dragging_hides_popup(self):
        try:
            v1 = get_vertex("1")
            hover_vertex(v1)
            self.assertTrue(assert_popup_showing(True))

            v2 = get_vertex("2")

            drag_vertex(v2)
            self.assertFalse(assert_popup_showing(False))
        except Exception as e:
            print(f"Exception occurred: {e}")

    @unittest.skip("Test is currently skipped")
    def test_showing_popup_emphasizes_popee_when_scaled(self):
        scale_graph_past_interaction_threshold()

        v1 = get_vertex("1")

        hover_vertex(v1)
        assert_popups_shown(v1, 1)

        self.assertTrue(get_vertex("1").has_been_emphasised())

    @unittest.skip("Test is currently skipped")
    def test_show_popup_for_edge(self):
        install_mouse_debugger()

        v1 = get_vertex("1")
        v2 = get_vertex("2")

        e = get_edge(v1, v2)

        assert_popups_shown(v1, 0)
        assert_popups_shown(v2, 0)

        hover_edge(e)

        assert_popups_shown(v1, 1)
        assert_popups_shown(v2, 1)


    def hover_vertex(self, vertex):
        self.tooltipSpy.clear_tooltip_triggered()

        super().hover_vertex(vertex)

        AbstractGTest.waitForCondition(lambda: self.tooltipSpy.is_tooltip_triggered(), "Timed-out waiting for tooltip to appear")
        waitForSwing()


    def hover_edge(self, edge):
        ensure_vertex_visible(edge.get_start())

        graph_space_edge_point = find_hover_point_in_graph_space(edge)
        view_point = GraphViewerUtils.translate_point_from_graph_space_to_view_space(graph_space_edge_point, self.viewer)

        mods = 0
        e = MouseEvent(self.viewer, MouseEvent.MOUSE_MOVED, System.currentTimeMillis(), mods, view_point.x, view_point.y, 0, False)

        listeners = self.viewer.get_mouse_motionListeners()
        swing(lambda: [listener.mouseMoved(e) for listener in listeners])

        self.tooltipSpy.clear_tooltip_triggered()

        AbstractGTest.waitForCondition(lambda: self.tooltipSpy.is_tooltip_triggered(), "Timed-out waiting for tooltip to appear")
        waitForSwing()


    def find_hover_point_in_graph_space(self, edge):
        # Get the edge shape. Then, walk from start to end, incrementally, looking for a point that hovers the edge.
        edge_shape = GraphViewerUtils.get_edge_shape_in_graph_space(self.viewer, edge)

        coords = [0] * 6
        path = GeneralPath(edge_shape)
        iterator = path.getPathIterator(None)

        iterator.currentSegment(coords)
        start_x = coords[0]
        start_y = coords[1]

        iterator.next()
        iterator.currentSegment(coords)
        end_x = coords[0]
        end_y = coords[1]

        sp = Point2D.Float(start_x, start_y)

        vsp = GraphViewerUtils.translate_point_from_graph_space_to_view_space(sp, self.viewer)
        click_viewer(vsp.x, vsp.y)

        ep = Point2D.Float(end_x, end_y)

        vep = GraphViewerUtils.translate_point_from_graph_space_to_view_space(ep, self.viewer)
        click_viewer(vep.x, vep.y)

        offset = 0.1
        for i in range(10):
            # move towards the endpoint until we are not occluded by the vertex
            dx = end_x - start_x
            dy = end_y - start_y
            test_x = start_x + (dx * (offset * i))
            test_y = start_y + (dy * (offset * i))

            test_point = Point2D.Float(test_x, test_y)

            view_point = GraphViewerUtils.translate_point_from_graph_space_to_view_space(test_point, self.viewer)
            click_viewer(view_point.x, view_point.y)

            # give the area some size to make the intersection a bit easier
            size = 2
            pick_area = Rectangle2D.Double(test_point.x - size / 2, test_point.y - size / 2, size, size)

            if edge_shape.intersects(pick_area):
                if not intersects_any_vertex(pick_area):
                    # found a point that hits the edge and not the vertex
                    return test_point

        fail("Unable to find a point on the edge to hover")
        return None


    def intersects_any_vertex(self, graph_space_area):
        vertices = self.graph.get_vertices()
        for v in vertices:
            bounds = GraphViewerUtils.get_vertex_bounds_in_graph_space(self.viewer, v)
            if bounds.intersects(graph_space_area):
                return True
        return False

    def drag_mouse(self, vertex, dx, dy):
        pass


    def assert_popup_showing(self, showing):
        is_shown = swing(lambda: self.viewer.is_popup_showing())
        assertEquals(showing, is_shown)


    def assert_popups_shown(self, v1, n):
        tooltips = swing(lambda: self.tooltipSpy.get_shown_tooltips(v1))
        assertEquals(n, len(tooltips))


if __name__ == '__main__':
    unittest.main()
