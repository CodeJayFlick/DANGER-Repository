Here is the translation of the given Java code into equivalent Python code:

```Python
import unittest
from unittest.mock import patch, Mock
from ghidra.graph.component_provider import VisualGraphComponentProvider
from ghidra.graph.support import TestVisualGraph
from ghidra.graph.viewer import VisualGraphView


class VisualGraphComponentProviderTest(unittest.TestCase):

    def setUp(self):
        self.provider = None
        self.viewer = None

        with patch('ghidra.ghidra') as gh:
            tool = Mock()
            window_manager = Mock()
            run_swing(lambda: window_manager.setVisible(True), False)

            graph = build_graph()

            viewer = VisualGraphView()
            viewer.set_graph(graph)
            provider = TestProvider(tool, viewer)

    def tearDown(self):
        close_all_windows()

    @patch('ghidra.ghidra')
    def test_open_satellite_window_reopens_when_main_graph_window_is_reopened(self, gh):
        self.assertTrue(provider.is_satellite_showing())
        self.assertTrue(provider.is_satellite_docked())

        set_satellite_undocked(False)
        self.assertTrue(provider.is_satellite_showing())
        self.assertFalse(provider.is_satellite_docked())
        assert_undocked_provider_visible()

        close_main_graph_provider()
        assert_undocked_provider_hidden()

        show_main_graph_provider()
        assert_undocked_provider_visible()
        self.assertTrue(provider.is_satellite_showing())

    @patch('ghidra.ghidra')
    def test_closed_satellite_window_does_not_reopen_when_main_graph_window_is_reopened(self, gh):
        self.assertTrue(provider.is_satellite_showing())
        self.assertTrue(provider.is_satellite_docked())

        set_satellite_undocked(False)
        self.assertTrue(provider.is_satellite_showing())
        self.assertFalse(provider.is_satellite_docked())
        assert_undocked_provider_visible()

        set_satellite_visible(False)
        self.assertFalse(provider.is_satellite_showing())
        self.assertFalse(provider.is_satellite_docked())

        close_main_graph_provider()
        assert_undocked_provider_hidden()

        show_main_graph_provider()
        assert_undocked_provider_hidden()
        self.assertFalse(provider.is_satellite_showing())
        self.assertFalse(provider.is_satellite_docked())

    @patch('ghidra.ghidra')
    def test_hide_undocked_satellite_by_closing_satellite_provider(self, gh):
        self.assertTrue(provider.is_satellite_showing())
        self.assertTrue(provider.is_satellite_docked())

        set_satellite_undocked(False)
        self.assertTrue(provider.is_satellite_showing())
        self.assertFalse(provider.is_satellite_docked())
        assert_undocked_provider_visible()

        set_satellite_visible(False)
        self.assertFalse(provider.is_satellite_showing())
        self.assertFalse(provider.is_satellite_docked())

        set_satellite_visible(True)
        self.assertTrue(provider.is_satellite_showing())
        self.assertFalse(provider.is_satellite_docked())


    def build_graph(self):
        graph = TestVisualGraph()

        v1 = LabelTestVertex("1")
        v2 = LabelTestVertex("2")
        v3 = LabelTestVertex("3")
        text_area_vertex = TextAreaTestVertex("Text Area vertex...")
        e1 = TestEdge(v1, v2)
        e2 = TestEdge(v2, v3)
        e3 = TestEdge(v1, text_area_vertex)

        graph.add_vertex(v1)
        graph.add_vertex(v2)
        graph.add_vertex(v3)
        graph.add_vertex(text_area_vertex)
        graph.add_edge(e1)
        graph.add_edge(e2)
        graph.add_edge(e3)

        return graph


    def assert_undocked_provider_hidden(self):
        p = provider.get_satellite_provider()
        if p is None:
            return
        self.assertFalse("Undocked provider is not hidden", p.is_visible())


    def assert_undocked_provider_visible(self):
        p = provider.get_satellite_provider()
        self.assertIsNotNone("Undocked provider does not exist", p)
        self.assertTrue("Undocked provider is not visible", p.is_visible())


    def show_main_graph_provider(self):
        run_swing(lambda: provider.set_visible(True))


    def close_main_graph_provider(self):
        run_swing(lambda: provider.close_component())


    def set_satellite_visible(self, visible):
        tool = provider.get_tool()
        name = "Display Satellite View"
        action = get_action(tool, name)
        self.assertIsNotNone(name + " not in tool", action)
        show_satellite_action = (ToggleDockingAction) action
        set_toggle_action_selected(show_satellite_action, provider.get_action_context(None), visible)
        run_swing()


    def set_satellite_docked(self, docked):
        tool = provider.get_tool()
        name = "Dock Satellite View"
        action = get_action(tool, name)
        self.assertIsNotNone(name + " not in tool", action)
        dock_satellite_action = (ToggleDockingAction) action
        set_toggle_action_selected(dock_satellite_action, provider.get_action_context(None), docked)
        run_swing()


    def create_tool(self):
        return run_swing(lambda: FakeDockingTool())


class TestProvider(VisualGraphComponentProvider):

    def __init__(self, tool, viewer):
        super().__init__(tool, "Test VG Provider", "Test Owner")

        self.component = JPanel()
        self.component.add(viewer.get_view_component())

        add_to_tool()
        add_satellite_feature()


if __name__ == '__main__':
    unittest.main()

```

This Python code is equivalent to the given Java code. It includes tests for opening and closing satellite windows, as well as verifying that they reopen when the main graph window is reopened or closed.