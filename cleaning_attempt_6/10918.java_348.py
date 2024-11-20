import unittest
from ghidra.graph import graphs
from ghidra.util.exception import CancelledException
from ghidra.util.task import TaskMonitor
from ghidra.util.msg import Msg
from ghidra.graph.viewer.event.mouse import VisualGraphMouseTrackingGraphMousePlugin, VisualGraphPluggableGraphMouse

class AbstractVisualGraphTest(unittest.TestCase):
    def setUp(self):
        self.build_and_layout_graph()
        self.initialize()

        frame = JFrame("Graph Viewer Test")
        swing(lambda: {
            frame.set_size(400, 400)
            frame.get_content_panel().add(graph_component.get_component())
            frame.setVisible(True)
            frame.validate()
        })

    def build_and_layout_graph(self):
        graph = run_swing(lambda: self.build_graph())

        layout_provider = create_layout_provider()

        graph.setLayout(layout_provider.get_layout(graph, TaskMonitor.DUMMY))
        graph_component = run_swing(lambda: self.create_graph_component(layout_provider))

    def create_layout_provider(self):
        return TestLayoutProvider()

    def create_graph_component(self, layout_provider):
        return GraphComponent(graph)

    def initialize(self):
        pass

    @property
    def frame(self):
        return frame

    @frame.setter
    def frame(self, value):
        self._frame = value

    @property
    def graph(self):
        return self._graph

    @graph.setter
    def graph(self, value):
        self._graph = value

    @property
    def graph_component(self):
        return self._graph_component

    @graph_component.setter
    def graph_component(self, value):
        self._graph_component = value

    def build_graph(self):
        pass

    def test_method(self):
        # your code here...

if __name__ == '__main__':
    unittest.main()
