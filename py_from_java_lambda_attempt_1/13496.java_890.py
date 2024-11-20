Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.program.model.block import CodeBlockModel
from ghidra.graph.service import TestGraphService
from ghidra.util.task import TaskMonitor
from ghidra.program.model import ProgramSelection
from ghidra. graph.flowgraphtype import BlockFlowGraphType, CallGraphType

class BlockGraphTaskTest(unittest.TestCase):

    def test_block_graph(self):
        model_name = block_model_service.get_active_block_model_name()
        model = block_model_service.get_new_model_by_name(model_name, program, True)
        graph_service = TestGraphService()
        task = BlockGraphTask(BlockFlowGraphType(), False, False, False, tool, None, None, model, graph_service)

        task.monitored_run(TaskMonitor.DUMMY)

        display = (TestGraphDisplay)graph_service.get_graph_display(True, TaskMonitor.DUMMY)
        graph = display.get_graph()

        self.assertEqual(5, graph.get_vertex_count())
        v1 = graph.get_vertex("01002200")
        v2 = graph.get_vertex("01002203")
        v3 = graph.get_vertex("01002239")
        v4 = graph.get_vertex("0100223c")
        v5 = graph.get_vertex("0100223e")

        self.assertIsNotNone(v1)
        self.assertIsNotNone(v2)
        self.assertIsNotNone(v3)
        self.assertIsNotNone(v4)
        self.assertIsNotNone(v5)

        self.assertEqual(5, graph.get_edge_count())
        e1 = graph.get_edge(v1, v2)
        e2 = graph.get_edge(v1, v3)
        e3 = graph.get_edge(v3, v4)
        e4 = graph.get_edge(v4, v5)
        e5 = graph.get_edge(v3, v5)

        self.assertIsNotNone(e1)
        self.assertIsNotNone(e2)
        self.assertIsNotNone(e3)
        self.assertIsNotNone(e4)
        self.assertIsNotNone(e5)

        map = v1.attributes
        self.assertEqual(2, len(map))
        self.assertTrue("Name" in map and "VertexType" in map)

        self.assertEqual("Entry", v3.attribute("VertexType"))
        self.assertEqual("Body", v4.attribute("VertexType"))
        self.assertEqual("Exit", v5.attribute("VertexType"))

    def test_code_block_graph(self):
        model_name = block_model_service.get_active_block_model_name()
        model = block_model_service.get_new_model_by_name(model_name, program, True)
        graph_service = TestGraphService()
        task = BlockGraphTask(CodeFlowGraphType(), False, False, False, tool, None, None, model, graph_service)

        task.monitored_run(TaskMonitor.DUMMY)

        display = (TestGraphDisplay)graph_service.get_graph_display(True, TaskMonitor.DUMMY)
        graph = display.get_graph()

        self.assertEqual(5, graph.get_vertex_count())
        v1 = graph.get_vertex("01002200")
        v2 = graph.get_vertex("01002203")
        v3 = graph.get_vertex("01002239")
        v4 = graph.get_vertex("0100223c")
        v5 = graph.get_vertex("0100223e")

        self.assertIsNotNone(v1)
        self.assertIsNotNone(v2)
        self.assertIsNotNone(v3)
        self.assertIsNotNone(v4)
        self.assertIsNotNone(v5)

        self.assertEqual(5, graph.get_edge_count())
        e1 = graph.get_edge(v1, v2)
        e2 = graph.get_edge(v1, v3)
        e3 = graph.get_edge(v3, v4)
        e4 = graph.get_edge(v4, v5)
        e5 = graph.get_edge(v3, v5)

        self.assertIsNotNone(e1)
        self.assertIsNotNone(e2)
        self.assertIsNotNone(e3)
        self.assertIsNotNone(e4)
        self baise None(e5)

        map = v3.attributes
        self.assertEqual(4, len(map))
        self.assertTrue("Name" in map and "VertexType" in map and "Code" in map and "Symbols" in map)

    def test_call_graph(self):
        model_name = block_model_service.get_active_subroutine_model_name()
        model = block_model_service.get_new_model_by_name(model_name, program, True)
        graph_service = TestGraphService()
        task = BlockGraphTask(CallGraphType(), False, False, False, tool, None, None, model, graph_service)

        task.monitored_run(TaskMonitor.DUMMY)

        display = (TestGraphDisplay)graph_service.get_graph_display(True, TaskMonitor.DUMMY)
        graph = display.get_graph()

        self.assertEqual(2, graph.get_vertex_count())
        v1 = graph.get_vertex("01002200")
        v2 = graph.get_vertex("01002239")

        self.assertIsNotNone(v1)
        self.assertIsNotNone(v2)

        self.assertEqual(1, graph.get_edge_count())
        e1 = graph.get_edge(v1, v2)

        self.assertIsNotNone(e1)

        map = v1.attributes
        self.assertEqual(2, len(map))
        self.assertTrue("Name" in map and "VertexType" in map)

    def test_block_graph_with_selection(self):
        model_name = block_model_service.get_active_block_model_name()
        model = block_model_service.get_new_model_by_name(model_name, program, True)
        graph_service = TestGraphService()
        selection = ProgramSelection(addr(0x1002239), addr(0x1002247))
        task = BlockGraphTask(BlockFlowGraphType(), False, False, False, tool, selection, None, model, graph_service)

        task.monitored_run(TaskMonitor.DUMMY)

        display = (TestGraphDisplay)graph_service.get_graph_display(True, TaskMonitor.DUMMY)
        graph = display.get_graph()

        self.assertEqual(3, graph.get_vertex_count())
        v1 = graph.get_vertex("01002200")
        v2 = graph.get_vertex("01002203")
        v3 = graph.get_vertex("01002239")
        v4 = graph.get_vertex("0100223c")
        v5 = graph.get_vertex("0100223e")

        self.assertIsNone(v1)
        self.assertIsNone(v2)
        self.assertIsNotNone(v3)
        self.assertIsNotNone(v4)
        self.assertIsNotNone(v5)

        self.assertEqual(3, graph.get_edge_count())
        e3 = graph.get_edge(v3, v4)
        e4 = graph.get_edge(v4, v5)
        e5 = graph.get_edge(v3, v5)

        self.assertIsNotNone(e3)
        self.assertIsNotNone(e4)
        self baise None(e5)