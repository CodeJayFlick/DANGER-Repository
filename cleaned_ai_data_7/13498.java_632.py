import unittest
from ghidra_graph import DataReferenceGraphTask, TestGraphService, ProgramLocation, AttributedVertex, AttributedEdge
from ghidra_program import program, addr

class TestDataReferenceGraphTask(unittest.TestCase):

    def test_GraphWithLimit(self):
        graph_service = TestGraphService()
        task = DataReferenceGraphTask(False, False, tool, None, 
            ProgramLocation(program, addr(0x0100001d)), graph_service, 1, 10, 
            DataReferenceGraph.DIRECTIONS_BOTH_WAYS)
        task.monitored_run(TaskMonitor.DUMMY)

        display = (TestGraphDisplay)graph_service.get_graph_display(True, TaskMonitor.DUMMY)
        graph = (DataReferenceGraph)display.get_graph()

        self.assertEqual(2, graph.get_vertex_count())
        v1 = graph.get_vertex(graph.make_name(addr(0x0100001d)))
        v2 = graph.get_vertex(graph.make_name(addr(0x0100000c)))
        e1 = graph.get_edge(v1, v2)
        self.assertIsNotNone(v1)
        self.assertIsNotNone(v2)
        self.assertIsNotNone(e1)

    def test_GraphWithoutLimit(self):
        graph_service = TestGraphService()
        task = DataReferenceGraphTask(False, False, tool, None, 
            ProgramLocation(program, addr(0x0100001d)), graph_service, 0, 10, 
            DataReferenceGraph.DIRECTIONS_BOTH_WAYS)
        task.monitored_run(TaskMonitor.DUMMY)

        display = (TestGraphDisplay)graph_service.get_graph_display(True, TaskMonitor.DUMMY)
        graph = (DataReferenceGraph)display.get_graph()

        self.assertEqual(3, graph.get_vertex_count())
        v1 = graph.get_vertex(graph.make_name(addr(0x0100001d)))
        v2 = graph.get_vertex(graph.make_name(addr(0x0100000c)))
        v3 = graph.get_vertex(graph.make_name(addr(0x0100000f)))
        e1 = graph.get_edge(v1, v2)
        e2 = graph.get_edge(v2, v3)
        self.assertIsNotNone(v1)
        self.assertIsNotNone(v2)
        self.assertIsNotNone(v3)
        self.assertIsNotNone(e1)
        self.assertIsNotNone(e2)

    def test_GraphAdd(self):
        graph_service = TestGraphService()
        task = DataReferenceGraphTask(False, False, tool, None, 
            ProgramLocation(program, addr(0x0100001d)), graph_service, 1, 10, 
            DataReferenceGraph.DIRECTIONS_BOTH_WAYS)
        task.monitored_run(TaskMonitor.DUMMY)

        display = (TestGraphDisplay)graph_service.get_graph_display(True, TaskMonitor.DUMMY)
        graph = (DataReferenceGraph)display.get_graph()

        self.assertEqual(2, graph.get_vertex_count())
        v1 = graph.get_vertex(graph.make_name(addr(0x0100001d)))
        v2 = graph.get_vertex(graph.make_name(addr(0x0100000c)))
        e1 = graph.get_edge(v1, v2)
        self.assertIsNotNone(v1)
        self.assertIsNotNone(v2)
        self.assertIsNotNone(e1)

        task_add = DataReferenceGraphTask(tool, program, addrSet(0x0100000c, 0x0100000f), display, 1, 
            DataReferenceGraph.DIRECTIONS_BOTH_WAYS)
        task_add.monitored_run(TaskMonitor.DUMMY)
        graph = (DataReferenceGraph)display.get_graph()
        self.assertEqual(3, graph.get_vertex_count())
        v1_add = graph.get_vertex(graph.make_name(addr(0x0100001d)))
        v2_add = graph.get_vertex(graph.make_name(addr(0x0100000c)))
        v3_add = graph.get_vertex(graph.make_name(addr(0x0100000f)))
        e1_add = graph.get_edge(v1_add, v2_add)
        e2_add = graph.get_edge(v2_add, v3_add)
        self.assertIsNotNone(v1_add)
        self.assertIsNotNone(v2_add)
        self.assertIsNotNone(v3_add)
        self.assertIsNotNone(e1_add)
        self.assertIsNotNone(e2_add)

    def test_DirectionsBoth(self):
        graph_service = TestGraphService()
        task = DataReferenceGraphTask(False, False, tool, None, 
            ProgramLocation(program, addr(0x0100000c)), graph_service, 0, 10, 
            DataReferenceGraph.DIRECTIONS_BOTH_WAYS)
        task.monitored_run(TaskMonitor.DUMMY)

        display = (TestGraphDisplay)graph_service.get_graph_display(True, TaskMonitor.DUMMY)
        graph = (DataReferenceGraph)display.get_graph()

        self.assertEqual(3, graph.get_vertex_count())
        v1 = graph.get_vertex(graph.make_name(addr(0x0100001d)))
        v2 = graph.get_vertex(graph.make_name(addr(0x0100000c)))
        v3 = graph.get_vertex(graph.make_name(addr(0x0100000f)))
        e1 = graph.get_edge(v1, v2)
        e2 = graph.get_edge(v2, v3)
        self.assertIsNotNone(v1)
        self.assertIsNotNone(v2)
        self.assertIsNotNone(v3)
        self.assertIsNotNone(e1)
        self.assertIsNotNone(e2)

    def test_DirectionsTo(self):
        graph_service = TestGraphService()
        task = DataReferenceGraphTask(False, False, tool, None, 
            ProgramLocation(program, addr(0x0100000c)), graph_service, 0, 10, 
            DataReferenceGraph.DIRECTIONS_TO_ONLY)
        task.monitored_run(TaskMonitor.DUMMY)

        display = (TestGraphDisplay)graph_service.get_graph_display(True, TaskMonitor.DUMMY)
        graph = (DataReferenceGraph)display.get_graph()

        self.assertEqual(2, graph.get_vertex_count())
        v1 = graph.get_vertex(graph.make_name(addr(0x0100001d)))
        v2 = graph.get_vertex(graph.make_name(addr(0x0100000c)))
        e1 = graph.get_edge(v1, v2)
        self.assertIsNone(e1)

    def test_DirectionsFrom(self):
        graph_service = TestGraphService()
        task = DataReferenceGraphTask(False, False, tool, None, 
            ProgramLocation(program, addr(0x0100000c)), graph_service, 0, 10, 
            DataReferenceGraph.DIRECTIONS_FROM_ONLY)
        task.monitored_run(TaskMonitor.DUMMY)

        display = (TestGraphDisplay)graph_service.get_graph_display(True, TaskMonitor.DUMMY)
        graph = (DataReferenceGraph)display.get_graph()

        self.assertEqual(2, graph.get_vertex_count())
        v1 = graph.get_vertex(graph.make_name(addr(0x0100001d)))
        v2 = graph.get_vertex(graph.make_name(addr(0x0100000c)))
        e1 = graph.get_edge(v2, v1)
        self.assertIsNone(e1)

    def test_NodeWithType(self):
        graph_service = TestGraphService()
        task = DataReferenceGraphTask(False, False, tool, None, 
            ProgramLocation(program, addr(0x0100001d)), graph_service, 1, 10, 
            DataReferenceGraph.DIRECTIONS_BOTH_WAYS)
        task.monitored_run(TaskMonitor.DUMMY)

        display = (TestGraphDisplay)graph_service.get_graph_display(True, TaskMonitor.DUMMY)
        graph = (DataReferenceGraph)display.get_graph()

        vertex = graph.get_vertex(graph.make_name(addr(0x0100001d)))
        self.assertEqual("pointer_thing", vertex.getAttribute(DataReferenceGraph.DATA_ATTRIBUTE))
        self.assertEqual("0100001d", vertex.getAttribute(DataReferenceGraph.ADDRESS_ATTRIBUTE))
        self.assertIsNone(vertex.getAttribute(DataReferenceGraph.LABEL_ATTRIBUTE))

    def test_CodeReference(self):
        graph_service = TestGraphService()
        task = DataReferenceGraphTask(False, False, tool, None, 
            ProgramLocation(program, addr(0x01002200)), graph_service, 0, 10, 
            DataReferenceGraph.DIRECTIONS_BOTH_WAYS)
        task.monitored_run(TaskMonitor.DUMMY)

        display = (TestGraphDisplay)graph_service.get_graph_display(True, TaskMonitor.DUMMY)
        graph = (DataReferenceGraph)display.get_graph()

        self.assertEqual(2, graph.get_vertex_count())
        v1 = graph.get_vertex(graph.make_name(addr(0x01002200)))
        v2 = graph.get_vertex(graph.make_name(addr(0x01000000)))
        e1 = graph.get_edge(v1, v2)
        self.assertIsNotNone(v1)
        self.assertIsNotNone(v2)
        self.assertIsNotNone(e1)

    def test_GraphSelection(self):
        selection = ProgramSelection(addr(0x01000000), addr(0x0100000c))
        graph_service = TestGraphService()
        task = DataReferenceGraphTask(False, False, tool, selection, 
            ProgramLocation(program, addr(0x0100000c)), graph_service, 0, 10, 
            DataReferenceGraph.DIRECTIONS_BOTH_WAYS)
        task.monitored_run(TaskMonitor.DUMMY)

        display = (TestGraphDisplay)graph_service.get_graph_display(True, TaskMonitor.DUMMY)
        graph = (DataReferenceGraph)display.get_graph()

        self.assertEqual(6, graph.get_vertex_count())
        v1 = graph.get_vertex(graph.make_name(addr(0x0100001d)))
        v2 = graph.get_vertex(graph.make_name(addr(0x0100000c)))
        v3 = graph.get_vertex(graph.make_name(addr(0x0100000f)))
        v4 = graph.get_vertex(graph.make_name(addr(0x01002200)))
        v5 = graph.get_vertex(graph.make_name(addr(0x01000000)))
        e1 = graph.get_edge(v2, v3)
        self.assertIsNotNone(v1)
        self.assertIsNotNone(v2)
        self.assertIsNotNone(v3)
        self.assertIsNotNone(v4)
        self.assertIsNotNone(v5)
        self.assertIsNotNone(e1)

if __name__ == '__main__':
    unittest.main()
