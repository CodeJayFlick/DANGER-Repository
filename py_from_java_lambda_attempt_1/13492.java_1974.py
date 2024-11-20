Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.datamgr.actions import TypeGraphTask
from ghidra.graph.testgraphdisplay import TestGraphDisplay
from ghidra.program.model.data import StructureDataType, IntegerDataType, FloatDataType, PointerDataType, TypedefDataType

class TestTypeGraphTask(unittest.TestCase):

    def setUp(self):
        self.base = StructureDataType("base structure", 16)
        self.base.insert(0, IntegerDataType())
        
        self.other = StructureDataType("another struct", 20)
        self.other.insert(0, IntegerDataType())
        self.other.insert(1, FloatDataType())

        self.pointer = PointerDataType(IntegerDataType())
        self.otherPointer = PointerDataType(self.other)

        self.otherTypeDef = TypedefDataType("other_ t", self.other)

    def testSimpleStructure(self):
        task = TypeGraphTask(self.base)
        task.run()

        display = TestGraphDisplay()
        graph = display.get_graph()
        
        self.assertEqual(1, len(graph.vertices))
        vertex = graph.get_vertex(self.base.name)
        self.assertIsNotNone(vertex)

    def testNestedStructure(self):
        self.base.insert(1, self.other)
        task = TypeGraphTask(self.base)
        task.run()

        display = TestGraphDisplay()
        graph = display.get_graph()
        
        self.assertEqual(2, len(graph.vertices))
        vertex1 = graph.get_vertex(self.base.name)
        self.assertIsNotNone(vertex1)
        vertex2 = graph.get_vertex(self.other.name)
        self.assertIsNotNone(vertex2)

    def testStructureWithPointer(self):
        self.base.insert(1, self.pointer)
        task = TypeGraphTask(self.base)
        task.run()

        display = TestGraphDisplay()
        graph = display.get_graph()
        
        self.assertEqual(1, len(graph.vertices))
        vertex = graph.get_vertex(self.base.name)
        self.assertIsNotNone(vertex)

    def testPointerToStructure(self):
        self.base.insert(1, self.otherPointer)
        task = TypeGraphTask(self.base)
        task.run()

        display = TestGraphDisplay()
        graph = display.get_graph()
        
        self.assertEqual(2, len(graph.vertices))
        vertex1 = graph.get_vertex(self.base.name)
        self.assertIsNotNone(vertex1)
        vertex2 = graph.get_vertex(self.other.name)
        self.assertIsNotNone(vertex2)

    def testEmbeddedAndPointer(self):
        self.base.insert(1, self.other)
        self.base.insert(2, self.pointer)
        task = TypeGraphTask(self.base)
        task.run()

        display = TestGraphDisplay()
        graph = display.get_graph()
        
        self.assertEqual(2, len(graph.vertices))
        vertex1 = graph.get_vertex(self.base.name)
        self.assertIsNotNone(vertex1)
        vertex2 = graph.get_vertex(self.other.name)
        self.assertIsNotNone(vertex2)

    def testPointerToTypedef(self):
        typedefPtr = PointerDataType(self.otherTypeDef)
        self.base.insert(1, typedefPtr)
        task = TypeGraphTask(self.base)
        task.run()

        display = TestGraphDisplay()
        graph = display.get_graph()
        
        self.assertEqual(2, len(graph.vertices))
        vertex1 = graph.get_vertex(self.base.name)
        self.assertIsNotNone(vertex1)
        vertex2 = graph.get_vertex(self.other.name)
        self.assertIsNotNone(vertex2)

    def testPointerToSelf(self):
        selfPtr = PointerDataType(self.base)
        self.base.insert(1, selfPtr)
        task = TypeGraphTask(self.base)
        task.run()

        display = TestGraphDisplay()
        graph = display.get_graph()
        
        self.assertEqual(1, len(graph.vertices))
        vertex = graph.get_vertex(self.base.name)
        self.assertIsNotNone(vertex)

    def testPointerCycle(self):
        self.base.insert(1, self.otherPointer)
        basePtr = PointerDataType(self.base)
        self.other.insert(1, basePtr)
        task = TypeGraphTask(self.base)
        task.run()

        display = TestGraphDisplay()
        graph = display.get_graph()
        
        self.assertEqual(2, len(graph.vertices))
        vertex1 = graph.get_vertex(self.base.name)
        self.assertIsNotNone(vertex1)
        vertex2 = graph.get_vertex(self.other.name)
        self.assertIsNotNone(vertex2)

if __name__ == '__main__':
    unittest.main()
```