Here is the translation of the Java code into Python:

```Python
import unittest
from collections import defaultdict

class AcyclicCallGraphBuilderTest(unittest.TestCase):

    def setUp(self):
        self.space = AddressSpace("Test", 32, "RAM", 0)
        self.functions = set()
        self.ref_state = ReferenceState()
        self.function_map = {}
        self.program = create_program()

    def test_diamond_graph(self):
        node(1, 2, 3)
        graph = build_call_graph()
        self.assertEqual(len(graph), 4)

        assert_dependents(graph, 4, [2, 3])
        assert_dependents(graph, 2, [1])
        assert_dependents(graph, 3, [1])
        assert_dependents(graph, 1, [])

    def test_3_sided_diamond_graph(self):
        node(1, 2)
        node(1, 3)
        node(2, 3)

        graph = build_call_graph()
        self.assertEqual(len(graph), 3)

        assert_dependents(graph, 3, [1, 2])
        assert_dependents(graph, 2, [1])
        assert_dependents(graph, 1, [])

    def test_simple_cycle(self):
        node(1, 2)
        node(2, 3)
        node(3, 1)

        graph = build_call_graph()
        self.assertEqual(len(graph), 3)

        assert_dependents(graph, 3, [2])
        assert_dependents(graph, 2, [1])
        assert_dependents(graph, 1, [])

    def test_node_with_self_cycle(self):
        node(1, 2)
        node(2, 3)
        node(3, 1)
        node(2, 2)

        graph = build_call_graph()
        self.assertEqual(len(graph), 3)

        assert_dependents(graph, 3, [2])
        assert_dependents(graph, 2, [1])
        assert_dependents(graph, 1, [])

    def test_where_first_node_is_not_root(self):
        node(1, 3)
        node(2, 3)
        node(3, 1)

        graph = build_call_graph()
        self.assertEqual(len(graph), 3)

        assert_dependents(graph, 1, [3])
        assert_dependents(graph, 3, [2])
        assert_dependents(graph, 2, [])

    def test_simple_thunks(self):
        node(1, 2)
        node(1, 4)
        node(1, 6)
        node(1, 9)
        node(1, 12)
        node(1, 13)

        thunk_node(2, 3, True)
        thunk_node(4, 5, False)
        thunk_node(6, 7, True)
        thunk_node(7, 8, True)
        thunk_node(9, 10, False)
        thunk_node(10, 11, False)
        thunk_node(12, 14, False)
        thunk_node(13, 14, False)

        graph = build_call_graph()
        self.assertEqual(len(graph), 18)

        assert_dependents(graph, 2, [1])
        assert_dependents(graph, 4, [1])
        assert_dependents(graph, 6, [1])
        assert_dependents(graph, 9, [1])
        assert_dependents(graph, 12, [1])
        assert_dependents(graph, 13, [1])

    def test_killed_thunks(self):
        node(1, 2)
        node(1, 4)
        node(1, 6)
        node(1, 9)
        node(1, 12)
        node(1, 13)

        thunk_node(2, 3, True)
        thunk_node(4, 5, False)
        thunk_node(6, 7, True)
        thunk_node(7, 8, True)
        thunk_node(9, 10, False)
        thunk_node(10, 11, False)
        thunk_node(12, 14, False)
        thunk_node(13, 14, False)

        graph = build_call_graph(True)
        self.assertEqual(len(graph), 8)

    def test_recurse_thru_thunk(self):
        node(1, 2)
        node(2, 3)   # Recursion between 2 and 3
        node(3, 2)
        node(3, 4)
        node(1, 5)

        thunk_node(5, 3, True)    # Thunk node hits recursion from different point

        graph = build_call_graph(True)
        self.assertEqual(len(graph), 4)

        assert_dependents(graph, 2, [1])
        assert_dependents(graph, 3, [1, 2])

    def test_node(self):
        pass

    def create_program(self):
        return ProgramTestDouble()

    def node(self, from_id, *to_ids):
        for to_id in to_ids:
            self.function_map[self.space.get_address(to_id*256)] = None
            self.ref_state.create_reference(self.space.get_address(from_id*256), self.space.get_address(to_id*256))

    def thunk_node(self, function_id, dest_function_id, has_ref):
        address = self.space.get_address(function_id * 256)
        to_addr = self.space.get_address(dest_function_id * 256)

        if not self.function_map.get(address):
            self.functions.add(None)
            self.function_map[address] = None

        ref_state.create_reference(address, to_addr) if has_ref else None
        create_thunk_function(address, to_addr)

    def build_call_graph(self, kill_thunks=False):
        builder = AcyclicCallGraphBuilder(self.program, self.functions, kill_thunks)
        return builder.get_dependency_graph()

class ReferenceState:
    def __init__(self):
        pass

    def create_reference(self, from_address, to_address):
        pass

class ProgramTestDouble:
    def get_function_manager(self):
        return None

class FunctionManagerTestDouble:
    def get_function_at(self, address):
        return None

class AddressSpace:
    def __init__(self, name, size, type, offset):
        self.name = name
        self.size = size
        self.type = type
        self.offset = offset

    def get_address(self, offset):
        pass

def create_program():
    return ProgramTestDouble()

def create_thunk_function(from_addr, to_addr):
    pass

class Function:
    def __init__(self, name):
        self.name = name

    def isThunkedFunction(self):
        pass

if __name__ == '__main__':
    unittest.main()
```

Please note that this code doesn't include the `create_thunk_function` and `isThunkedFunction` methods as they are not provided in your original Java code.