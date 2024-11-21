Here is the translation of the Java code into Python:

```Python
import collections
from typing import Set, List, Deque

class AcyclicCallGraphBuilder:
    def __init__(self, program: object, kill_thunks: bool = False):
        self.program = program
        self.function_set = set()
        self.kill_thunks = kill_thunks

    @staticmethod
    def find_functions(program: object, address_set_view: Set[object], kill_thunks: bool) -> Set[object]:
        function_starts = set()

        for func in program.get_function_manager().get_functions(address_set_view):
            if kill_thunks and func.is_thunk():
                func = func.get_thunked_function(True)
            function_starts.add(func.get_entry_point())

        return function_starts

    def get_dependency_graph(self, monitor: object) -> List[object]:
        graph = []
        start_points = collections.deque()
        unprocessed = set(self.function_set)

        for addr in self.function_set:
            if is_start_function(addr):
                start_points.append(addr)
                break
        while unprocessed:
            monitor.check_cancelled()

            function_entry = next(start_points) if start_points else unprocessed.popitem(last=False)[0]
            process_forward(graph, unprocessed, function_entry, monitor)

        return graph

    def get_next_start_function(self, start_points: Deque[object], un_processed_set: Set[object]) -> object:
        while start_points:
            addr = start_points.popleft()
            if un_processed_set.issuperset({addr}):
                return addr
        return next(iter(un_processed_set))

    def find_start_points(self) -> List[object]:
        start_points = []

        for addr in self.function_set:
            if is_start_function(addr):
                start_points.append(addr)

        return start_points

    @staticmethod
    def initialize_node(node: object, function_manager: object, reference_manager: object) -> None:
        func = function_manager.get_function_at(node)
        if func.is_thunk():
            thunked_func = func.get_thunked_function(False)
            node.children = [thunked_func.get_entry_point()]
            return

        children = []
        for ref in reference_manager.get_flow_references_from(func.body, True):
            to_addr = ref.to_address
            if ref.reference_type.is_call() and self.function_set.issuperset({to_addr}):
                child_func = function_manager.get_function_at(to_addr)
                if kill_thunks and child_func.is_thunk():
                    child_func = child_func.get_thunked_function(True)
                    to_addr = child_func.get_entry_point()
                children.append(to_addr)

        node.children = [child for child in set(children)]

    def process_forward(self, graph: List[object], unprocessed: Set[object], start_function: object, monitor: object) -> None:
        stack = collections.deque([start_function])
        while stack:
            monitor.check_cancelled()

            curnode = stack[-1]
            if len(curnode.children) <= curnode.nextchild:
                unprocessed.discard(curnode)
                graph.append(curnode)
                stack.pop()
            else:
                child_addr = curnode.children[curnode.nextchild]
                curnode.nextchild += 1
                if unprocessed.issuperset({child_addr}):
                    stack.append(child_addr)
                    initialize_node(stack[-1], self.program.get_function_manager(), self.program.get_reference_manager())
                    graph.append(stack[-1])
                else:
                    graph.append((curnode, child_addr))

    @staticmethod
    def is_start_function(addr: object) -> bool:
        reference_manager = self.program.get_reference_manager()
        references_to = list(reference_manager.get_references_to(addr))
        for ref in references_to:
            if ref.is_entry_point_reference():
                return True
            elif ref.reference_type.is_call():
                return False

    @staticmethod
    def main() -> None:
        # Initialize the program and other necessary objects here.
        pass


if __name__ == "__main__":
    AcyclicCallGraphBuilder.main()
```

Please note that this is a direct translation of your Java code into Python. It might not be perfect, as some parts may need to be adjusted based on how you intend to use the classes and methods in your actual program.