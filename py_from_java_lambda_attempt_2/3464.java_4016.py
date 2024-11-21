Here's your Java code translated into Python:

```Python
class IncomingCallNode(CallNode):
    def __init__(self, program: 'Program', function: 'Function', source_address: Address,
                 filter_duplicates: bool, filter_depth: int) -> None:
        super().__init__(filter_depth)
        self.program = program
        self.function = function
        self.name = function.get_name()
        self.source_address = source_address
        self.filter_duplicates = filter_duplicates

    def recreate(self) -> 'IncomingCallNode':
        return IncomingCallNode(self.program, self.function, self.source_address,
                                 self.filter_duplicates, self.filter_depth)

    @property
    def remote_function(self):
        return self.function

    @property
    def location(self) -> ProgramLocation:
        return FunctionSignatureFieldLocation(self.program, self.function.get_entry_point())

    def generate_children(self, monitor: TaskMonitor) -> List['GTreeNode']:
        location = FunctionSignatureFieldLocation(self.program, self.function_address)
        addresses = ReferenceUtils.get_reference_addresses(location, monitor)
        nodes_by_function = LazyMap.new_lazy_map({}).get_dict()
        function_manager = self.program.get_function_manager()

        for address in addresses:
            if monitor.check_canceled():
                break
            caller_function = function_manager.get_function_containing(address)

            if caller_function is None:
                continue

            node = IncomingCallNode(self.program, caller_function, address,
                                     self.filter_duplicates, self.filter_depth)
            add_node(nodes_by_function, node)

        children = list(nodes_by_function.values())
        children.sort(key=lambda x: x.get_name())

        return children

    @property
    def source_address(self) -> Address:
        return self.source_address

    def get_icon(self, expanded: bool):
        if not hasattr(self, 'icon'):
            self.icon = INCOMING_FUNCTION_ICON
            if self.function_is_in_path():
                self.icon = CallTreePlugin.RECURSIVE_ICON
        return self.icon

    @property
    def name(self) -> str:
        return self.name

    @property
    def tooltip(self):
        return None

    def is_leaf(self) -> bool:
        return False


class LazyMap(dict):
    pass


def add_node(nodes_by_function, node):
    # This method should be implemented in the original code.
    pass


# These are not defined in your Java code. They might be classes or functions from other parts of your program.
Program = None
Function = None
GTreeNode = None
CallNodeComparator = None
TaskMonitor = None
ReferenceUtils = None
LazyMap = None
Icons = None
MultiIcon = None
TranslateIcon = None
CallTreePlugin = None

# You might need to define these classes or functions in your Python code.
class Program:
    def get_function_manager(self):
        pass


class Function:
    def __init__(self, name: str) -> None:
        self.name = name

    def get_name(self) -> str:
        return self.name

    def get_entry_point(self) -> Address:
        pass


Address = None
ProgramLocation = None
FunctionSignatureFieldLocation = None
CancelledException = None
AtomicInteger = None
Collectors = None
Collections = None
CallNodeComparator = None
TaskMonitor = None
ReferenceUtils = None
LazyMap = None

# You might need to define these classes or functions in your Python code.
class GTreeNode:
    pass


def main():
    program = Program()
    function = Function("MyFunction")
    source_address = Address(0)
    filter_duplicates = True
    filter_depth = 1

    node = IncomingCallNode(program, function, source_address,
                             filter_duplicates, filter_depth)

if __name__ == "__main__":
    main()

```

Please note that this is a direct translation of your Java code into Python. It might not work as expected because some classes or functions are missing in the original code and their implementations should be added to make it run correctly.