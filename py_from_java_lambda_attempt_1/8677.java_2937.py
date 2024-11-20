Here is the translation of the Java code into Python:

```Python
class DataReferenceGraph:
    REF_SOURCE_ATTRIBUTE = "Source"
    REF_TYPE_ATTRIBUTE = "Type"
    REF_SYMBOL_ATTRIBUTE = "Symbol"
    DATA_ATTRIBUTE = "DataType"
    ADDRESS_ATTRIBUTE = "Address"
    LABEL_ATTRIBUTE = "Label"

    class Directions(enum.Enum):
        TO_ONLY = 1
        FROM_ONLY = 2
        BOTH_WAYS = 3

    def __init__(self, program: 'Program', depth: int) -> None:
        self.program = program
        self.depth_per_step = depth
        super().__init__("Data Reference", DataFlowGraphType())

    @staticmethod
    def make_name(address):
        code_unit = address.get_code_unit()
        if not code_unit:
            return str(address)
        unit_address = code_unit.get_address()

        name = None
        symbol_table = program.get_symbol_table()
        primary_symbol = symbol_table.get_primary_symbol(unit_address)

        if primary_symbol is not None:
            name = primary_symbol.name(True)
        else:
            name = str(unit_address)

        return name

    def graph_from(self, base_address: 'Address', direction: Directions, monitor):
        if base_address is None:
            return None
        vertex = AttributedVertex(self.make_name(base_address))
        vertex.set_attribute(ADDRESS_ATTRIBUTE, str(base_address))
        self.setup_vertex(vertex)
        self.add_vertex(vertex)

        try:
            self.recurse_graph(base_address, self.depth_per_step, direction, monitor)
        except CancelledException as e:
            print(f"Cancelled: {e}")

    def setup_edge(self, edge, ref):
        edge.set_attribute(REF_SOURCE_ATTRIBUTE, ref.get_source().display_string())
        edge.set_edge_type(ProgramGraphType.edge_type(ref.reference_type()))
        if ref.symbol_id != -1:
            symbol = self.program.get_symbol_table().get_symbol(ref.symbol_id)
            edge.set_attribute(REF_SYMBOL_ATTRIBUTE, symbol.name)

    def setup_vertex(self, vertex):
        address = Address(vertex.attribute(ADDRESS_ATTRIBUTE))
        code_unit = self.program.get_listing().code_unit_containing(address)
        if isinstance(code_unit, Data):
            vertex.set_attribute(DATA_ATTRIBUTE, code_unit.base_data_type.name())
            vertex.set_vertex_type(ProgramGraphType.DATA)
        elif isinstance(code_unit, Instruction):
            vertex.set_vertex_type(ProgramGraphType.INSTRUCTION)
        else:
            vertex.set_vertex_type(ProgramGraphType.STACK)

    def recurse_graph(self, start_address: 'Address', max_depth: int, direction: Directions, monitor):
        if direction != DataReferenceGraph.Directions.FROM_ONLY:
            for ref in self.program.get_listing().code_unit_containing(start_address).reference_iterator_to():
                if not ref.reference_type.is_flow():
                    next_address = process_reference(direction, start_vertex=start_address, ref=ref)
                    monitor.check_cancelled()
                    if next_address is not None:
                        if max_depth > 1:
                            self.recurse_graph(next_address, max_depth - 1, direction, monitor)
                        elif max_depth == 0:
                            self.recurse_graph(next_address, 0, direction, monitor)

        if direction != DataReferenceGraph.Directions.TO_ONLY:
            for ref in self.program.get_listing().code_unit_containing(start_address).references_from():
                if not ref.reference_type.is_flow():
                    next_address = process_reference(direction, start_vertex=start_address, ref=ref)
                    monitor.check_cancelled()
                    if next_address is not None:
                        if max_depth > 1:
                            self.recurse_graph(next_address, max_depth - 1, direction, monitor)
                        elif max_depth == 0:
                            self.recurse_graph(next_address, 0, direction, monitor)

    def process_reference(self, direction: Directions, start_vertex: 'AttributedVertex', ref):
        target_address = None
        if direction == DataReferenceGraph.Directions.TO_ONLY:
            target_address = ref.from_address()
        else:
            target_address = ref.to_address()

        vertex = AttributedVertex(self.make_name(target_address))
        vertex.set_attribute(ADDRESS_ATTRIBUTE, str(target_address))
        self.setup_vertex(vertex)
        edge = None
        if direction == DataReferenceGraph.Directions.TO_ONLY:
            edge = self.add_edge(new_vertex=vertex, start_vertex=start_vertex)
        else:
            edge = self.add_edge(start_vertex=start_vertex, new_vertex=vertex)

        if not edge.has_attribute("Weight"):
            return target_address

    def __str__(self):
        return "Data Reference Graph"
```

Note: This is a direct translation of the Java code into Python. The `AttributedVertex` and `ProgramGraphType` classes are assumed to be defined elsewhere in your program, as they do not have equivalent definitions here.