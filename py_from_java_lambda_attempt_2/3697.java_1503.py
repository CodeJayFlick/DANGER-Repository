Here is the translation of the given Java code into equivalent Python:

```Python
class TypeGraphTask:
    def __init__(self, type: 'DataType', graph_service):
        self.type = type
        if isinstance(type, TypeDef):
            self.type = type.get_base_data_type()
        self.graph_title = f"Graph of Type: {type.name}"
        self.graph_service = graph_service

class GraphType:
    def __init__(self, name):
        self.edge_types = [REFERENCE, COMPOSITE]

class AttributedVertex:
    def __init__(self, name):
        self.name = name
        self.description = ToolTipUtils.get_tooltip_text(self.type)

class AttributedEdge:
    pass

class GraphDisplayOptions:
    def __init__(self, graph_type: 'GraphType'):
        self.default_vertex_color = Color.BLUE
        self.edge_colors = {COMPOSITE: Color.MAGENTA, REFERENCE: Color.BLUE}

class AttributedGraph:
    def __init__(self, title, graph_type):
        self.title = title
        self.graph_type = graph_type

def recurse_composite(struct: 'Composite', graph: 'AttributedGraph', last_vertex=None, edge_type=COMPOSITE, monitor=None) -> None:
    new_vertex = AttributedVertex(struct.name)
    new_vertex.description = ToolTipUtils.get_tooltip_text(struct)

    if not last_vertex:
        graph.add_vertex(new_vertex)
    else:
        edge = graph.add_edge(last_vertex, new_vertex)
        edge.set_edge_type(edge_type)

def recurse_pointer(pointer: 'Pointer', graph: 'AttributedGraph', last_vertex=None, monitor=None) -> None:
    ptr_type = pointer.get_data_type()
    if not ptr_type:
        return

    if isinstance(ptr_type, TypeDef):
        ptr_type = ptr_type.get_base_data_type()

    if isinstance(ptr_type, Pointer):
        recurse_pointer(ptr_type, graph, last_vertex, monitor)
    elif isinstance(ptr_type, Composite):
        recurse_composite(ptr_type, graph, last_vertex, REFERENCE, monitor)

def run(self) -> None:
    graph_type = GraphType("Data Graph")
    edge_types = [REFERENCE, COMPOSITE]
    for et in edge_types:
        graph_type.edge_type(et)
    
    options = GraphDisplayOptions(graph_type)
    default_color = Color.BLUE
    colors = {COMPOSITE: Color.MAGENTA, REFERENCE: Color.BLUE}

    if isinstance(self.type, Pointer):
        recurse_pointer(self.type, AttributedGraph(self.graph_title, graph_type), None, self.monitor)
    elif isinstance(self.type, Composite):
        recurse_composite(self.type, AttributedGraph(self.graph_title, graph_type), None, self.monitor)

    try:
        display = self.graph_service.get_graph_display(False, self.monitor)
        display.set_graph(AttributedGraph(self.graph_title, graph_type), options, self.graph_title, False, self.monitor)
    except GraphException as e:
        Msg.show_error(self, None, "Data Type Graph Error", f"Unexpected error while graphing: {e.message}", e)

```

Please note that Python does not have direct equivalent of Java's `Task` and `TaskMonitor`. The code above assumes you will implement these yourself.