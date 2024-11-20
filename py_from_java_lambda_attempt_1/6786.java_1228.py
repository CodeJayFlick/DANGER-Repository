Here is the translation of the given Java code into Python:

```Python
import ghidra

class GraphAST:
    def __init__(self):
        self.SHAPE_ATTRIBUTE = "Shape"
        self.DEFAULT = "Default"
        self.CONSTANT = "Constant"
        self.REGISTER = "Register"
        self.UNIQUE = "Unique"
        self.PERSISTENT = "Persistent"
        self.ADDRESS_TIED = "Address Tied"
        self.OP = "Op"

    def run(self):
        tool = state.get_tool()
        if not tool:
            print("Script is not running in GUI")
        graph_display_broker = tool.getService(graph_display.ghidra.GraphDisplayBroker)
        if not graph_display_broker:
            msg.show_error(self, tool.get_tool_frame(), "GraphAST Error", 
                           "No graph display providers found: Please add a graph display provider to your tool")
            return

        func = self.get_function_containing(current_address)
        if not func:
            msg.show_warn(self, state.get_tool().get_tool_frame(), "GraphAST Error",
                          "No Function at current location")
            return

        self.build_ast()

        graph_type = GraphTypeBuilder("AST").vertex_type(self.DEFAULT).vertex_type(self.CONSTANT) \
                     .vertex_type(self.REGISTER).vertex_type(self.UNIQUE).vertex_type(self.PERSISTENT) \
                     .vertex_type(self.ADDRESS_TIED).vertex_type(self.OP).edge_type(self.DEFAULT) \
                     .edge_type(self.WITHIN_BLOCK).edge_type(self.BETWEEN_BLOCK).build()

        display_options = GraphDisplayOptionsBuilder(graph_type).vertex_selection_color(WebColors.DEEP_PINK) \
                           .edge_selection_color(WebColors.DEEP_PINK).default_vertex_color(WebColors.RED) \
                           .default_edge_color(WebColors.NAVY).default_vertex_shape(VertexShape.ELLIPSE) \
                           .default_layout_algorithm("Hierarchical MinCross Coffman Graham").use_icons(False) \
                           .arrow_length(15).label_position(GraphLabelPosition.SOUTH) \
                           .shape_override_attribute(self.SHAPE_ATTRIBUTE)

        graph = AttributedGraph("AST Graph", graph_type)
        self.build_graph()

        display = graph_display_broker.get_default_graph_display(False, monitor)
        description = "AST Data Flow Graph For " + func.name
        display.set_graph(graph, display_options, description, False, monitor)

    def build_ast(self):
        ifc = DecompInterface()
        options = DecompileOptions()
        if not ifc.open_program(current_program):
            raise DecompileException("Decompiler", 
                                      "Unable to initialize: " + ifc.get_last_message())
        ifc.set_simplification_style("normalize")
        res = ifc.decompile_function(func, 30, None)
        self.high = res.get_high_function()

    def get_varnode_key(self, vn):
        op = vn.get_def()
        id = ""
        if op:
            id += str(op.get_seqnum().get_target()) + " v " + str(vn.get_unique_id())
        else:
            id += "i v " + str(vn.get_unique_id())
        return id

    def get_op_key(self, op):
        sq = op.get_seqnum()
        id = str(sq.get_target()) + " o " + str(op.get_seqnum().get_time())
        return id

    def create_varnode_vertex(self, vn):
        name = str(vn.get_address())
        id = self.get_varnode_key(vn)
        vertex_type = self.DEFAULT
        if vn.is_constant():
            vertex_type = self.CONSTANT
        elif vn.is_register():
            vertex_type = self.REGISTER
            reg = func.program().get_register(vn.get_address(), vn.get_size())
            if reg:
                name = reg.name
        else:
            pass

        vert = graph.add_vertex(id, name)
        vert.set_vertex_type(vertex_type)

    def create_op_vertex(self, op):
        name = str(op.mnemonic)
        id = self.get_op_key(op)
        opcode = op.get_opcode()
        if (opcode == PcodeOp.LOAD or opcode == PcodeOp.STORE) and i == 0:
            continue
        elif opcode == PcodeOp.INDIRECT and i == 1:
            continue

        vn = op.input(i)
        if vn:
            v = self.get_varnode_vertex(vertices, vn)
            create_edge(v, vert)

    def get_varnode_vertex(self, vertices, vn):
        res = vertices.get(vn.unique_id())
        if not res:
            res = self.create_varnode_vertex(vn)
            vertices.put(vn.unique_id(), res)
        return res

    def build_graph(self):
        vertices = {}
        op_iter = high.pcode_ops()
        while op_iter.has_next():
            op = op_iter.next()
            vert = self.create_op_vertex(op)

            for i in range(len(op.inputs)):
                opcode = op.get_opcode()
                if (i == 0 and (opcode == PcodeOp.LOAD or opcode == PcodeOp.STORE)) or \
                   (i == 1 and opcode == PcodeOp.INDIRECT):
                    continue

                vn = op.input(i)
                if vn:
                    v = self.get_varnode_vertex(vertices, vn)
                    create_edge(v, vert)

            outvn = op.output()
            if outvn:
                outv = self.get_varnode_vertex(vertices, outvn)
                if outv:
                    create_edge(vert, outv)