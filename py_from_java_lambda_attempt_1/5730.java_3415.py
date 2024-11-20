Here is the translation of the given Java code into equivalent Python:

```Python
class ProgramGraphDisplayOptions:
    def __init__(self, graph_type):
        self.graph_type = graph_type

    def initialize_defaults(self):
        self.default_vertex_shape = 'ELLIPSE'
        self.default_vertex_color = (255, 0, 0)  # Red
        self.default_edge_color = (255, 0, 0)  # Red
        self.favored_edge_type = 'FALL_THROUGH'

        vertex_types = {
            'BODY': {'shape': 'RECTANGLE', 'color': (0, 0, 255)},  # Blue
            'ENTRY': {'shape': 'TRIANGLE_DOWN', 'color': (205, 102, 50)},  # Dark Orange
            'EXIT': {'shape': 'TRIANGLE_UP', 'color': (139, 0, 139)},  # Magenta
            'SWITCH': {'shape': 'DIAMOND', 'color': (34, 139, 34)},  # Cyan
            'EXTERNAL': {'shape': 'RECTANGLE', 'color': (34, 139, 34)},  # Green
            'BAD': {'shape': 'ELLIPSE', 'color': (255, 0, 0)},  # Red
            'DATA': {'shape': 'ELLIPSE', 'color': (255, 192, 203)},  # Pink
            'ENTRY_NEXUS': {'shape': 'ELLIPSE', 'color': (245, 222, 179)},  # Wheat
            'INSTRUCTION': {'shape': 'HEXAGON', 'color': (0, 0, 255)},  # Blue
            'STACK': {'shape': 'RECTANGLE', 'color': (34, 139, 34)}  # Green
        }

        edge_types = {
            'ENTRY_EDGE': (128, 128, 128),  # Gray
            'FALL_THROUGH': (0, 0, 255),  # Blue
            'UNCONDITIONAL_JUMP': (34, 139, 34),  # Green
            'UNCONDITIONAL_CALL': (205, 102, 50),  # Orange
            'TERMINATOR': (139, 0, 139),  # Magenta
            'JUMP_TERMINATOR': (139, 0, 139),  # Magenta
            'INDIRECTION': (255, 192, 203),  # Pink

            'CONDITIONAL_JUMP': (205, 102, 50),  # Orange
            'CONDITIONAL_CALL': (205, 102, 50),  # Orange
            'CONDITIONAL_TERMINATOR': (139, 0, 139),  # Magenta
            'CONDITIONAL_CALL_TERMINATOR': (139, 0, 139),  # Magenta

            'COMPUTED_JUMP': (34, 139, 34),  # Cyan
            'COMPUTED_CALL': (34, 139, 34),  # Cyan
            'COMPUTED_CALL_TERMINATOR': (139, 0, 139),  # Magenta

            'CONDITIONAL_COMPUTED_CALL': (34, 139, 34),  # Cyan
            'CONDITIONal COMPUTED_JUMP': (34, 139, 34),  # Cyan

            'CALL_OVERRIDE_UNCONDITIONAL': (255, 0, 0),  # Red
            'JUMP_OVERRIDE_UNCONDITIONAL': (255, 0, 0),  # Red
            'CALLOTHER OVERRIDE_CALL': (255, 0, 0),  # Red
            'CALLOTHER_OVERRIDE_JUMP': (255, 0, 0),  # Red

            'READ': (34, 139, 34),  # Green
            'WRITE': (255, 0, 0),  # Red
            'READ_WRITE': (205, 102, 50),  # Orange
            'UNKNOWN_DATA': (0, 0, 0),  # Black
            'EXTERNAL_REF': (139, 0, 139),  # Magenta

            'READ_INDIRECT': (34, 139, 34),  # Green
            'WRITE_INDIRECT': (255, 0, 0),  # Red
            'READ_WRITE_INDIRECT': (205, 102, 50),  # Orange
            'DATA INDIRECT': (205, 102, 50),  # Orange

            'PARAM': (34, 139, 34),  # Cyan
            'THUNK': (0, 0, 255)  # Blue
        }

        for vertex_type, settings in vertex_types.items():
            self.configure_vertex_type(vertex_type, settings['shape'], tuple(settings['color']))

        for edge_type, color in edge_types.items():
            self.configure_edge_type(edge_type, color)

    def configure_vertex_type(self, type_name, shape, color):
        pass

    def configure_edge_type(self, edge_type, color):
        pass
```

Please note that this is a direct translation of the given Java code into equivalent Python. However, some parts like `configure_vertex_type` and `configure_edge_type` are not implemented as they were in the original Java code.