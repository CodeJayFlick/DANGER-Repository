class FcgView:
    def __init__(self, options):
        self.options = options

    def install_graph_viewer(self):
        component = self.create_graph_component()
        component.set_graph_options(self.options)
        self.graph_component = component

    def create_graph_component(self):
        return FcgComponent(self.visual_graph)

    @property
    def graph_component(self):
        return super().get_graph_component()

class VisualGraphOptions:
    pass

class FunctionCallGraphPlugin:
    pass

class FcgVertex:
    pass

class FcgEdge:
    pass

class FcgComponent:
    def __init__(self, visual_graph):
        self.visual_graph = visual_graph

    def set_graph_options(self, options):
        pass
