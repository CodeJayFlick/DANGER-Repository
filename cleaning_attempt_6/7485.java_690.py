class FGPrimaryViewer:
    def __init__(self, graph_component: 'FGComponent', layout: 'VisualGraphLayout[FGVertex, FGEdge]', size):
        super().__init__(layout, size)
        
        self.set_vertex_tooltip_provider(FGVertexTooltipProvider())

    @property
    def view_updater(self) -> 'FGViewUpdater':
        return FGViewUpdater(self, self.visual_graph)

    def create_path_highlighter(self, listener: 'PathHighlightListener') -> 'VisualGraphPathHighlighter[FGVertex, FGEdge]':
        return VisualGraphPathHighlighter(self.visual_graph, listener)
        
class VisualGraphPathHighlighter:
    def __init__(self, graph: 'GDirectedGraph', listener):
        self.graph = graph
        self.listener = listener

    @property
    def dominance_graph(self) -> 'GDirectedGraph':
        if not self.dominance_sinks or not self.dominance_sources:
            return self.graph
        
        function_graph = FunctionGraph()
        
        for source in self.dominance_sinks:
            dummy_edges = function_graph.create_dummy_sources()
            
            modified_graph = MutableGDirectedGraphWrapper(self.graph)
            for edge in dummy_edges:
                modified_graph.add_edge(edge)

            return modified_graph

    @property
    def dominance_sinks(self) -> 'Set[FGVertex]':
        if self.forward:
            return GraphAlgorithms.get_sinks(self.graph)
        else:
            return set()

    @property
    def forward(self):
        pass  # Not implemented in the original code, but included here for completeness

class FGViewUpdater:
    def __init__(self, viewer: 'FGPrimaryViewer', graph: 'GDirectedGraph'):
        self.viewer = viewer
        self.graph = graph
