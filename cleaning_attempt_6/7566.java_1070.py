class DNLayoutOptions:
    HELP_ANCHOR = DecompilerNestedLayoutProvider.LAYOUT_NAME + "_Options"
    USE_EDGE_ROUTING_AROUND_VERTICES_KEY = "Route Edges Around Vertices"
    USE_EDGE_ROUTING_AROUND_VERTICES_DESCRIPTION = f"Signals that edges should be routed around any intersecting vertex. When toggled off, edges will pass through any intersecting vertices."
    
    DIM_RETURN_EDGES_KEY = "Use Dim Return Edges"
    DIM_RETURN_EDGES_DESCRIPTION = f"Signals to lighten the default return edges."

    def __init__(self):
        self.use_edge_routing_around_vertices = False
        self.use_dimmed_return_edges = True

    def register_options(self, options):
        help_location = HelpLocation(OWNER, self.HELP_ANCHOR)

        options.register_option(self.USE_EDGE_ROUTING_AROUND_VERTICES_KEY,
                                 self.use_edge_routing_around_vertices,
                                 help_location,
                                 self.USE_EDGE_ROUTING_AROUND_VERTICES_DESCRIPTION)
        
        options.register_option(self.DIM_RETURN_EDGES_KEY,
                                 self.use_dimmed_return_edges,
                                 help_location,
                                 self.DIM_RETURN_EDGES_DESCRIPTION)

    def load_options(self, options):
        self.use_edge_routing_around_vertices = options.get_boolean(
            self.USE_EDGE_ROUTING_AROUND_VERTICES_KEY, 
            self.use_edge_routing_around_vertices
        )
        
        self.use_dimmed_return_edges = options.get_boolean(
            self.DIM_RETURN_EDGES_KEY,
            self.use_dimmed_return_edges
        )

    def use_edge_routing_around_vertices(self):
        return self.use_edge_routing_around_vertices

    def use_dimmed_return_edges(self):
        return self.use_dimmed_return_edges

    def option_change_requires_relayout(self, option_name):
        # format: 'Nested Code Layout.Route Edges....'
        return option_name.endswith(self.USE_EDGE_ROUTING_AROUND_VERTICES_KEY) or \
               option_name.endswith(self.DIM_RETURN_EDGES_KEY)
