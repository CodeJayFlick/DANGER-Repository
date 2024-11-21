class FGEdgePaintTransformer:
    def __init__(self, options):
        self.options = options

    def apply(self, e):
        flow_type = e.get_flow_type()
        color = self.options.get_color(flow_type)
        return color
