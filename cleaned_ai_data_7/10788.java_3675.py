class VertexTooltipProvider:
    def __init__(self):
        pass

    def get_tooltip(self, v):
        """Returns a tooltip component for the given vertex"""
        # TO DO: implement this method in your subclass
        raise NotImplementedError("Subclasses must implement this method")

    def get_tooltip(self, v, e):
        """Returns a tooltip component for the given vertex and edge"""
        # TO DO: implement this method in your subclass
        raise NotImplementedError("Subclasses must implement this method")

    def get_tooltip_text(self, v, e):
        """Returns a tooltip string for the given vertex and mouse event"""
        # TO DO: implement this method in your subclass
        raise NotImplementedError("Subclasses must implement this method")
