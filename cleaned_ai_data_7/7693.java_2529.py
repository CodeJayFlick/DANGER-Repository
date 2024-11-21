import set

class FcgEmphasizeEdgesJob:
    def __init__(self, viewer: 'GraphViewer', edges: set):
        self.edges = edges
        super().__init__(viewer, True)

    def update_opacity(self, percent_complete: float) -> None:
        remaining = 1 - percent_complete if percent_complete > 0.5 else percent_complete

        for edge in self.edges:
            edge.set_emphasis(remaining * 10)
