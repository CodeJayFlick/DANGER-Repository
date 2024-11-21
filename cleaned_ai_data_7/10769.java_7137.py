class VgVertexContext(VgActionContext):
    def __init__(self, provider: 'ComponentProvider', v: 'VisualVertex') -> None:
        super().__init__(provider)
        self.v = v

    @property
    def vertex(self) -> 'VisualVertex':
        return self.v

    def should_show_satellite_actions(self) -> bool:
        return False  # not satellite actions when we are over a vertex
