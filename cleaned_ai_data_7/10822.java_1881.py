class JungLayout(VVisualVertex, EVisualEdge):
    def __init__(self, jung_layout: Layout[V, E]):
        super().__init__(jung_layout)

    def clone_jung_layout(self, new_graph: VisualGraph[V, E]) -> Layout[V, E]:
        return super().clone_jung_layout(new_graph).map(lambda x: JungLayout(x))

    def get_jung_layout(self) -> Layout[None, None]:
        return self.delegate
