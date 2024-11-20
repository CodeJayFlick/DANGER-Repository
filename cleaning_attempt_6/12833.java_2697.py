class DummyGraphDisplayListener:
    def graph_closed(self):
        # I'm a dummy
        pass

    def clone_with(self, graph_display: 'GraphDisplay') -> 'DummyGraphDisplayListener':
        return self.__class__()

    def selection_changed(self, vertices: set) -> None:
        # I'm a dummy
        pass

    def location_focus_changed(self, vertex: object) -> None:
        # I'm a dummy
        pass

    def dispose(self) -> None:
        # I'm a dummy
        pass
