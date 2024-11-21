class ToolTipInfo[T]:
    def __init__(self, event: object, graph_object: T) -> None:
        self.event = event
        self.graph_object = graph_object
        self.tooltip_component = self.create_tooltip_component()

    @abstractmethod
    def create_tooltip_component(self) -> JComponent:
        pass

    @abstractmethod
    def emphasize(self) -> None:
        pass

    @abstractmethod
    def de_emphasize(self) -> None:
        pass

    def get_mouse_event(self) -> object:
        return self.event

    def get_tooltip_component(self) -> object:
        return self.tooltip_component


class JComponent:  # equivalent to Java's javax.swing.JComponent
    pass
