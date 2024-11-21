Here is the translation of the Java code to Python:
```
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
```
Note that I've used the `object` type for variables like `event` and `tooltip_component`, since Python doesn't have a built-in concept of generics like Java does. Additionally, I've defined an abstract base class `JComponent` in Python, which is equivalent to the Java class.

Also note that this translation assumes you're using Python 3.x; if you're using Python 2.x, some syntax may be different (e.g., no type hints).