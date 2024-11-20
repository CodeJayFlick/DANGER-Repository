Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractFGLayout:
    def __init__(self, graph: 'FunctionGraph', layout_name: str):
        self.function = graph.get_function()
        self.options = graph.get_options()

    @abstractmethod
    def create_cloned_fg_layout(self, new_graph: 'FunctionGraph') -> 'AbstractVisualGraphLayout':
        pass

    def get_visual_graph(self) -> 'FunctionGraph':
        return self.graph

    def create_cloned_layout(self, new_graph: 'VisualGraph') -> 'AbstractFGLayout':
        return self.create_cloned_fg_layout(new_graph)

    def clone_layout(self, new_graph: 'VisualGraph') -> 'FGLayout':
        clone = super().clone_layout(new_graph)
        return AbstractFGLayout(clone.get_function(), clone.get_options())

    @property
    def is_condensed_layout(self) -> bool:
        return self.options.use_condensed_layout()

    def get_edge_renderer(self) -> 'BasicEdgeRenderer':
        return FGEdgeRenderer()
```

Note that Python does not have direct support for abstract classes or methods like Java. However, we can achieve similar functionality using the `@abstractmethod` decorator and inheritance in Python.

Also note that Python's type hinting is used to indicate the expected types of variables, function parameters, etc., but it is not enforced at runtime (unlike some other languages).