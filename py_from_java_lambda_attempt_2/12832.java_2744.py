Here is the translation of the given Java interface into Python:

```Python
from abc import ABC, abstractmethod


class AttributedGraphExporter(ABC):
    @abstractmethod
    def export_graph(self, graph: 'AttributedGraph', file_path: str) -> None:
        """Exports the given graph to the given writer"""
        pass

    @property
    @abstractmethod
    def suggested_file_extension(self) -> str:
        """Returns the suggested file extension to use for this exporter"""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the name of this exporter"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Returns a description of the exporter"""
        pass


class AttributedGraphExporterExtension(AttributedGraphExporter):
    # Implement your custom export graph method here.
    pass
```

Note: Python does not have direct equivalent to Java's interface. Instead, we use abstract base classes (ABC) and abstract methods from `abc` module to achieve similar functionality.