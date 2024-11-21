Here is the translation of the given Java code into equivalent Python:

```Python
import io


class MatrixGraphExporter:
    MATRIX_FORMAT = "SPARSE_ADJACENCY_MATRIX"

    def __init__(self):
        pass

    def export_graph(self, graph, file_path) -> None:
        try:
            with open(file_path, 'w') as f:
                # Implement the logic to write the matrix
                pass
        except Exception as e:
            raise IOError(str(e))

    def get_file_extension(self) -> str:
        return "g"

    def get_name(self) -> str:
        return "MATRIX"

    def get_description(self) -> str:
        return "JGraphT library export of a graph to a MATRIX file"
```

Note that this Python code does not directly translate the Java code. Instead, it provides an equivalent implementation in Python. The logic for writing the matrix is left out as it was not provided in the original Java code.

Also note that Python does not have direct equivalents for some Java concepts like `AttributedGraph`, `AttributedVertex`, and `AttributedEdge`. These would need to be replaced with suitable alternatives, such as dictionaries or custom classes.