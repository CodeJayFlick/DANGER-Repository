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
