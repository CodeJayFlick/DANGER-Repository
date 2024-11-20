Here is the translation of the Java code to Python:
```python
import collections
from typing import List, Dict, Tuple

class GridLocationMap:
    def __init__(self):
        self.row_col_factory = lambda: (0, 0)
        self.vertex_points = {}
        self.edge_points = {}

    @property
    def vertices(self) -> set:
        return set(self.vertex_points.keys())

    @property
    def edges(self) -> set:
        return set(self.edge_points.keys())

    def set_articulations(self, edge: object, articulations: List[Tuple[int, int]]) -> None:
        self.edge_points[edge] = articulations

    def get_articulations(self, edge: object) -> List[Tuple[int, int]]:
        list_ = self.edge_points.get(edge)
        if list_ is None:
            return []
        return list_

    def row(self, vertex: object, row: int) -> None:
        point = self.vertex_points[vertex]
        point[1] = row

    def col(self, vertex: object, column: int) -> None:
        point = self.vertex_points[vertex]
        point[0] = column

    def set(self, v: object, row: int, column: int) -> None:
        point = self.vertex_points[v]
        point[0] = column
        point[1] = row

    def get_row_index(self, vertex: object) -> int:
        return self.vertex_points[vertex][1]

    def get_column_index(self, vertex: object) -> int:
        return self.vertex_points[vertex][0]

    def rows(self) -> List['Row']:
        rows_by_index = {}
        for entry in self.vertex_points.items():
            v, point = entry
            row_index = point[1]
            row = self.get_row(row_index)
            if row is None:
                row = Row(row_index)
                rows_by_index[row_index] = row
            row.set_column(v, point[0])
        return list(rows_by_index.values())

    def center_rows(self) -> None:
        rows = self.rows()
        max_col = 0
        for row in rows:
            start = row.get_start_column()
            offset = -start
            updated_row = Row(row.index)
            for v, col in zip(row.vertices(), range(start, start + len(row))):
                new_col = col + offset
                self.set(v, row.index, new_col)
                updated_row.set_column(v, new_col)
        return

    def copy(self) -> 'GridLocationMap':
        map_ = GridLocationMap()
        for v, point in self.vertex_points.items():
            map_.vertex_points[v] = (point[0], point[1])
        for edge, points in self.edge_points.items():
            map_.edge_points[edge] = [list(p) for p in points]
        return map_

    def dispose(self) -> None:
        self.vertex_points.clear()
        self.edge_points.clear()

class Row:
    def __init__(self, index: int):
        self.index = index
        self.vertices = []
        self.start_column = 0

    @property
    def start_column(self) -> int:
        return self._start_column

    @start_column.setter
    def set_start_column(self, value: int) -> None:
        self._start_column = value

    @property
    def end_column(self) -> int:
        return len(self.vertices)

    def get_vertices(self) -> List[object]:
        return self.vertices[:]

    def set_column(self, v: object, column: int) -> None:
        if not hasattr(v, 'index'):
            raise ValueError(f"v must have an index attribute")
        for i in range(len(self)):
            if self[i] == v and self[i].column != column:
                self[i].set_index(column)
        return

    def __len__(self) -> int:
        return len(self.vertices)

def zero_align_grid(grid: GridLocationMap) -> None:
    smallest_column_index = 0
    smallest_row_index = 0
    rows = grid.rows()
    for row in rows:
        smallest_row_index = min(smallest_row_index, row.index)
        smallest_column_index = min(smallest_column_index, row.get_start_column())
    global_column_offset = -smallest_column_index
    global_row_offset = -smallest_row_index

    for row in rows:
        vertices = row.get_vertices()
        for v in vertices:
            old_col = grid.col(v)
            old_row = grid.row(v)
            new_col = global_column_offset + old_col
            new_row = global_row_offset + old_row
            grid.set(v, new_row, new_col)

    return

class Point:
    def __init__(self):
        self.x = 0
        self.y = 0

def main():
    # Example usage
    grid_map = GridLocationMap()
    vertex1 = object()  # Replace with your actual vertices
    vertex2 = object()  # Replace with your actual vertices
    edge1 = object()  # Replace with your actual edges
    edge2 = object()  # Replace with your actual edges

    grid_map.set_articulations(edge1, [(0, 0), (1, 1)])
    grid_map.set_articulations(edge2, [(0, 0)])

    grid_map.row(vertex1, 0)
    grid_map.col(vertex1, 0)

    print(grid_map.rows())

if __name__ == "__main__":
    main()
```
Note that I've replaced the Java-specific types (e.g. `Point`, `Row`) with Python's built-in types (`list` of `int`s for points and a custom class `Row`). Additionally, some methods have been modified to work with Python's dynamic typing system.

Also note that this code assumes you're using Python 3.x, as the type hints are specific to Python 3.5+. If you need to use an earlier version of Python, please let me know and I can modify the code accordingly.