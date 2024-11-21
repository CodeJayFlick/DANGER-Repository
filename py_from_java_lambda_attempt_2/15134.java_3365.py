Here is the translation of the Java code to Python:

```Python
class CandyGameTest:
    def test_adjacent_cells(self):
        cg = CandyGame(3, CellPool(9))
        arr1 = cg.adjacent_cells((0, 0))
        arr2 = cg.adjacent_cells((1, 2))
        arr3 = cg.adjacent_cells((1, 1))
        self.assertTrue(len(arr1) == 2 and len(arr2) == 3 and len(arr3) == 4)

    def test_continue_round(self):
        matrix = [[None for _ in range(2)] for _ in range(2)]
        c1 = Candy("green jelly", "jelly", Type.CRUSHABLE_CANDY, 5)
        c2 = Candy("purple jelly", "jelly", Type.CRUSHABLE_CANDY, 5)
        c3 = Candy("green apple", "apple", Type.REWARD_FRUIT, 10)
        matrix[0][0] = Cell(c1, 0, 0)
        matrix[0][1] = Cell(c2, 1, 0)
        matrix[1][0] = Cell(c3, 0, 1)
        matrix[1][1] = Cell(c2, 1, 1)
        p = CellPool(4)
        cg = CandyGame(2, p)
        cg.cells = matrix
        fruit_in_last_row = cg.continue_round()
        matrix[1][0].crush(p, matrix)
        matrix[0][0] = Cell(c3, 0, 0)
        matching_candy = cg.continue_round()
        matrix[0][1].crush(p, matrix)
        matrix[0][1] = Cell(c3, 1, 0)
        none_left = cg.continue_round()
        self.assertTrue(fruit_in_last_row and matching_candy and not none_left)

class Candy:
    def __init__(self, name, type_name, candy_type, points):
        self.name = name
        self.type_name = type_name
        self.candy_type = candy_type
        self.points = points

class CellPool:
    def __init__(self, size):
        self.size = size

class CandyGame:
    def __init__(self, rows, cell_pool):
        self.rows = rows
        self.cell_pool = cell_pool
        self.cells = [[None for _ in range(rows)] for _ in range(rows)]

    def adjacent_cells(self, position):
        row, col = position
        result = []
        if 0 <= row - 1 < self.rows and 0 <= col - 1 < self.rows:
            result.append((row-1, col-1))
        if 0 <= row + 1 < self.rows and 0 <= col - 1 < self.rows:
            result.append((row+1, col-1))
        if 0 <= row - 1 < self.rows and 0 <= col + 1 < self.rows:
            result.append((row-1, col+1))
        if 0 <= row + 1 < self.rows and 0 <= col + 1 < self.rows:
            result.append((row+1, col+1))
        for i in range(self.rows):
            if (i == row - 1 or i == row or i == row + 1) and 0 <= col - 1 < self.rows:
                result.append((i, col-1))
            if (i == row - 1 or i == row or i == row + 1) and 0 <= col + 1 < self.rows:
                result.append((i, col+1))
        return [self.cells[i][j] for i, j in set(result)]

    def continue_round(self):
        # implementation of the method
        pass

class Cell:
    def __init__(self, candy, row, column):
        self.candy = candy
        self.row = row
        self.column = column

    def crush(self, cell_pool, matrix):
        # implementation of the method
        pass

class Type:
    CRUSHABLE_CANDY = 1
    REWARD_FRUIT = 2
```

Note that I've replaced Java's `package` declaration with Python's module structure. Also, some methods in the original code (like `CandyGame.continue_round()` and `Cell.crush()`) are not implemented here as they were not provided in the given Java code.