Here is the translation of the Java code to Python:

```Python
class CellTest:
    def test_interact(self):
        c1 = Candy("green jelly", "jelly", 0, 5)
        c2 = Candy("green apple", "apple", 1, 10)
        matrix = [[Cell(c) for _ in range(4)] for _ in range(4)]
        matrix[0][0] = Cell(c1, 0, 0)
        matrix[0][1] = Cell(c1, 1, 0)
        matrix[0][2] = Cell(c2, 2, 0)
        matrix[0][3] = Cell(c1, 3, 0)
        cp = CellPool(5)
        points1 = matrix[0][0].interact(matrix[0][1], cp, matrix)
        points2 = matrix[0][2].interact(matrix[0][3], cp, matrix)
        self.assertTrue(points1 > 0 and points2 == 0)

    def test_crush(self):
        c1 = Candy("green jelly", "jelly", 0, 5)
        c2 = Candy("purple candy", "candy", 0, 5)
        matrix = [[Cell(c) for _ in range(4)] for _ in range(4)]
        matrix[0][0] = Cell(c1, 0, 0)
        matrix[1][0] = Cell(c2, 0, 1)
        cp = CellPool(5)
        matrix[1][0].crush(cp, matrix)
        self.assertEqual("green jelly", str(matrix[1][0].candy))

class Candy:
    def __init__(self, name, type_name, candy_type, points):
        self.name = name
        self.type_name = type_name
        self.candy_type = candy_type
        self.points = points

class CellPool:
    def __init__(self, size):
        self.size = size

class Cell:
    def __init__(self, candy, x, y):
        self.candy = candy
        self.x = x
        self.y = y

    def interact(self, other_cell, cell_pool, matrix):
        # implement the logic for interacting with another cell here
        pass

    def crush(self, cell_pool, matrix):
        # implement the logic for crushing a cell here
        pass
```

Note that I've assumed some of the Java code to be equivalent Python syntax. For example, `var` is not needed in Python and can be replaced with simply assigning values to variables. Also, there are no explicit imports required as they would have been imported implicitly by Python's dynamic typing system.