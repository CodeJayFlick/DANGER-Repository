Here is the translation of the Java code to Python:

```Python
class Cell:
    def __init__(self):
        self.candy = None
        self.position_x = 0
        self.position_y = 0

    def crush(self, pool, cell_matrix):
        # take out from this position and put back in pool
        pool.add_new_cell(self)
        self.fill_this_space(pool, cell_matrix)

    def fill_this_space(self, pool, cell_matrix):
        for y in range(self.position_y - 1, -1, -1):
            cell_matrix[y][self.position_x] = cell_matrix[y-1][self.position_x]
            cell_matrix[y][self.position_x].position_y = y
        new_c = pool.get_new_cell()
        cell_matrix[0][self.position_x] = new_c
        cell_matrix[0][self.position_x].position_x = self.position_x
        cell_matrix[0][self.position_x].position_y = 0

    def handle_crush(self, c, pool, cell_matrix):
        if self.position_y >= c.position_y:
            self.crush(pool, cell_matrix)
            c.crush(pool, cell_matrix)
        else:
            c.crush(pool, cell_matrix)
            self.crush(pool, cell_matrix)

    def interact(self, c, pool, cell_matrix):
        if (self.candy.type == 'REWARD_FRUIT' or c.candy.type == 'REWARD_FRUIT'):
            return 0
        elif self.candy.name == c.candy.name:
            points_won = self.candy.points + c.candy.points
            handle_crush(c, pool, cell_matrix)
            return points_won
        else:
            return 0

class CellPool:
    def __init__(self):
        pass

    def add_new_cell(self, cell):
        pass

    def get_new_cell(self):
        pass
```

Note that I've made some assumptions about the `Candy` class and its methods (`get_points`, `name`, etc.) as well as the `CellPool` class. You'll need to define these classes yourself based on your specific requirements.

Also, Python is a dynamically-typed language, so you don't need to specify types for variables like Java does with `int positionX;`.