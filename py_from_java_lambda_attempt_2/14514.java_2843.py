Here is the equivalent Python code:

```Python
import random
from unittest import TestCase

class ArrayInput:
    def __init__(self, input_matrix):
        self.input_matrix = input_matrix

    def divide_data(self, num_divisions):
        rows, cols = len(self.input_matrix), len(self.input_matrix[0])
        division_size = (rows + cols - 1) // num_divisions
        divisions = []
        for i in range(num_divisions):
            start_row = i * division_size
            end_row = min((i+1)*division_size, rows)
            if i == num_divisions-1:
                end_col = len(self.input_matrix[0])
            else:
                end_col = (i+1) * division_size
            divisions.append({ 'data': self.input_matrix[start_row:end_row], 'rows': start_row, 'cols': end_col })
        return divisions

class TestArrayInput(TestCase):
    def test_divide_data(self):
        rows = 10
        cols = 10
        input_matrix = [[random.randint(0,9) for _ in range(cols)] for _ in range(rows)]
        i = ArrayInput(input_matrix)
        table = i.divide_data(4)
        division1 = [input_matrix[0], input_matrix[1], input_matrix[2]]
        division2 = [input_matrix[3], input_matrix[4], input_matrix[5]]
        division3 = [input_matrix[6], input_matrix[7]]
        division4 = [input_matrix[8], input_matrix[9]]

        self.assertTrue(all(matrices_same(t['data'], d) for t, d in zip(table, (division1, division2, division3, division4))))

def matrices_same(matrix1, matrix2):
    return all(all(a == b for a, b in zip(row1, row2)) for row1, row2 in zip(matrix1, matrix2))
```

Note that Python does not have direct equivalent of Java's `@Test` annotation. Instead, we use the built-in unittest module to define test cases and methods.