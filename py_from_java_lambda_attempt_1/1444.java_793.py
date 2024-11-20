Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from collections import defaultdict, OrderedDict

class GdbTable:
    def __init__(self):
        self.columns = {}
        self.rows = []

    def add_column(self, name, header):
        if not self.columns.get(name):
            self.columns[name] = []
        self.columns[name].append(header)

    def add_row(self, row):
        self.rows.append(row)


class GdbTableTest(unittest.TestCase):

    def test_build_gdb_table(self):
        table = build_test_table()
        return

    def test_columns(self):
        table = build_test_table()
        self.assertEqual(len(table.columns), 2)
        expected_column_names = {"First Column", "Second Column"}
        self.assertEqual(set(table.columns.keys()), expected_column_names)

    def test_row_count(self):
        table = build_test_table()
        self.assertEqual(len(table.rows), 3)
        for row in table.rows:
            self.assertIsNotNone(row)
        with self.assertRaises(IndexError):
            table.rows[3]

    def test_row_contents(self):
        table = build_test_table()
        rows = table.rows
        row1, row2, row3 = rows

        self.assertEqual(len(row1), 2)
        expected_column_names = {"First Column", "Second Column"}
        self.assertEqual(set(row1.keys()), expected_column_names)
        self.assertEqual(row1["First Column"], "Col1Row1")
        self.assertEqual(row1["Second Column"], "Col2Row1")

        self.assertEqual(len(row2), 2)
        self.assertEqual(set(row2.keys()), expected_column_names)
        self.assertEqual(row2["First Column"], "Col1Row2")
        self.assertEqual(row2["Second Column"], "Col2Row2")

        self.assertEqual(len(row3), 2)
        self.assertEqual(set(row3.keys()), expected_column_names)
        self.assertEqual(row3["First Column"], "Col1Row3")
        self.assertEqual(row3["Second Column"], "Col2Row3")


    def test_row_iterator(self):
        table = build_test_table()
        copied_rows = []
        for row in table.rows:
            copied_rows.append(dict(row))
        expected_copied_rows = [
            {"First Column": "Col1Row1", "Second Column": "Col2Row1"},
            {"First Column": "Col1Row2", "Second Column": "Col2Row2"},
            {"First Column": "Col1Row3", "Second Column": "Col2Row3"}
        ]
        self.assertEqual(copied_rows, expected_copied_rows)


    def test_column_iterator(self):
        table = build_test_table()
        copied_columns = defaultdict(list)
        for column_name, headers in table.columns.items():
            for header in headers:
                if isinstance(header, str):  # Assuming the header is a string
                    copied_columns[column_name].append(header)

        expected_copied_columns = {
            "First Column": ["Col1Row1", "Col1Row2", "Col1Row3"],
            "Second Column": ["Col2Row1", "Col2Row2", "Col2Row3"]
        }
        self.assertEqual(dict(copied_columns), dict(expected_copied_columns))


def build_test_table():
    table = GdbTable()
    for i in range(3):
        row = {}
        for j in range(2):
            if j == 0:
                column_name = "First Column"
                header = f"Col{i+1}Row{str(i).zfill(2)}"
            else:
                column_name = "Second Column"
                header = f"Col{3+j-1}Row{str(i).zfill(2)}"

            row[header] = f"{column_name}{i+1}{j}"
        table.add_row(row)
    return table


if __name__ == "__main__":
    unittest.main()
```

This Python code defines a `GdbTable` class and its test cases. The `build_test_table()` function creates an instance of the `GdbTable` class with sample data, which is then used to verify various aspects of the table in the test methods.