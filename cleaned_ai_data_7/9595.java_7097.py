class DefaultRowColLocation:
    def __init__(self):
        self.row = 0
        self.col = 0

    def __init__(self, row: int, col: int):
        self.row = row
        self.col = col

    def with_col(self, new_column: int) -> 'DefaultRowColLocation':
        return DefaultRowColLocation(new_column, self.row)

    def with_row(self, new_row: int) -> 'DefaultRowColLocation':
        return DefaultRowColLocation(new_row, self.col)
