class Array:
    def __init__(self):
        self.data = []

    def remove(self, index: int) -> None:
        if 0 <= index < len(self.data):
            self.data[index] = 0

    def get_last_non_empty_index(self) -> int:
        for i in range(len(self.data)):
            if self.data[i]:
                return i
        return -1

    def copy_data_to(self, index: int, table: list, to_index: int, to_col: int) -> None:
        if 0 <= index < len(self.data):
            table[to_index][to_col] = self.data[index]
