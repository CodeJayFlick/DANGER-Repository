class ByteArray:
    def __init__(self):
        self.bytes = [0] * 4
        self.last_non_zero_index = -1

    def put(self, index: int, value: bytes) -> None:
        if value == b'\x00':
            self.remove(index)
            return
        
        if index >= len(self.bytes):
            self.adjust_array(max(index + 1, len(self.bytes) * 2))
        
        self.bytes[index] = value
        if index > self.last_non_zero_index:
            self.last_non_zero_index = index

    def remove(self, index: int) -> None:
        if index >= len(self.bytes):
            return
        
        self.bytes[index] = b'\x00'
        if index == self.last_non_zero_index:
            self.last_non_zero_index = self.find_last_non_zero_index()
        
        if self.last_non_zero_index < len(self.bytes) // 4:
            self.adjust_array(self.last_non_zero_index * 2)

    def find_last_non_zero_index(self) -> int:
        for i in range(self.last_non_zero_index, -1, -1):
            if self.bytes[i] != b'\x00':
                return i
        
        return -1

    def get(self, index: int) -> bytes:
        if 0 <= index < len(self.bytes):
            return self.bytes[index]
        
        return b'\x00'

    def adjust_array(self, size: int) -> None:
        if size < 4:
            size = 4
        
        new_bytes = [0] * size
        length = min(size, len(self.bytes))
        self.bytes[:length].copyto(new_bytes)
        self.bytes = new_bytes

    @property
    def last_non_empty_index(self) -> int:
        return self.last_non_zero_index

    def copy_data_to(self, index: int, table, to_index: int, to_col: int) -> None:
        table.put_byte(to_index, to_col, self.get(index))
