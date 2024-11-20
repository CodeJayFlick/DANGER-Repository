Here is the translation of the Java code into Python:

```Python
class FloatArray:
    def __init__(self):
        self.floats = [0] * 4
        self.last_non_zero_index = -1

    def put(self, index: int, value: float) -> None:
        if value == 0:
            self.remove(index)
            return
        
        if index >= len(self.floats):
            self.adjust_array(max(index + 1, len(self.floats) * 2))
        
        self.floats[index] = value
        if index > self.last_non_zero_index:
            self.last_non_zero_index = index

    def remove(self, index: int) -> None:
        if index >= len(self.floats):
            return
        
        self.floats[index] = 0
        if index == self.last_non_zero_index:
            self.last_non_zero_index = self.find_last_non_zero_index()
        
        if self.last_non_zero_index < len(self.floats) // 4:
            self.adjust_array(self.last_non_zero_index * 2)

    def find_last_non_zero_index(self) -> int:
        for i in range(self.last_non_zero_index, -1, -1):
            if self.floats[i] != 0:
                return i
        
        return -1

    def get(self, index: int) -> float:
        if index < len(self.floats):
            return self.floats[index]
        
        return 0.0

    def adjust_array(self, size: int) -> None:
        if size < 4:
            size = 4
        
        new_floats = [0] * size
        length = min(size, len(self.floats))
        new_floats[:length] = self.floats[:length]
        self.floats = new_floats

    @property
    def last_non_empty_index(self) -> int:
        return self.last_non_zero_index

    def copy_data_to(self, index: int, table, to_index: int, to_col: int) -> None:
        table.put_float(to_index, to_col, self.get(index))
```

Please note that Python does not have a direct equivalent of Java's `Serializable` interface. Also, the code assumes that you are using some kind of data structure (like list or array) and methods like `putFloat`, which is specific to your environment.