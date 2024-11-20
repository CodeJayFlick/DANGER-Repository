Here is the translation of the Java code to Python:

```Python
class IntIndexManager:
    def __init__(self):
        self.next_index = 0
        self.free_list = []

    def allocate(self):
        if not self.free_list:
            if self.next_index < 1:
                raise IndexError("No unused indexes")
            temp = self.next_index - 1
            self.next_index += 1
            return temp
        else:
            i = self.free_list.pop()
            return int(i)

    def deallocate(self, index):
        if index < 0 or index >= self.next_index:
            raise IndexError("Index out of bounds")
        if index == self.next_index - 1:
            self.next_index -= 1
        else:
            self.free_list.append(index)
        
        # all nodes are free, so reset...
        if self.next_index == len(self.free_list):
            self.clear()

    def clear(self):
        self.next_index = 0
        self.free_list = []
```

Note that Python does not have a direct equivalent to Java's `ArrayList` or `Serializable`. The above code uses Python lists (`self.free_list`) and integers for indexing.