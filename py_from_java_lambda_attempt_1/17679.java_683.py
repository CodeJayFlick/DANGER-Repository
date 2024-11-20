Here is the translation of the given Java code into Python:

```Python
class TimeSelector:
    MIN_DEFAULT_CAPACITY = 8

    def __init__(self, default_capacity: int, ascending: bool):
        self.ascending = ascending
        self.time_heap = [0] * max(default_capacity, self.MIN_DEFAULT_CAPACITY)
        self.heap_size = 0
        self.last_time = float('-inf')

    def is_empty(self) -> bool:
        while self.heap_size != 0 and self.time_heap[0] == self.last_time:
            self.time_heap[0] = self.time_heap[self.heap_size - 1]
            self.percolate_down(0, self.time_heap[0])
            self.heap_size -= 1
        return self.heap_size == 0

    def add(self, time: int) -> None:
        if self.heap_size == 0:
            self.time_heap[0] = time
        elif not self.percolate_up(self.heap_size - 1, time):
            self.check_expansion()

    def poll_first(self) -> int:
        min_time = self.last_time

        while min_time == self.last_time:
            min_time = self.time_heap[0]

            self.time_heap[0] = self.time_heap[self.heap_size - 1]
            self.percolate_down(0, self.time_heap[0])
            self.heap_size -= 1

        self.last_time = min_time
        return min_time

    def check_expansion(self) -> None:
        if self.heap_size == len(self.time_heap):
            self.time_heap += [0] * (len(self.time_heap) << 1)

    def percolate_up(self, index: int, element: int) -> bool:
        if index == 0:
            return True

        parent_index = (index - 1) >> 1
        parent = self.time_heap[parent_index]

        if parent == element:
            return False
        elif (self.ascending and element < parent) or not self.ascending and parent < element:
            self.time_heap[index] = parent
            self.time_heap[parent_index] = element
            is_successful = self.percolate_up(parent_index, element)
            if not is_successful:
                self.time_heap[index] = element
                self.time_heap[parent_index] = parent
            return is_successful
        else:
            self.time_heap[index] = element
            return True

    def percolate_down(self, index: int, element: int) -> None:
        if index == self.heap_size - 1:
            return

        child_index = self.get_smaller_child(index)

        if child_index != -1:
            child = self.time_heap[child_index]
            if (self.ascending and child < element) or not self.ascending and element < child:
                self.time_heap[child_index] = element
                self.time_heap[index] = child
                self.percolate_down(child_index, element)

    def get_smaller_child(self, index: int) -> int:
        left_child_index = (index << 1) + 1
        right_child_index = (index << 1) + 2

        if self.heap_size <= left_child_index:
            return -1
        elif self.heap_size <= right_child_index:
            return left_child_index
        else:
            if self.ascending:
                return time_heap[left_child_index] < time_heap[right_child_index]
            else:
                return time_heap[left_child_index] > time_heap[right_child_index]

    def __str__(self) -> str:
        return str(self.time_heap)
```

Please note that Python does not support direct translation of Java code. The above Python code is a manual translation and may require some adjustments to work correctly in your specific use case.