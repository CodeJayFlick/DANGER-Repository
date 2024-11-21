Here is the translation of the Java code into Python:

```Python
class ShortListIndexer:
    def __init__(self, num_lists: int, capacity: int):
        self.capacity = capacity
        self.num_lists = num_lists
        self.links = [0] * capacity
        self.heads = [END_OF_LIST for _ in range(num_lists)]
        self.free_ptr = 0
        self.size = 0

    def add(self, list_id: int) -> int:
        if not (0 <= list_id < self.num_lists):
            raise IndexError("List ID out of bounds")
        
        index = self.allocate()
        if index >= 0:
            self.links[index] = self.heads[list_id]
            self.heads[list_id] = index
        return index

    def append(self, list_id: int) -> int:
        if not (0 <= list_id < self.num_lists):
            raise IndexError("List ID out of bounds")
        
        index = self.allocate()
        if index >= 0:
            if self.heads[list_id] == END_OF_LIST:
                self.heads[list_id] = index
            else:
                p = self.heads[list_id]
                while self.links[p] != END_OF_LIST:
                    p = self.links[p]
                self.links[p] = index
        return index

    def remove(self, list_id: int, index: int) -> None:
        if not (0 <= list_id < self.num_lists):
            raise IndexError("List ID out of bounds")
        
        head = self.heads[list_id]

        if head == END_OF_LIST:
            return
        
        # the special case that the index to be removed is the first one in
        # the list.
        if head == index:
            temp = self.links[head]
            self.free(index)
            self.heads[list_id] = temp
            return

        ptr = head
        while self.links[ptr] != END_OF_LIST:
            if self.links[ptr] == index:
                # found the index to be deleted, remove it from the list by
                # fixing the previous index's link to skip the removed index.
                self.links[ptr] = self.links[index]
                self.free(index)
                break
            ptr = self.links[ptr]

    def removeAll(self, list_id: int) -> None:
        head = self.heads[list_id]
        self.heads[list_id] = END_OF_LIST

        # cycle through the list and free all the indexes.
        while head != END_OF_LIST:
            temp = head
            head = self.links[head]
            self.free(temp)

    def get_new_capacity(self) -> int:
        if self.capacity == max_value:
            return -1
        
        elif 0 < self.capacity <= (max_value // 2):
            new_capacity = self.capacity * 2
        else:
            new_capacity = max_value

        return new_capacity

    def get_size(self) -> int:
        return self.size

    def get_capacity(self) -> int:
        return self.capacity

    def get_num_lists(self) -> int:
        return self.num_lists

    def next(self, index: int) -> int:
        return self.links[index]

    def first(self, list_id: int) -> int:
        if not (0 <= list_id < self.num_lists):
            raise IndexError("List ID out of bounds")
        
        return self.heads[list_id]

    def grow_capacity(self, new_capacity: int) -> None:
        if new_capacity <= self.capacity:
            return
        
        temp = [0] * new_capacity
        for i in range(self.capacity):
            temp[i] = self.links[i]
        for i in range(self.capacity, new_capacity - 1):
            temp[i] = i + 1
        temp[new_capacity - 1] = END_OF_LIST
        self.free_ptr = self.capacity
        self.capacity = new_capacity
        self.links = temp

    def grow_num_lists(self, num_new_lists: int) -> None:
        if num_new_lists <= self.num_lists:
            return
        
        temp = [END_OF_LIST for _ in range(num_new_lists)]
        for i in range(self.num_lists):
            temp[i] = self.heads[i]
        self.heads = temp
        self.num_lists = num_new_lists

    def clear(self) -> None:
        for i in range(self.capacity):
            self.links[i] = i + 1
        self.links[self.capacity - 1] = END_OF_LIST
        self.free_ptr = 0
        for _ in range(self.num_lists):
            self.heads[_] = END_OF_LIST
        self.size = 0

    def free(self, p: int) -> None:
        self.size -= 1
        self.links[p] = self.free_ptr
        self.free_ptr = p

    def allocate(self) -> int:
        if self.free_ptr == END_OF_LIST:
            new_capacity = min(max_value, (self.capacity * 2))
            for i in range(self.capacity):
                self.links[i] = i + 1
            self.links[self.capacity - 1] = END_OF_LIST
            self.free_ptr = 0
        p = self.free_ptr
        self.free_ptr = self.links[p]
        self.links[p] = END_OF_LIST
        return p

    def get_list_size(self, list_id: int) -> int:
        if not (0 <= list_id < self.num_lists):
            raise IndexError("List ID out of bounds")
        
        count = 0
        p = self.heads[list_id]
        while p != END_OF_LIST:
            count += 1
            p = self.links[p]
        return count

END_OF_LIST = -1
max_value = (2**15) - 1


# Example usage:

indexer = ShortListIndexer(5, max_value)
print(indexer.add(0))  # Add an index to the first list.
print(indexer.append(0))  # Append another index to the same list.
print(indexer.next(END_OF_LIST))  # Get the next index in the linked list.

indexer.remove(1, END_OF_LIST)  # Remove the last index from the second list.
indexer.removeAll(2)  # Empty all indexes from the third list.
```

This Python code defines a class `ShortListIndexer` that manages multiple linked lists of short indexes. It provides methods for adding and removing indexes from these lists, as well as other operations like growing or shrinking the capacity of the index pool.

Note: The provided Java code seems to be part of the Ghidra reverse engineering framework.