class LRUCache:
    def __init__(self, capacity):
        self.capacity = capacity
        self.in_memory = [int(-1e9) for _ in range(capacity * 8)]
        self.out_memory = [int(-1e9) for _ in range(capacity * 8)]

    def get(self, target_index):
        self.access(target_index)
        return self.in_memory[target_index]

    def set(self, target_index, value):
        self.access(target_index)
        self.in_memory[target_index] = value

    def access(self, target_index):
        if not self.remove_first_occurrence(target_index):
            if len(self) >= capacity:
                last_index = self.remove_last()
                out_value = self.out_memory[last_index]
                self.out_memory[last_index] = int(-1e9)
                self.in_memory[target_index] = out_value
                self.out_memory[target_index] = int(-1e9)
            else:
                self.add_first(target_index)

    def __len__(self):
        return sum(1 for x in self.in_memory if x != -1e9) + len([x for x in self.out_memory if x == -1e9])

    def remove_last(self):
        last_index = max(range(len(self.in_memory)), key=lambda i: self.in_memory[i])
        out_value = self.out_memory[last_index]
        self.out_memory[last_index] = int(-1e9)
        return last_index

    def add_first(self, target_index):
        if len(self) >= capacity:
            old_last_index = self.remove_last()
            out_value = self.out_memory[old_last_index]
            self.out_memory[target_index] = out_value
            self.in_memory[target_index] = int(-1e9)
        else:
            self.in_memory[target_index] = 0

    def remove_first_occurrence(self, target_index):
        for i in range(len(self)):
            if self.in_memory[i] == -1e9 and self.out_memory[i] != -1e9:
                return True
        return False
