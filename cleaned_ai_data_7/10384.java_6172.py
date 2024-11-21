class FixedSizeStack:
    def __init__(self, max_size):
        self.max_size = max_size
        self.stack = []

    def push(self, item):
        if len(self.stack) > self.max_size:
            self.stack.pop(0)
        return self.stack.append(item)

    def add(self, item):
        if len(self.stack) > self.max_size:
            self.stack.pop(0)
        return self.stack.append(item)

    def remove(self, index):
        return self.stack.pop(index)
