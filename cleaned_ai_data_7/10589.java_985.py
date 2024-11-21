class Counter:
    def __init__(self):
        self.map = {}

    def clear(self):
        self.map.clear()

    def get_and_remove(self, name):
        if name not in self.map:
            return 0
        count = self.map.pop(name)
        return count

    def total_count(self):
        total = 0
        for key in self.map.keys():
            count = self.map[key]
            total += count
        return total

    def increment(self, name):
        if name not in self.map:
            self.map[name] = 0
        self.map[name] += 1

class Count:
    def __init__(self):
        self.count = 0

    def increment(self):
        self.count += 1
