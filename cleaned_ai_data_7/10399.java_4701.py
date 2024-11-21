class ListAccumulator:
    def __init__(self):
        self.list = []

    def add(self, t):
        self.list.append(t)

    def add_all(self, collection):
        for item in collection:
            self.add(item)

    def contains(self, t):
        return t in self.list

    def get(self):
        return self.list.copy()

    def as_list(self):
        return self.list

    def size(self):
        return len(self.list)

    def __iter__(self):
        return iter(self.list)

    def __str__(self):
        return str(self.list)
