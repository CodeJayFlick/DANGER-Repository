class GraphPathSet:
    def __init__(self):
        self.paths = set()

    def contains_some_path_starting_with(self, other_path):
        for path in self(paths):
            if path.startswith(other_path):
                return True
        return False

    def add(self, path):
        self.paths.add(path)

    def get_paths_containing(self, v):
        result = set()
        for path in self.paths:
            if v in path:
                result.add(path)
        return result

    def size(self):
        return len(self(paths))

    def __str__(self):
        buf = ""
        for path in self.paths:
            buf += str(path) + "\n"
        return buf
