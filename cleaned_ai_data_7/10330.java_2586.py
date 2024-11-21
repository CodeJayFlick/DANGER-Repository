import collections

class TreeSetValuedTreeMap:
    def __init__(self):
        self._map = collections.defaultdict(collections.OrderedDict)

    def create_collection(self):
        return []

    def __getitem__(self, key):
        if key not in self._map:
            self._map[key] = []
        return self._map[key]

    def __setitem__(self, key, value):
        if key not in self._map:
            self._map[key] = []
        self._map[key].append(value)

    def __len__(self):
        return len(self._map)
