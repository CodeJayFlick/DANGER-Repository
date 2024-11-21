class MultiValuedTreeMap:
    def __init__(self):
        self.map = {}

    def add(self, key, value):
        if not isinstance(key, str) or not isinstance(value, list):
            raise TypeError("Key must be a string and Value must be a list")
        values = self.find_key(key)
        values.append(value)

    def get_first(self, key):
        return next((value for value in self.get(key)), None)

    def put_single(self, key, value):
        if not isinstance(key, str) or not isinstance(value, list):
            raise TypeError("Key must be a string and Value must be a list")
        values = self.find_key(key)
        values.clear()
        values.append(value)

    def clear(self):
        self.map = {}

    def contains_key(self, key):
        return key in self.map

    def contains_value(self, value):
        for k, v in self.map.items():
            if value in v:
                return True
        return False

    def entry_set(self):
        return set((k, list(v)) for k, v in self.map.items())

    def __eq__(self, other):
        if not isinstance(other, dict):
            raise TypeError("Other must be a dictionary")
        return self.map == other

    def get(self, key):
        return self.map.get(key)

    def hash_code(self):
        return hash(frozenset(self.map.items()))

    def is_empty(self):
        return len(self.map) == 0

    def key_set(self):
        return set(self.map.keys())

    def put(self, key, value):
        if not isinstance(key, str) or not isinstance(value, list):
            raise TypeError("Key must be a string and Value must be a list")
        self.map[key] = value
        return value

    def put_all(self, other):
        for k, v in other.items():
            self.put(k, v)

    def remove(self, key):
        if not isinstance(key, str):
            raise TypeError("Key must be a string")
        return self.map.pop(key, None)

    def size(self):
        return len(self.map)

    def values(self):
        return list(self.map.values())

    def add_all(self, key, *values):
        for value in values:
            if not isinstance(value, list):
                raise TypeError("Value must be a list")
            self.add(key, value)

    def add_first(self, key, value):
        if not isinstance(key, str) or not isinstance(value, list):
            raise TypeError("Key must be a string and Value must be a list")
        values = self.get(key)
        if values is None:
            self.put_single(key, [value])
        else:
            values.insert(0, value)

    def equals_ignore_value_order(self, other_map):
        if not isinstance(other_map, dict):
            raise TypeError("Other map must be a dictionary")
        return set(self.map.keys()) == set(other_map.keys())

    def find_key(self, key):
        if not isinstance(key, str):
            raise TypeError("Key must be a string")
        values = self.get(key)
        if values is None:
            values = []
            self.put(key, values)
        return values

    def clone(self):
        new_map = MultiValuedTreeMap()
        for k in set(self.map.keys()):
            v = self.get(k)
            new_map.put(k, [x for x in v])
        return new_map

    def __str__(self):
        result = ""
        delimiter = ","
        for name in self.key_set():
            values = self.get(name)
            if values is not None:
                for value in values:
                    result += f"{delimiter} {name}={value}"
                delimiter = ", "
        return "[" + result[1:] + "]"
