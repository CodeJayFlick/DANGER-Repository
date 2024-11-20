class PairList:
    def __init__(self):
        self.keys = []
        self.values = []

    def add(self, key: object, value: object) -> None:
        if not isinstance(key, type(None)):
            self.keys.append(key)
        else:
            raise ValueError("Key cannot be null")
        
        if not isinstance(value, type(None)):
            self.values.append(value)
        else:
            raise ValueError("Value cannot be null")

    def get(self, index: int) -> tuple:
        return (self.keys[index], self.values[index])

    def remove(self, key: object) -> None:
        try:
            i = self.keys.index(key)
            del self.keys[i]
            del self.values[i]
        except ValueError as e:
            print(f"Key not found: {e}")

    def subList(self, from_index: int, to_index: int) -> 'PairList':
        return PairList([self.keys[from_index:to_index]], [self.values[from_index:to_index]])

    def stream(self):
        pass

    def contains(self, key: object) -> bool:
        try:
            i = self.keys.index(key)
            return True
        except ValueError as e:
            print(f"Key not found: {e}")
            return False

    def unique(self) -> 'PairList':
        seen_keys = set()
        new_list = []
        for key, value in zip(self.keys, self.values):
            if key not in seen_keys:
                seen_keys.add(key)
                new_list.append((key, value))
        return PairList([k for k, _ in new_list], [v for _, v in new_list])

    def toMap(self) -> dict:
        return {k: v for k, v in zip(self.keys, self.values)}

class Itr:
    def __init__(self):
        pass

    def hasNext(self) -> bool:
        if len(PairList.keys) > 0:
            return True
        else:
            return False

    def next(self) -> tuple:
        try:
            key = PairList.keys.pop(0)
            value = PairList.values.pop(0)
            return (key, value)
        except IndexError as e:
            print(f"Index out of range: {e}")
