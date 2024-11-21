class KeyIndexableSet:
    def __init__(self):
        self.modification_number = 0
        self.keyed_objects = []

    def get_modification_number(self) -> int:
        return self.modification_number

    def size(self) -> int:
        return len(self.keyed_objects)

    def capacity(self) -> int:
        # This method is not implemented in the original Java code, so I'll leave it as a placeholder
        pass

    def add(self, o: 'KeyedObject') -> bool:
        if o is None or self.contains(o):
            return False
        self.keyed_objects.append(o)
        self.modification_number += 1
        return True

    def remove(self, o: 'KeyedObject') -> bool:
        try:
            self.keyed_objects.remove(o)
            self.modification_number += 1
            return True
        except ValueError:
            return False

    def contains(self, o: 'KeyedObject') -> bool:
        return o in self.keyed_objects

    def iterator(self) -> 'GraphIterator':
        # This method is not implemented in the original Java code, so I'll leave it as a placeholder
        pass

    def to_array(self) -> list:
        return [o for o in self.keyed_objects]

    def get_keyed_object(self, key: int) -> 'KeyedObject' | None:
        for obj in self.keyed_objects:
            if obj.get_key() == key:
                return obj
        return None

class KeyedObject:
    def __init__(self):
        pass  # This class is not implemented in the original Java code, so I'll leave it as a placeholder

    def get_key(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")
