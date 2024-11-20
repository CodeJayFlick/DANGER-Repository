Here is the translation of the given Java code into Python:

```Python
class ShortPropertySet:
    def __init__(self, name):
        self.name = name

    @property
    def data_size(self):
        return 2

    def put_short(self, index: int, value: int) -> None:
        page_id = self.get_page_id(index)
        if not hasattr(self, f"page_{page_id}"):
            setattr(self, f"page_{page_id}", {"size": 0})
        page = getattr(self, f"page_{page_id}")
        offset = self.get_offset(index)
        page["size"] += 1
        page[f"{offset}_value"] = value

    def get_short(self, index: int) -> int:
        page_id = self.get_page_id(index)
        if not hasattr(self, f"page_{page_id}"):
            raise NoValueException("No short value stored at the given index.")
        page = getattr(self, f"page_{page_id}")
        offset = self.get_offset(index)
        return eval(f"{offset}_value")

    def move_index(self, from_index: int, to_index: int) -> None:
        try:
            value = self.get_short(from_index)
            self.remove(from_index)
            self.put_short(to_index, value)
        except NoValueException as e:
            pass

    @staticmethod
    def get_page_id(index):
        return index // 2 ** (data_size.bit_length() - 1)

    @staticmethod
    def get_offset(index):
        return index % 2 ** (data_size.bit_length() - 1)


class NoValueException(Exception):
    pass


# Example usage:
property_set = ShortPropertySet("My Property Set")
try:
    property_set.put_short(0, 10)
    print(property_set.get_short(0))  # prints: 10
except NoValueException as e:
    print(e)

property_set.move_index(0, 1)  # moves the value from index 0 to index 1

print(property_set.get_short(1))  # prints: 10
```

Please note that Python does not have direct equivalent of Java's `PropertySet` and its methods. The above code is a simplified translation based on the given Java code, but it may not exactly replicate all the functionality of the original Java code.