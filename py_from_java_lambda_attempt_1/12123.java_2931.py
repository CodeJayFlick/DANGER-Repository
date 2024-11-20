Here is the translation of the Java code into Python:

```Python
class IndexedAddressIterator:
    def __init__(self, iter, addr_map, col_index):
        self.iter = iter
        self.addr_map = addr_map

    def remove(self):
        raise NotImplementedError("remove method not implemented")

    def has_next(self):
        try:
            return next(self.iter) is not None
        except Exception as e:
            print(f"Error: {e}")

    def __next__(self):
        try:
            field = next(self.iter)
            if field is not None:
                addr = field.get_long_value()
                return self.addr_map.decode_address(addr)
            else:
                raise StopIteration
        except Exception as e:
            print(f"Error: {e}")
            return None

    def __iter__(self):
        return self


# Example usage:

class DBFieldIterator:
    def __init__(self, fields):
        self.fields = fields

    def next(self):
        if not hasattr(self, 'index'):
            self.index = 0
        else:
            field = self.fields[self.index]
            self.index += 1
            return field


class AddressMap:
    def decode_address(self, addr):
        # implement your decoding logic here
        pass

addr_map = AddressMap()
db_field_iterator = DBFieldIterator([{"long_value": i} for i in range(10)])
indexed_iter = IndexedAddressIterator(db_field_iterator, addr_map, 0)

for _ in indexed_iter:
    print(next(indexed_iter))
```

Please note that this is a translation of the Java code into Python. The actual implementation may vary depending on your specific requirements and constraints.