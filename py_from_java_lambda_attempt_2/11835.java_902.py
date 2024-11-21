Here is the translation of the Java code into Python:

```Python
class DataKeyIterator:
    def __init__(self, code_mgr, addr_map, it):
        self.code_mgr = code_mgr
        self.addr_map = addr_map
        self.it = it
        self.next_cu = None

    def remove(self):
        raise Exception("Not supported")

    def has_next(self):
        if not self.next_cu:
            self.find_next()
        return bool(self.next_cu)

    def next(self):
        if self.has_next():
            ret = self.next_cu
            self.next_cu = None
            return ret
        return None

    def find_next(self):
        while True:
            try:
                addr = self.it.__next__()
                self.next_cu = self.code_mgr.get_data_at(self.addr_map.decode_address(addr), addr)
                break
            except Exception as e:
                pass


# Example usage:

class CodeManager:
    def get_data_at(self, address, addr):
        # implement your logic here
        return None

class AddressMap:
    @staticmethod
    def decode_address(address):
        # implement your logic here
        return 0

it = iter([1, 2, 3])  # replace with actual DBLongIterator
addr_map = AddressMap()
code_mgr = CodeManager()

data_key_iterator = DataKeyIterator(code_mgr, addr_map, it)
while data_key_iterator.has_next():
    print(data_key_iterator.next())
```

Please note that the Python code does not directly translate Java's `DBLongIterator` and other classes. Instead, I used a simple iterator (`iter([1, 2, 3])`) to demonstrate how you can iterate over some sequence of values in Python.

Also, please replace the placeholder logic in `CodeManager.get_data_at()` and `AddressMap.decode_address()` with your actual implementation based on the requirements of your project.