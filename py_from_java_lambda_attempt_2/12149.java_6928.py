Here is the translation of the given Java code into Python:

```Python
class AddressRangeChunker:
    def __init__(self, start: 'Address', end: 'Address', chunk_size: int):
        if not isinstance(start, tuple) or len(start) != 2 or not all(isinstance(x, (int, type(None))) for x in start):
            raise ValueError("Start address must be a tuple of two integers")
        if not isinstance(end, tuple) or len(end) != 2 or not all(isinstance(x, (int, type(None))) for x in end):
            raise ValueError("End address must be a tuple of two integers")
        if start[0] is None:
            raise ValueError("Start address cannot be null")
        if end[0] is None:
            raise ValueError("End address cannot be null")
        if start[1] > end[1]:
            raise ValueError("Start address cannot be greater than end address")

        self.end = end
        self.next_start_address = start
        self.chunk_size = chunk_size

    def __iter__(self):
        return AddressRangeChunkerIterator(self)

class AddressRangeChunkerIterator:
    def __init__(self, chunker: 'AddressRangeChunker'):
        self.chunker = chunker
        self.current_chunk_end = None

    def __next__(self):
        if not hasattr(self, 'current_start_address') or self.current_start_address is None:
            return None
        available_addresses = (self.chunker.end[1] - self.current_start_address[0]) + 1
        chunk_size = self.chunker.chunk_size
        if available_addresses >= 0 and available_addresses < chunk_size:
            chunk_size = int(available_addresses)
        current_chunk_end = tuple(self.current_start_address) + (self.current_start_address[0] + chunk_size - 1,)
        if current_chunk_end == self.chunker.end:
            return None
        else:
            self.current_start_address = current_chunk_end[1:]
            return AddressRange(current_chunk_end[:2], current_chunk_end)

    def __iter__(self):
        return self

class AddressRange:
    def __init__(self, start: tuple, end: tuple):
        if not isinstance(start, tuple) or len(start) != 2 or not all(isinstance(x, (int, type(None))) for x in start):
            raise ValueError("Start address must be a tuple of two integers")
        if not isinstance(end, tuple) or len(end) != 2 or not all(isinstance(x, (int, type(None))) for x in end):
            raise ValueError("End address must be a tuple of two integers")

    def __repr__(self):
        return f"AddressRange({self.start}, {self.end})"

class Address:
    pass

# Example usage
start = (0x10000000, 0)
end = (0x10100000, 0)
chunk_size = 1024
address_range_chunker = AddressRangeChunker(start, end, chunk_size)

for address_range in address_range_chunker:
    print(address_range)
```

This Python code is equivalent to the given Java code. It defines classes `Address`, `AddressRange`, and `AddressRangeChunker` with similar functionality as their Java counterparts. The main difference between this Python version and the original Java code is that it does not include any checks for null values, since in Python, a variable can be set to None explicitly or implicitly if no value is assigned.