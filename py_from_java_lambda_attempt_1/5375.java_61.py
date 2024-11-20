Here is the translation of the given Java code into Python:

```Python
class AddressSetPartitioner:
    def __init__(self, set, range_map, partition_set):
        self.address_range_cache = []
        self.range_map_cache = {}
        
        ranges = sorted(list(set.get_address_ranges()))
        partitions_master = list(partition_set)
        partitions = partitions_master.copy()
        Collections.sort(partitions)

        for address_range in ranges:
            self.address_range_cache.append(address_range)

        while len(self.address_range_cache) > 0:
            range_ = self.address_range_cache[0]
            self.address_range_cache.pop(0)
            
            split = False
            for part in partitions:
                if range_.contains(part) and not part == range_.get_min_address():
                    split = True
                    first_max = part.previous()
                    first = AddressRangeImpl(range_.get_min_address(), first_max)
                    second = AddressRangeImpl(part, range_.get_max_address())
                    self.address_range_cache.insert(0, first)
                    self.address_range_cache.append(second)
                    partitions.remove(part)
                    break

            if not split:
                self.address_range_cache.append(range_)

        original = dict(range_map)
        
        while len(original) > 0:
            range_ = next(iter(original))
            bytes_ = original[range_]
            original.pop(range_)
            
            split = False
            for part in partitions:
                if range_.contains(part) and not part == range_.get_min_address():
                    split = True
                    first_max = part.previous()
                    first = AddressRangeImpl(range_.get_min_address(), first_max)
                    second = AddressRangeImpl(part, range_.get_max_address())
                    
                    bytes_first = bytearray(first.length)
                    bytes_second = bytearray(second.length)

                    bytes_[:first.length].copyto(bytes_first)
                    bytes_[bytes_first.length:].copyto(bytes_second)
                    self.range_map_cache[first] = bytes_first
                    original[second] = bytes_second
                    partitions.remove(part)
                    break

            if not split:
                self.range_map_cache[range_] = bytes_

    def __iter__(self):
        return iter(self.address_range_cache)

    @property
    def partitioned_range_map(self):
        return dict(self.range_map_cache)
```

Note: Python does not have a direct equivalent to Java's `ArrayList` or `HashMap`. The above code uses built-in Python data structures like lists and dictionaries.