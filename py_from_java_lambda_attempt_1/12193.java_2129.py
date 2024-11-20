Here is the translation of the given Java code into Python:

```Python
class PartitionCodeSubIterator:
    def __init__(self, model, monitor=None):
        self.model = model
        if monitor is None:
            self.monitor = "DUMMY"
        else:
            self.monitor = monitor
        self.listing = self.model.get_listing()
        self.inst_iter = self.listing.get_instructions(True)
        self.next_sub = None

    def has_next(self) -> bool:
        # Next sub block is already waiting
        if self.next_sub is not None:
            return True
        
        # Check block list for available block
        if len(self.block_list) > 0: 
            self.next_sub = self.block_list.pop(0)
            if self.next_sub is not None:
                return True

        # Iterate over instructions looking for next block
        while self.next_sub is None and self.inst_iter.has_next():
            inst = self.inst_iter.next()

            # don't iterate over instructions in subroutines already found!
            min_addr = inst.get_min_address()
            
            if self.addr_covered_so_far.contains(min_addr):
                continue
            
            block = self.model.get_first_code_block_containing(min_addr, self.monitor)
            if block is not None:
                self.addr_covered_so_far.add(block)
                self.next_sub = block
        return self.next_sub is not None

    def next(self) -> object:
        if self.next_sub is None:
            has_next()
        ret_sub = self.next_sub
        self.next_sub = None
        return ret_sub


class AddressSetView:  # Assuming this class exists in the given Java code, I'm including it here for completeness.
    def __init__(self):
        pass

    def contains(self, min_addr):  # Assuming this method is available in the given Java code, I'm including it here for completeness.
        return True


class InstructionIterator:  # Assuming this class exists in the given Java code, I'm including it here for completeness.
    def __init__(self):
        pass

    def has_next(self) -> bool:
        return False

    def next(self):  # Assuming this method is available in the given Java code, I'm including it here for completeness.
        return None


class CodeBlock:  # Assuming this class exists in the given Java code, I'm including it here for completeness.
    pass
```

Please note that Python does not support exact equivalent of Java's `@Override` annotation.