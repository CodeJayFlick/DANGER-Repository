Here is your Java code translated into Python:

```Python
class PartitionCodeSubModel:
    def __init__(self, program):
        self.program = program
        self.listing = program.get_listing()
        self.modelM = MultEntSubModel(program)

    @staticmethod
    def NAME():
        return "Partitioned Code"

    def getCodeBlockAt(self, addr, monitor=None):
        block = self._found_modelP.getBlockAt(addr)
        if block is not None:
            return block

        block = get_first_code_block_containing(addr, monitor)
        if block is not None and block.get_start_address().equals(addr):
            return block
        return None

    def getCodeBlocksContaining(self, addr_set, monitor=None):
        blocks = self._found_modelP.get_all_blocks_containing(addr_set)

        modelM_sub = self.modelM.getCodeBlockAt(addr_set.getMinAddress(), monitor)
        if modelM_sub is not None:
            start_addresses = modelM_sub.getStartAddresses()
            entry_points = [start_address for start_address in start_addresses]
            address_set = AddressSetView(modelM_sub, addr_set)

            if len(entry_points) == 1:  # If only one entry point
                return [createSub(address_set, entry_points[0])]
            else:
                subs = getModelPSubs(modelM_sub, monitor)
                for sub in subs:
                    address_set.add(sub)
        return []

    def getFirstCodeBlockContaining(self, addr, monitor=None):
        blocks = self.getCodeBlocksContaining(addr, monitor)
        if len(blocks) > 0:
            return blocks[0]
        return None

    # Other methods...
```

Please note that Python does not support static variables like Java. Also, there are some classes and functions in your code which I did not translate as they were missing their implementation (like `MultEntSubModel`, `_found_modelP`, etc.).