class BlockCopy:
    def __init__(self):
        self.ref = None  # Reference to basic block of which this is a copy
        self.address = 'NO_ADDRESS'  # Address upon entry to the basic block
        self.altindex = -1  # Alternate index for correlating this block with result structure

    def set(self, r, addr):
        self.ref = r
        self.address = addr

    @property
    def start_address(self):
        return self.address

    @property
    def stop_address(self):
        return self.address

    @property
    def ref_obj(self):
        return self.ref

    @property
    def alt_index(self):
        return self.altindex

class PcodeBlock:
    COPY = 'COPY'

# Usage example:

block_copy = BlockCopy()
print(block_copy.start_address)  # prints: NO_ADDRESS
print(block_copy.stop_address)   # prints: NO_ADDRESS
print(block_copy.ref_obj)       # prints: None
print(block_copy.alt_index)      # prints: -1

block_copy.set('some_object', 'new_address')
print(block_copy.start_address)  # prints: new_address
print(block_copy.stop_address)   # prints: new_address
print(block_copy.ref_obj)       # prints: some_object
print(block_copy.alt_index)      # still prints: -1, because this is not implemented in Python

