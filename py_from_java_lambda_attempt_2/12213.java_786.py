Here is the translation of the Java code to Python:
```
class HashEntry:
    def __init__(self, hash):
        self.hash = hash
        self.inst_list = []

    class InstructHash:
        pass  # Note: This is a nested class in Python, equivalent to an inner class in Java

    @property
    def inst_list(self):
        return self._inst_list

    @inst_list.setter
    def inst_list(self, value):
        self._inst_list = value

    def has_duplicate_blocks(self):
        visited_blocks = set()
        for instruct_hash in self.inst_list:
            if instruct_hash.block in visited_blocks:
                return True  # Indicates multiple InstructHashes from one block
            visited_blocks.add(instruct_hash.block)
        return False


class Block:
    is_visited = False

# Example usage:
hash = ...  # Initialize the Hash object
entry = HashEntry(hash)

instruct_hashes = [InstructHash(), InstructHash()]
for instruct_hash in instruct_hashes:
    entry.inst_list.append(instruct_hash)

print(entry.has_duplicate_blocks())  # Output: True or False
```
Note that I had to introduce a new `Block` class to represent the `block` attribute of each `InstructHash`, since Python does not have an equivalent concept to Java's inner classes.