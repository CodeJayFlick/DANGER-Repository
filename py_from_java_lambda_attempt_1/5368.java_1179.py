Here is the translation of the Java code into Python:

```Python
class MemoryBlockUtils:
    def create_uninitialized_block(self, program: 'Program', is_overlay: bool, name: str,
                                    start: int, length: int, comment: str, source: str, r: bool, w: bool, x: bool) -> 'MemoryBlock':
        memory = program.get_memory()
        try:
            block = memory.create_uninitialized_block(name, start, length, is_overlay)
            self.set_block_attributes(block, comment, source, r, w, x)
            self.adjust_fragment(program, start, name)
            return block
        except LockException as e:
            log.append_msg("Failed to create memory block: exclusive lock/checkout required")
        except Exception as e:
            log.append_msg(f"Failed to create '{name}' memory block: {e}")
        return None

    def create_initialized_block(self, program: 'Program', is_overlay: bool,
                                   name: str, start: int, file_bytes: 'FileBytes', offset: int, length: int,
                                   comment: str, source: str, r: bool, w: bool, x: bool) -> 'MemoryBlock':
        if not program.has_exclusive_access():
            log.append_msg("Failed to create memory block: exclusive access/checkout required")
            return None
        try:
            block = program.get_memory().create_initialized_block(name, start, file_bytes, offset, length, is_overlay)
        except LockException as e:
            raise RuntimeException(e)
        self.set_block_attributes(block, comment, source, r, w, x)
        self.adjust_fragment(program, block.start, name)
        return block

    def create_bit_mapped_block(self, program: 'Program', name: str,
                                 start: int, base: int, length: int, comment: str, source: str, r: bool, w: bool, x: bool) -> 'MemoryBlock':
        memory = program.get_memory()
        try:
            block = memory.create_bit_mapped_block(name, start, base, length)
            self.set_block_attributes(block, comment, source, r, w, x)
            self.adjust_fragment(program, start, name)
            return block
        except LockException as e:
            log.append_msg(f"Failed to create '{name}' bit mapped memory block: exclusive lock/checkout required")
        except Exception as e:
            log.append_msg(f"Failed to create '{name}' mapped memory block: {e}")
        return None

    def adjust_fragment(self, program: 'Program', address: int, name: str) -> None:
        listing = program.get_listing()
        for tree_name in listing.tree_names():
            try:
                fragment = listing.fragment(tree_name, address)
                fragment.name = name
            except DuplicateNameException as e:
                Msg.warn(MemoryBlockUtils, f"Could not rename fragment to match newly created block because of name conflict")

    def create_file_bytes(self, program: 'Program', provider: 'ByteProvider', offset: int, length: int) -> 'FileBytes':
        memory = program.get_memory()
        try:
            return memory.create_file_bytes(provider.name(), offset, length)
        except Exception as e:
            raise

class Program:
    def get_memory(self):
        pass

class FileBytes:
    def __init__(self, name: str):
        self.name = name
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an interpretation based on the provided code and Python syntax.