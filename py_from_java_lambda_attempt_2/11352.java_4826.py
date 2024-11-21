Here is the translation of the Java code into Python:

```Python
class ProgramMappedMemory:
    def __init__(self, program: 'Program', fault_handler):
        self.program = program
        memory = program.get_memory()
        initialized_address_set = memory.get_loaded_and_initialized_address_set()

        for block in memory.get_blocks():
            if not block.is_initialized() and block.is_mapped():
                initialized_address_set = add_mapped_initialized_memory(block)

        program.add_consumer(self)
        self.fault_handler = fault_handler

    def get_program(self):
        return self.program

    def dispose(self):
        if self.program is not None:
            self.program.release(self)
            self.program = None

    def write(self, bytes: bytearray, size: int, addr: 'Address', offset: int) -> None:
        memory = self.program.get_memory()
        current_offset = offset
        remaining = size
        next_addr = addr

        while True:
            chunk_size = min(remaining, (next_addr + 1).subtract(next_addr))
            if not initialized_address_set.contains_range(next_addr):
                handle_write_fault(bytes, current_offset, remaining, next_addr)
                break
            elif range.contains(next_addr):
                try:
                    memory.set_bytes(next_addr, bytes[current_offset:current_offset+chunk_size], chunk_size)
                except MemoryAccessException as e:
                    raise LowlevelError(f"Unexpected memory write error: {e}")
                if (next_addr + 1).subtract(end_addr) > 0:
                    next_addr = end_addr
            else:
                gap_size = range.min_address().subtract(next_addr)
                chunk_size = min(gap_size, remaining)
                handle_write_fault(bytes, current_offset, chunk_size, next_addr)

            if chunk_size == remaining:
                break

            try:
                next_addr += 1
            except AddressOverflowException as e:
                raise LowlevelError(f"Unexpected error: {e}")

            current_offset += chunk_size
            remaining -= chunk_size

    def handle_write_fault(self, bytes: bytearray, offset: int, size: int, addr: 'Address') -> None:
        # TODO: Should we create blocks or convert to initialized as needed ?

    def read(self, bytes: bytearray, size: int, addr: 'Address', offset: int, generate_initialized_mask=False) -> bytearray | None:
        memory = self.program.get_memory()
        current_offset = offset
        remaining = size
        next_addr = addr

        while True:
            chunk_size = min(remaining, (next_addr + 1).subtract(next_addr))
            if not initialized_address_set.contains_range(next_addr):
                if generate_initialized_mask:
                    bytes[:] = get_initialized_mask(len(bytes), offset, current_offset, remaining)
                else:
                    handle_read_fault(bytes, current_offset, remaining, next_addr)

                break
            elif range.contains(next_addr):
                try:
                    memory.get_bytes(next_addr, bytes[current_offset:current_offset+chunk_size], chunk_size)
                except MemoryAccessException as e:
                    Msg.warn(self, f"Unexpected memory read error: {e}")

                if (next_addr + 1).subtract(end_addr) > 0:
                    next_addr = end_addr
            else:
                range_addr = range.min_address()
                gap_size = range_addr.subtract(next_addr)
                chunk_size = min(gap_size, remaining)

                if generate_initialized_mask:
                    bytes[:] = get_initialized_mask(len(bytes), offset, current_offset, chunk_size)
                else:
                    handle_read_fault(bytes, current_offset, chunk_size, next_addr)

            if chunk_size == remaining:
                break

            try:
                next_addr += 1
            except AddressOverflowException as e:
                raise LowlevelError(f"Unexpected error: {e}")

            current_offset += chunk_size
            remaining -= chunk_size

        return bytes[:]

    def get_initialized_mask(self, bufsize: int, initial_offset: int, uninitialized_offset: int, uninitialized_size: int) -> bytearray | None:
        if initialized_mask is None:
            initialized_mask = MemoryPage.get_initialized_mask(bufsize, 0, initial_offset, False)
        MemoryPage.set_uninitialized(initialized_mask, uninitialized_offset, uninitialized_size)

    def handle_read_fault(self, bytes: bytearray, offset: int, size: int, addr: 'Address') -> None:
        Arrays.fill(bytes[offset:offset+size], 0)
        if self.fault_handler is not None:
            self.fault_handler.uninitialized_read(addr, size, bytes[:size])

    def get_initialized_address_set(self) -> AddressSetView | None:
        return initialized_address_set
```

Please note that this translation assumes the following:

- The `Address` class represents an address in memory.
- The `Program` class has methods to access its memory and blocks.
- The `MemoryPage` class is used for handling uninitialized memory regions.
- The `LowlevelError`, `Msg`, and `Arrays` classes are available.

This translation does not include the implementation of these classes, as they would require a deep understanding of Java's equivalent Python libraries.