class MemoryBlockDefinition:
    def __init__(self, block_name: str, address_string: str, bit_mapped_address: str = None,
                 mode: str = None, length_string: str = None, initialized_string: bool = False):
        self.block_name = block_name
        self.address_string = address_string
        self.bit_mapped_address = bit_mapped_address
        if mode:
            mode = mode.lower()
            read_permission = 'r' in mode
            write_permission = 'w' in mode
            execute_permission = 'x' in mode
            volatile_permission = 'v' in mode

        try:
            length = int(length_string)
        except ValueError as e:
            raise Exception(f"{length_string} is not a valid integer") from e

        self.initialized = initialized_string

    def __str__(self):
        return f"{self.block_name} @ {self.address_string}, length={hex(self.length)}"

    def create_block(self, program: dict) -> None:
        if not (block_name := self.block_name) or not (address_string := self.address_string) or length <= 0:
            return

        mem = program['mem']
        addr = int(address_string)

        block = None
        if bit_mapped_address:
            mapped_addr = int(bit_mapped_address)
            block = mem.create_bit_mapped_block(block_name, addr, mapped_addr, length, False)
        elif self.initialized:
            try:
                block = mem.create_initialized_block(block_name, addr, length, 0x00, None, False)
            except Exception as e:
                raise AssertionError(f"Unexpected error: {e}")
        else:
            block = mem.create_uninitialized_block(block_name, addr, length, False)

        if read_permission and write_permission and execute_permission and volatile_permission:
            block.set_read(True)
            block.set_write(True)
            block.set_execute(True)
            block.set_volatile(True)


# Example usage
program = {'mem': None}  # Initialize the program dictionary

block_definition = MemoryBlockDefinition('my_block', '0x10000000')
try:
    block_definition.create_block(program)
except Exception as e:
    print(f"Error: {e}")
