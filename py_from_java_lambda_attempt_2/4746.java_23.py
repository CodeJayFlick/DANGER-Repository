Here is the translation of the Java code into Python:

```Python
class ElfRelocationHandler:
    def __init__(self):
        pass

    @abstractmethod
    def can_relocate(self, elf_header: 'ElfHeader') -> bool:
        raise NotImplementedError("can_relocate must be implemented")

    def get_relr_relocation_type(self) -> int:
        return 0

    @abstractmethod
    def create_relocation_context(self, load_helper: 'ElfLoadHelper', relocation_table: 'ElfRelocationTable', symbol_map: dict['ElfSymbol', Address]) -> 'ElfRelocationContext':
        raise NotImplementedError("create_relocation_context must be implemented")

    @abstractmethod
    def relocate(self, elf_relocation_context: 'ElfRelocationContext', relocation: 'ElfRelocation', relocation_address: Address) -> None:
        raise MemoryAccessException()
        raise NotFoundException()

    @staticmethod
    def is_unsupported_external_rel relocation(program: 'Program', relocation_address: Address, symbol_addr: Address, symbol_name: str, adjustment: int, log: MessageLog) -> bool:
        if symbol_addr is not null:
            block = program.memory.get_block(symbol_addr)
            if block is None or block.name != MemoryBlock.EXTERNAL_BLOCK_NAME:
                return False
            sign = "+"
            if adjustment < 0:
                adjustment = -adjustment
                sign = "-"
            adj_str = sign + "0x" + str(adjustment).upper()
            symbol_name = "<no name>" if symbol_name is None else symbol_name
            log.append_msg("Unsupported EXTERNAL Data Elf Relocation: at {} (External Location={}{}).".format(relocation_address, symbol_name, adj_str))
            program.bookmark_manager.set_bookmark(relocation_address, BookmarkType.ERROR, "EXTERNAL Relocation", "Unsupported EXTERNAL Data Elf Relocation: External Location={}".format(adj_str))
            return True

    @staticmethod
    def mark_as_unhandled(program: 'Program', relocation_address: Address, type: int, symbol_index: int, symbol_name: str, log: MessageLog) -> None:
        if symbol_name is not None:
            symbol_name = "<no name>"
        log.append_msg("Unhandled Elf Relocation: Type={} (0x{}) at {} (Symbol={}).".format(type, hex(type), relocation_address, symbol_name))
        program.bookmark_manager.set_bookmark(relocation_address, BookmarkType.ERROR, "Relocation_Type_{}".format(hex(type)), "Unhandled Elf Relocation: Symbol={}, 0x{}.".format(symbol_name, hex(symbol_index)))

    @staticmethod
    def mark_as_unsupported_relr(program: 'Program', relocation_address: Address) -> None:
        program.bookmark_manager.set_bookmark(relocation_address, BookmarkType.ERROR, "Unsupported RELR Relocation", "ELF Extension does not specify type")

    @staticmethod
    def mark_as_uninitialized_memory(program: 'Program', relocation_address: Address, type: int, symbol_index: int, symbol_name: str, log: MessageLog) -> None:
        if symbol_name is not None:
            symbol_name = "<no name>"
        log.append_msg("Unable to perform relocation: Type={} (0x{}) at {} (Symbol={}). - uninitialized memory.".format(type, hex(type), relocation_address, symbol_name))
        program.bookmark_manager.set_bookmark(relocation_address, BookmarkType.ERROR, "Relocation_Type_{}".format(hex(type)), "Unable to perform relocation: Symbol={}, 0x{}.- uninitialized memory.".format(symbol_name, hex(symbol_index)))

    @staticmethod
    def mark_as_error(program: 'Program', relocation_address: Address, type: int, symbol_name: str, msg: str, log: MessageLog) -> None:
        if symbol_name is not None:
            symbol_name = "<no name>"
        log.append_msg("Elf Relocation Error: Type={} at {} (Symbol={}). {}".format(type, relocation_address, symbol_name, msg))
        program.bookmark_manager.set_bookmark(relocation_address, BookmarkType.ERROR, "Relocation_{}".format(hex(type)), "Elf Relocation Error: Symbol={}, {}:.".format(symbol_name, msg))

    @staticmethod
    def mark_as_warning(program: 'Program', relocation_address: Address, type: str, symbol_name: str = None, symbol_index: int = 0, msg: str = "", log: MessageLog) -> None:
        if symbol_name is not None:
            symbol_name = "<no name>"
        log.append_msg("Elf Relocation Warning: Type={} at {} (Symbol={}). {}".format(type, relocation_address, symbol_name, msg))
        program.bookmark_manager.set_bookmark(relocation_address, BookmarkType.WARNING, "Relocation_Type_{}".format(type), "Unhandled Elf relocation({}) at address: {}. Symbol={}, 0x{}. . {}".format(type, relocation_address, symbol_name, hex(symbol_index), msg))

```

Note that I have not implemented the abstract methods in this translation. You will need to implement these methods according to your specific requirements.